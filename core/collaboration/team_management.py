"""
团队协作和数据共享功能模块
基于20年渗透测试经验的团队协作系统
支持多用户实时协作、项目共享和权限管理
"""

import asyncio
import logging
import json
import hashlib
import secrets
from typing import Dict, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
import sqlite3
import threading

logger = logging.getLogger(__name__)

class UserRole(Enum):
    """用户角色枚举"""
    ADMIN = "admin"
    LEADER = "leader"
    MEMBER = "member"
    VIEWER = "viewer"

class ProjectStatus(Enum):
    """项目状态枚举"""
    PLANNING = "planning"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    ARCHIVED = "archived"

class PermissionLevel(Enum):
    """权限级别枚举"""
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    ADMIN = "admin"

@dataclass
class User:
    """用户信息"""
    user_id: str
    username: str
    email: str
    role: UserRole
    created_at: datetime
    last_login: datetime
    is_active: bool = True
    
    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            'user_id': self.user_id,
            'username': self.username,
            'email': self.email,
            'role': self.role.value,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat(),
            'is_active': self.is_active
        }

@dataclass
class Project:
    """项目信息"""
    project_id: str
    name: str
    description: str
    status: ProjectStatus
    created_by: str
    created_at: datetime
    modified_at: datetime
    team_members: Dict[str, PermissionLevel]  # user_id -> permission
    
    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            'project_id': self.project_id,
            'name': self.name,
            'description': self.description,
            'status': self.status.value,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat(),
            'modified_at': self.modified_at.isoformat(),
            'team_members': {uid: perm.value for uid, perm in self.team_members.items()}
        }

@dataclass
class CollaborationEvent:
    """协作事件"""
    event_id: str
    project_id: str
    user_id: str
    event_type: str
    description: str
    data: Dict
    timestamp: datetime
    
    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            'event_id': self.event_id,
            'project_id': self.project_id,
            'user_id': self.user_id,
            'event_type': self.event_type,
            'description': self.description,
            'data': self.data,
            'timestamp': self.timestamp.isoformat()
        }

class TeamManager:
    """团队管理器"""
    
    def __init__(self, database_path: str = "team_collaboration.db"):
        self.database_path = database_path
        self.db_lock = threading.Lock()
        
        # 内存缓存
        self.users: Dict[str, User] = {}
        self.projects: Dict[str, Project] = {}
        self.sessions: Dict[str, Dict] = {}  # session_id -> session_data
        
        # 初始化数据库
        self._init_database()
        
        # 加载数据
        self._load_users()
        self._load_projects()
        
        logger.info("团队管理器初始化完成")
    
    def _init_database(self):
        """初始化数据库"""
        with self.db_lock:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            # 创建用户表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_login TEXT,
                    is_active INTEGER DEFAULT 1
                )
            ''')
            
            # 创建项目表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS projects (
                    project_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    status TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    modified_at TEXT NOT NULL,
                    team_members TEXT NOT NULL,
                    FOREIGN KEY (created_by) REFERENCES users (user_id)
                )
            ''')
            
            # 创建协作事件表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS collaboration_events (
                    event_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    description TEXT,
                    data TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (project_id) REFERENCES projects (project_id),
                    FOREIGN KEY (user_id) REFERENCES users (user_id)
                )
            ''')
            
            # 创建默认管理员用户
            cursor.execute('SELECT COUNT(*) FROM users WHERE role = ?', (UserRole.ADMIN.value,))
            if cursor.fetchone()[0] == 0:
                self._create_default_admin(cursor)
            
            conn.commit()
            conn.close()
    
    def _create_default_admin(self, cursor):
        """创建默认管理员用户"""
        admin_id = self._generate_user_id()
        username = "admin"
        email = "admin@kunlun-sec.com"
        password_hash = self._hash_password("admin123")
        created_at = datetime.now().isoformat()
        
        cursor.execute('''
            INSERT INTO users (user_id, username, email, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (admin_id, username, email, password_hash, UserRole.ADMIN.value, created_at))
    
    def _load_users(self):
        """加载用户数据"""
        with self.db_lock:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM users WHERE is_active = 1')
            rows = cursor.fetchall()
            
            for row in rows:
                user = User(
                    user_id=row[0],
                    username=row[1],
                    email=row[2],
                    role=UserRole(row[4]),
                    created_at=datetime.fromisoformat(row[5]),
                    last_login=datetime.fromisoformat(row[6]) if row[6] else datetime.now(),
                    is_active=bool(row[7])
                )
                self.users[user.user_id] = user
            
            conn.close()
    
    def _load_projects(self):
        """加载项目数据"""
        with self.db_lock:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM projects')
            rows = cursor.fetchall()
            
            for row in rows:
                team_members = json.loads(row[7])
                project = Project(
                    project_id=row[0],
                    name=row[1],
                    description=row[2],
                    status=ProjectStatus(row[3]),
                    created_by=row[4],
                    created_at=datetime.fromisoformat(row[5]),
                    modified_at=datetime.fromisoformat(row[6]),
                    team_members={uid: PermissionLevel(perm) for uid, perm in team_members.items()}
                )
                self.projects[project.project_id] = project
            
            conn.close()
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """用户认证"""
        with self.db_lock:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM users WHERE username = ? AND is_active = 1', (username,))
            row = cursor.fetchone()
            
            if row and self._verify_password(password, row[3]):
                user = User(
                    user_id=row[0],
                    username=row[1],
                    email=row[2],
                    role=UserRole(row[4]),
                    created_at=datetime.fromisoformat(row[5]),
                    last_login=datetime.fromisoformat(row[6]) if row[6] else datetime.now(),
                    is_active=bool(row[7])
                )
                
                # 更新最后登录时间
                cursor.execute(
                    'UPDATE users SET last_login = ? WHERE user_id = ?',
                    (datetime.now().isoformat(), user.user_id)
                )
                conn.commit()
                
                conn.close()
                return user
            
            conn.close()
            return None
    
    def create_user(self, username: str, email: str, password: str, role: UserRole) -> User:
        """创建用户"""
        with self.db_lock:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            # 检查用户名和邮箱是否已存在
            cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', (username,))
            if cursor.fetchone()[0] > 0:
                raise ValueError("用户名已存在")
            
            cursor.execute('SELECT COUNT(*) FROM users WHERE email = ?', (email,))
            if cursor.fetchone()[0] > 0:
                raise ValueError("邮箱已存在")
            
            # 创建用户
            user_id = self._generate_user_id()
            password_hash = self._hash_password(password)
            created_at = datetime.now().isoformat()
            
            cursor.execute('''
                INSERT INTO users (user_id, username, email, password_hash, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, username, email, password_hash, role.value, created_at))
            
            user = User(
                user_id=user_id,
                username=username,
                email=email,
                role=role,
                created_at=datetime.fromisoformat(created_at),
                last_login=datetime.now(),
                is_active=True
            )
            
            self.users[user_id] = user
            conn.commit()
            conn.close()
            
            logger.info(f"用户创建成功: {username}")
            return user
    
    def create_project(self, name: str, description: str, created_by: str) -> Project:
        """创建项目"""
        with self.db_lock:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            # 检查项目名是否已存在
            cursor.execute('SELECT COUNT(*) FROM projects WHERE name = ?', (name,))
            if cursor.fetchone()[0] > 0:
                raise ValueError("项目名已存在")
            
            # 创建项目
            project_id = self._generate_project_id()
            created_at = datetime.now().isoformat()
            modified_at = created_at
            
            # 创建者自动拥有管理员权限
            team_members = {created_by: PermissionLevel.ADMIN}
            
            cursor.execute('''
                INSERT INTO projects (project_id, name, description, status, created_by, created_at, modified_at, team_members)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                project_id, name, description, ProjectStatus.PLANNING.value,
                created_by, created_at, modified_at, json.dumps({created_by: PermissionLevel.ADMIN.value})
            ))
            
            project = Project(
                project_id=project_id,
                name=name,
                description=description,
                status=ProjectStatus.PLANNING,
                created_by=created_by,
                created_at=datetime.fromisoformat(created_at),
                modified_at=datetime.fromisoformat(modified_at),
                team_members=team_members
            )
            
            self.projects[project_id] = project
            conn.commit()
            conn.close()
            
            # 记录协作事件
            self._log_collaboration_event(
                project_id, created_by, "project_created",
                f"项目 '{name}' 已创建", {}
            )
            
            logger.info(f"项目创建成功: {name}")
            return project
    
    def add_user_to_project(self, project_id: str, user_id: str, permission: PermissionLevel) -> bool:
        """添加用户到项目"""
        if project_id not in self.projects:
            return False
        
        if user_id not in self.users:
            return False
        
        with self.db_lock:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            project = self.projects[project_id]
            project.team_members[user_id] = permission
            project.modified_at = datetime.now()
            
            # 更新数据库
            cursor.execute('''
                UPDATE projects 
                SET team_members = ?, modified_at = ?
                WHERE project_id = ?
            ''', (
                json.dumps({uid: perm.value for uid, perm in project.team_members.items()}),
                project.modified_at.isoformat(),
                project_id
            ))
            
            conn.commit()
            conn.close()
            
            # 记录协作事件
            user = self.users[user_id]
            self._log_collaboration_event(
                project_id, project.created_by, "user_added",
                f"用户 '{user.username}' 已添加到项目",
                {'user_id': user_id, 'permission': permission.value}
            )
            
            logger.info(f"用户 {user.username} 已添加到项目 {project.name}")
            return True
    
    def check_permission(self, project_id: str, user_id: str, required_permission: PermissionLevel) -> bool:
        """检查用户权限"""
        if project_id not in self.projects:
            return False
        
        project = self.projects[project_id]
        
        if user_id not in project.team_members:
            return False
        
        user_permission = project.team_members[user_id]
        
        # 权限检查逻辑
        permission_hierarchy = {
            PermissionLevel.READ: 1,
            PermissionLevel.WRITE: 2,
            PermissionLevel.EXECUTE: 3,
            PermissionLevel.ADMIN: 4
        }
        
        return permission_hierarchy[user_permission] >= permission_hierarchy[required_permission]
    
    def _log_collaboration_event(self, project_id: str, user_id: str, 
                               event_type: str, description: str, data: Dict):
        """记录协作事件"""
        with self.db_lock:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            event_id = self._generate_event_id()
            timestamp = datetime.now().isoformat()
            
            cursor.execute('''
                INSERT INTO collaboration_events (event_id, project_id, user_id, event_type, description, data, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (event_id, project_id, user_id, event_type, description, json.dumps(data), timestamp))
            
            conn.commit()
            conn.close()
    
    def get_project_events(self, project_id: str, limit: int = 100) -> List[CollaborationEvent]:
        """获取项目协作事件"""
        events = []
        
        with self.db_lock:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM collaboration_events 
                WHERE project_id = ? 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (project_id, limit))
            
            rows = cursor.fetchall()
            
            for row in rows:
                event = CollaborationEvent(
                    event_id=row[0],
                    project_id=row[1],
                    user_id=row[2],
                    event_type=row[3],
                    description=row[4],
                    data=json.loads(row[5]),
                    timestamp=datetime.fromisoformat(row[6])
                )
                events.append(event)
            
            conn.close()
        
        return events
    
    def create_session(self, user_id: str) -> str:
        """创建用户会话"""
        session_id = secrets.token_urlsafe(32)
        
        self.sessions[session_id] = {
            'user_id': user_id,
            'created_at': datetime.now(),
            'last_activity': datetime.now()
        }
        
        return session_id
    
    def validate_session(self, session_id: str) -> Optional[User]:
        """验证会话"""
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        
        # 检查会话是否过期（24小时）
        if (datetime.now() - session['last_activity']).total_seconds() > 24 * 3600:
            del self.sessions[session_id]
            return None
        
        # 更新最后活动时间
        session['last_activity'] = datetime.now()
        
        user_id = session['user_id']
        return self.users.get(user_id)
    
    def _hash_password(self, password: str) -> str:
        """哈希密码"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """验证密码"""
        return self._hash_password(password) == password_hash
    
    def _generate_user_id(self) -> str:
        """生成用户ID"""
        return f"user_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
    
    def _generate_project_id(self) -> str:
        """生成项目ID"""
        return f"project_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    def _generate_event_id(self) -> str:
        """生成事件ID"""
        return f"event_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
    
    # ========== 公共方法 ==========
    
    def get_user(self, user_id: str) -> Optional[User]:
        """获取用户"""
        return self.users.get(user_id)
    
    def get_all_users(self) -> List[User]:
        """获取所有用户"""
        return list(self.users.values())
    
    def get_project(self, project_id: str) -> Optional[Project]:
        """获取项目"""
        return self.projects.get(project_id)
    
    def get_user_projects(self, user_id: str) -> List[Project]:
        """获取用户参与的项目"""
        return [p for p in self.projects.values() if user_id in p.team_members]
    
    def get_all_projects(self) -> List[Project]:
        """获取所有项目"""
        return list(self.projects.values())
    
    def update_project_status(self, project_id: str, status: ProjectStatus) -> bool:
        """更新项目状态"""
        if project_id not in self.projects:
            return False
        
        with self.db_lock:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            project = self.projects[project_id]
            project.status = status
            project.modified_at = datetime.now()
            
            cursor.execute('''
                UPDATE projects 
                SET status = ?, modified_at = ?
                WHERE project_id = ?
            ''', (status.value, project.modified_at.isoformat(), project_id))
            
            conn.commit()
            conn.close()
            
            # 记录协作事件
            self._log_collaboration_event(
                project_id, project.created_by, "status_updated",
                f"项目状态更新为: {status.value}",
                {'old_status': project.status.value, 'new_status': status.value}
            )
            
            return True

class RealTimeCollaboration:
    """实时协作系统"""
    
    def __init__(self, team_manager: TeamManager):
        self.team_manager = team_manager
        self.connected_users: Dict[str, Dict] = {}  # user_id -> connection_info
        self.project_rooms: Dict[str, List[str]] = {}  # project_id -> [user_id]
        self.message_handlers: Dict[str, Callable] = {}
        
        # 注册消息处理器
        self._register_message_handlers()
        
        logger.info("实时协作系统初始化完成")
    
    def _register_message_handlers(self):
        """注册消息处理器"""
        self.message_handlers['join_project'] = self._handle_join_project
        self.message_handlers['leave_project'] = self._handle_leave_project
        self.message_handlers['send_message'] = self._handle_send_message
        self.message_handlers['update_data'] = self._handle_update_data
    
    async def handle_websocket_message(self, user_id: str, message: Dict):
        """处理WebSocket消息"""
        message_type = message.get('type')
        
        if message_type in self.message_handlers:
            await self.message_handlers[message_type](user_id, message)
        else:
            logger.warning(f"未知的消息类型: {message_type}")
    
    async def _handle_join_project(self, user_id: str, message: Dict):
        """处理加入项目消息"""
        project_id = message.get('project_id')
        
        if project_id and self.team_manager.check_permission(project_id, user_id, PermissionLevel.READ):
            if project_id not in self.project_rooms:
                self.project_rooms[project_id] = []
            
            if user_id not in self.project_rooms[project_id]:
                self.project_rooms[project_id].append(user_id)
                
                # 广播用户加入消息
                await self._broadcast_to_project(project_id, {
                    'type': 'user_joined',
                    'user_id': user_id,
                    'timestamp': datetime.now().isoformat()
                })
                
                logger.info(f"用户 {user_id} 加入项目 {project_id}")
    
    async def _handle_leave_project(self, user_id: str, message: Dict):
        """处理离开项目消息"""
        project_id = message.get('project_id')
        
        if project_id and project_id in self.project_rooms:
            if user_id in self.project_rooms[project_id]:
                self.project_rooms[project_id].remove(user_id)
                
                # 广播用户离开消息
                await self._broadcast_to_project(project_id, {
                    'type': 'user_left',
                    'user_id': user_id,
                    'timestamp': datetime.now().isoformat()
                })
                
                logger.info(f"用户 {user_id} 离开项目 {project_id}")
    
    async def _handle_send_message(self, user_id: str, message: Dict):
        """处理发送消息"""
        project_id = message.get('project_id')
        content = message.get('content')
        
        if project_id and content and self.team_manager.check_permission(project_id, user_id, PermissionLevel.WRITE):
            # 广播消息
            await self._broadcast_to_project(project_id, {
                'type': 'chat_message',
                'user_id': user_id,
                'content': content,
                'timestamp': datetime.now().isoformat()
            })
            
            # 记录协作事件
            self.team_manager._log_collaboration_event(
                project_id, user_id, "chat_message",
                f"用户发送聊天消息",
                {'content': content}
            )
    
    async def _handle_update_data(self, user_id: str, message: Dict):
        """处理数据更新消息"""
        project_id = message.get('project_id')
        data_type = message.get('data_type')
        data = message.get('data')
        
        if project_id and data_type and data and self.team_manager.check_permission(project_id, user_id, PermissionLevel.WRITE):
            # 广播数据更新
            await self._broadcast_to_project(project_id, {
                'type': 'data_updated',
                'user_id': user_id,
                'data_type': data_type,
                'data': data,
                'timestamp': datetime.now().isoformat()
            })
            
            # 记录协作事件
            self.team_manager._log_collaboration_event(
                project_id, user_id, "data_updated",
                f"用户更新了 {data_type} 数据",
                {'data_type': data_type, 'data': data}
            )
    
    async def _broadcast_to_project(self, project_id: str, message: Dict):
        """向项目房间广播消息"""
        if project_id in self.project_rooms:
            # 这里需要实际的WebSocket连接实现
            # 目前是占位实现
            user_ids = self.project_rooms[project_id]
            
            for user_id in user_ids:
                if user_id in self.connected_users:
                    # 实际实现中这里会通过WebSocket发送消息
                    pass
    
    def user_connected(self, user_id: str, connection_info: Dict):
        """用户连接"""
        self.connected_users[user_id] = connection_info
        logger.info(f"用户 {user_id} 已连接")
    
    def user_disconnected(self, user_id: str):
        """用户断开连接"""
        if user_id in self.connected_users:
            del self.connected_users[user_id]
            
            # 从所有项目房间中移除用户
            for project_id, user_list in self.project_rooms.items():
                if user_id in user_list:
                    user_list.remove(user_id)
            
            logger.info(f"用户 {user_id} 已断开连接")

# 数据共享管理器
class DataSharingManager:
    """数据共享管理器"""
    
    def __init__(self, team_manager: TeamManager):
        self.team_manager = team_manager
        self.shared_data: Dict[str, Dict] = {}  # data_id -> data_info
        
        logger.info("数据共享管理器初始化完成")
    
    def share_data(self, project_id: str, user_id: str, data_type: str, 
                  data: Any, description: str = "") -> str:
        """共享数据"""
        if not self.team_manager.check_permission(project_id, user_id, PermissionLevel.WRITE):
            raise PermissionError("用户没有写入权限")
        
        data_id = self._generate_data_id()
        
        shared_data = {
            'data_id': data_id,
            'project_id': project_id,
            'shared_by': user_id,
            'data_type': data_type,
            'data': data,
            'description': description,
            'shared_at': datetime.now(),
            'access_count': 0
        }
        
        self.shared_data[data_id] = shared_data
        
        # 记录协作事件
        self.team_manager._log_collaboration_event(
            project_id, user_id, "data_shared",
            f"用户共享了 {data_type} 数据",
            {'data_id': data_id, 'data_type': data_type, 'description': description}
        )
        
        logger.info(f"数据共享成功: {data_id}")
        return data_id
    
    def get_shared_data(self, project_id: str, user_id: str, data_id: str) -> Optional[Dict]:
        """获取共享数据"""
        if data_id not in self.shared_data:
            return None
        
        shared_data = self.shared_data[data_id]
        
        # 检查权限
        if shared_data['project_id'] != project_id:
            return None
        
        if not self.team_manager.check_permission(project_id, user_id, PermissionLevel.READ):
            return None
        
        # 更新访问计数
        shared_data['access_count'] += 1
        
        return shared_data
    
    def get_project_shared_data(self, project_id: str, user_id: str) -> List[Dict]:
        """获取项目的所有共享数据"""
        if not self.team_manager.check_permission(project_id, user_id, PermissionLevel.READ):
            return []
        
        project_data = []
        
        for data_id, shared_data in self.shared_data.items():
            if shared_data['project_id'] == project_id:
                # 复制数据，不包含实际数据内容
                data_info = shared_data.copy()
                if 'data' in data_info:
                    del data_info['data']  # 不返回实际数据
                project_data.append(data_info)
        
        return project_data
    
    def _generate_data_id(self) -> str:
        """生成数据ID"""
        return f"data_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"

# 协作系统管理器
class CollaborationSystem:
    """协作系统管理器"""
    
    def __init__(self, database_path: str = "team_collaboration.db"):
        self.team_manager = TeamManager(database_path)
        self.real_time_collab = RealTimeCollaboration(self.team_manager)
        self.data_sharing_manager = DataSharingManager(self.team_manager)
        
        logger.info("协作系统初始化完成")
    
    def authenticate(self, username: str, password: str) -> Tuple[Optional[User], Optional[str]]:
        """用户认证"""
        user = self.team_manager.authenticate_user(username, password)
        
        if user:
            session_id = self.team_manager.create_session(user.user_id)
            return user, session_id
        
        return None, None
    
    def validate_session(self, session_id: str) -> Optional[User]:
        """验证会话"""
        return self.team_manager.validate_session(session_id)
    
    # 代理方法
    def create_user(self, username: str, email: str, password: str, role: UserRole) -> User:
        """创建用户"""
        return self.team_manager.create_user(username, email, password, role)
    
    def create_project(self, name: str, description: str, created_by: str) -> Project:
        """创建项目"""
        return self.team_manager.create_project(name, description, created_by)
    
    def share_data(self, project_id: str, user_id: str, data_type: str, 
                  data: Any, description: str = "") -> str:
        """共享数据"""
        return self.data_sharing_manager.share_data(project_id, user_id, data_type, data, description)
    
    def get_team_manager(self) -> TeamManager:
        """获取团队管理器"""
        return self.team_manager
    
    def get_real_time_collab(self) -> RealTimeCollaboration:
        """获取实时协作系统"""
        return self.real_time_collab
    
    def get_data_sharing_manager(self) -> DataSharingManager:
        """获取数据共享管理器"""
        return self.data_sharing_manager