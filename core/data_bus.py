"""
数据总线 - 统一SQLite数据库访问层
功能：
- 所有模块共享数据访问
- 统一的事务管理
- 数据模型注册和迁移
- 连接池管理
"""

import logging
import threading
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime
from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, scoped_session, declarative_base
from sqlalchemy.pool import NullPool

logger = logging.getLogger(__name__)

Base = declarative_base()


class DataBus:
    """数据总线"""
    
    def __init__(self, db_path: str = "data/app.db"):
        self._db_path = db_path
        self._engine = None
        self._session_factory = None
        self._scoped_session = None
        self._lock = threading.RLock()
        self._logger = logging.getLogger("DataBus")
        self._models: Dict[str, Any] = {}
        
        self._initialize()
    
    def _initialize(self):
        """初始化数据库连接"""
        try:
            db_path = Path(self._db_path).resolve()
            db_path.parent.mkdir(parents=True, exist_ok=True)
            
            # 创建引擎（使用NullPool避免SQLite文件锁定问题）
            self._engine = create_engine(
                f'sqlite:///{db_path}',
                poolclass=NullPool,
                connect_args={'check_same_thread': False},
                echo=False
            )
            
            # 创建会话工厂
            self._session_factory = sessionmaker(bind=self._engine)
            self._scoped_session = scoped_session(self._session_factory)
            
            # 启用WAL模式提高并发性能
            @event.listens_for(self._engine, "connect")
            def set_sqlite_pragma(dbapi_connection, connection_record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA cache_size=10000")
                cursor.execute("PRAGMA temp_store=MEMORY")
                cursor.close()
            
            self._logger.info(f"数据库初始化成功: {db_path}")
            
        except Exception as e:
            self._logger.error(f"数据库初始化失败: {e}")
            raise
    
    def register_model(self, model_name: str, model_class):
        """注册数据模型"""
        with self._lock:
            self._models[model_name] = model_class
            self._logger.debug(f"注册数据模型: {model_name}")
    
    def get_model(self, model_name: str):
        """获取数据模型"""
        return self._models.get(model_name)
    
    @contextmanager
    def get_session(self):
        """获取数据库会话（上下文管理器）"""
        session = self._scoped_session()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            self._logger.error(f"数据库操作失败: {e}")
            raise
        finally:
            self._scoped_session.remove()
    
    def execute_query(self, query_func):
        """执行查询"""
        with self.get_session() as session:
            return query_func(session)
    
    def execute_write(self, write_func):
        """执行写入"""
        with self.get_session() as session:
            result = write_func(session)
            return result
    
    def create_all_tables(self):
        """创建所有注册的表"""
        Base.metadata.create_all(self._engine)
        self._logger.info("创建所有数据表")
    
    def drop_all_tables(self):
        """删除所有表（谨慎使用）"""
        Base.metadata.drop_all(self._engine)
        self._logger.warning("删除所有数据表")
    
    def backup_database(self, backup_path: str):
        """备份数据库"""
        import shutil
        backup_path = Path(backup_path)
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self._db_path, backup_path)
        self._logger.info(f"数据库备份成功: {backup_path}")
    
    def get_stats(self) -> Dict[str, Any]:
        """获取数据库统计信息"""
        stats = {
            'db_path': self._db_path,
            'registered_models': list(self._models.keys()),
            'model_count': len(self._models),
        }
        
        try:
            with self.get_session() as session:
                stats['connection_active'] = True
        except:
            stats['connection_active'] = False
        
        return stats
    
    def close(self):
        """关闭数据库连接"""
        if self._scoped_session:
            self._scoped_session.remove()
        if self._engine:
            self._engine.dispose()
        self._logger.info("数据库连接已关闭")
