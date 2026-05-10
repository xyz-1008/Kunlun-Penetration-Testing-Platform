"""
C2框架集成模块 - MITM代理与C2框架深度集成
功能：
- 识别C2信标心跳流量，自动关联信标会话
- 支持将C2通信流量通过代理转发，统一流量出口
- 代理面板显示信标在线状态及最近通信时间
- 选中信标会话可直接下发命令，结果在代理面板展示
"""

import re
import json
import uuid
import time
import hashlib
import logging
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class BeaconStatus(Enum):
    """信标状态"""
    ONLINE = "online"
    OFFLINE = "offline"
    DORMANT = "dormant"
    COMPROMISED = "compromised"


class C2Protocol(Enum):
    """C2协议类型"""
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    SMB = "smb"
    TCP = "tcp"
    CUSTOM = "custom"


@dataclass
class BeaconSession:
    """信标会话"""
    id: str
    session_id: str
    hostname: str
    username: str
    internal_ip: str
    external_ip: str
    os_info: str
    architecture: str
    process_name: str
    process_id: int
    integrity_level: str
    first_seen: datetime
    last_seen: datetime
    status: BeaconStatus
    protocol: C2Protocol
    sleep_interval: int  # 秒
    jitter: int  # 百分比
    metadata: Dict[str, Any] = field(default_factory=dict)
    commands_sent: int = 0
    commands_completed: int = 0
    is_proxy_forwarded: bool = False


@dataclass
class C2Command:
    """C2命令"""
    id: str
    session_id: str
    command_type: str
    command_data: str
    status: str  # pending, sent, completed, failed
    created_at: datetime
    sent_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[str] = None
    error: Optional[str] = None


class C2BeaconDetector:
    """C2信标检测器 - 识别常见C2框架的信标流量特征"""
    
    def __init__(self):
        # Cobalt Strike 信标特征
        self._cs_beacon_patterns = [
            r'\/[a-zA-Z0-9]{8}\/[a-zA-Z0-9]{12}',  # CS默认URI格式
            r'User-Agent:.*Mozilla.*\(compatible;.*MSIE.*',  # CS默认UA
        ]
        
        # Metasploit 信标特征
        self._msf_beacon_patterns = [
            r'\/[a-zA-Z0-9]{8}\.gif',  # MSF默认URI
            r'User-Agent:.*Mozilla.*Windows.*',
        ]
        
        # Sliver 信标特征
        self._sliver_beacon_patterns = [
            r'\/[a-zA-Z0-9]{16}\/[a-zA-Z0-9]{16}',
        ]
        
        # 通用心跳特征
        self._heartbeat_patterns = [
            r'{"heartbeat":.*}',
            r'{"beacon":.*}',
            r'{"checkin":.*}',
        ]
        
        # 已知的C2域名特征
        self._c2_domain_patterns = [
            r'\.ddns\.net$',
            r'\.no-ip\.com$',
            r'\.duckdns\.org$',
            r'\.hopto\.org$',
            r'\.zapto\.org$',
        ]
    
    def detect_c2_beacon(self, request_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """检测C2信标流量"""
        try:
            url = request_data.get('url', '')
            headers = request_data.get('headers', {})
            body = request_data.get('body', '')
            method = request_data.get('method', 'GET')
            
            detection_result = {
                'is_c2': False,
                'framework': 'unknown',
                'confidence': 0.0,
                'indicators': [],
            }
            
            # 检测Cobalt Strike
            cs_score = self._check_patterns(url, headers, body, self._cs_beacon_patterns)
            if cs_score > 0.5:
                detection_result['is_c2'] = True
                detection_result['framework'] = 'cobalt_strike'
                detection_result['confidence'] = cs_score
                detection_result['indicators'].append('cobalt_strike_pattern')
            
            # 检测Metasploit
            msf_score = self._check_patterns(url, headers, body, self._msf_beacon_patterns)
            if msf_score > 0.5:
                detection_result['is_c2'] = True
                detection_result['framework'] = 'metasploit'
                detection_result['confidence'] = max(detection_result['confidence'], msf_score)
                detection_result['indicators'].append('metasploit_pattern')
            
            # 检测Sliver
            sliver_score = self._check_patterns(url, headers, body, self._sliver_beacon_patterns)
            if sliver_score > 0.5:
                detection_result['is_c2'] = True
                detection_result['framework'] = 'sliver'
                detection_result['confidence'] = max(detection_result['confidence'], sliver_score)
                detection_result['indicators'].append('sliver_pattern')
            
            # 检测心跳特征
            heartbeat_score = self._check_patterns(url, headers, body, self._heartbeat_patterns)
            if heartbeat_score > 0.3:
                detection_result['indicators'].append('heartbeat_pattern')
                detection_result['confidence'] = max(detection_result['confidence'], heartbeat_score)
            
            # 检测C2域名
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.hostname or ''
            for pattern in self._c2_domain_patterns:
                if re.search(pattern, domain, re.IGNORECASE):
                    detection_result['indicators'].append('suspicious_domain')
                    detection_result['confidence'] = max(detection_result['confidence'], 0.4)
                    break
            
            # 检查请求间隔（心跳特征）
            if self._is_heartbeat_request(request_data):
                detection_result['indicators'].append('heartbeat_timing')
                detection_result['confidence'] = max(detection_result['confidence'], 0.3)
            
            return detection_result if detection_result['is_c2'] or detection_result['confidence'] > 0.3 else None
            
        except Exception as e:
            logger.error(f"C2信标检测失败: {e}")
            return None
    
    def _check_patterns(self, url: str, headers: Dict, body: str, patterns: List[str]) -> float:
        """检查模式匹配度"""
        if not patterns:
            return 0.0
        
        matches = 0
        for pattern in patterns:
            if re.search(pattern, url, re.IGNORECASE):
                matches += 1
                continue
            if re.search(pattern, json.dumps(headers), re.IGNORECASE):
                matches += 1
                continue
            if re.search(pattern, body, re.IGNORECASE):
                matches += 1
        
        return matches / len(patterns)
    
    def _is_heartbeat_request(self, request_data: Dict[str, Any]) -> bool:
        """检查是否为心跳请求（基于请求特征）"""
        url = request_data.get('url', '')
        method = request_data.get('method', 'GET')
        body = request_data.get('body', '')
        
        # 心跳请求通常是GET或POST，body较小或包含特定字段
        if method == 'GET' and len(body) == 0:
            return True
        
        if method == 'POST' and len(body) < 200:
            try:
                data = json.loads(body) if body else {}
                if any(k in data for k in ['heartbeat', 'beacon', 'checkin', 'alive']):
                    return True
            except:
                pass
        
        return False


class C2SessionManager:
    """C2会话管理器"""
    
    def __init__(self):
        self._sessions: Dict[str, BeaconSession] = {}
        self._commands: Dict[str, C2Command] = {}
        self._session_history: Dict[str, List[Dict]] = {}
        self._callbacks: Dict[str, List[Callable]] = {
            'on_new_session': [],
            'on_session_update': [],
            'on_command_result': [],
        }
    
    def create_or_update_session(self, detection_result: Dict[str, Any], 
                                  request_data: Dict[str, Any]) -> Optional[BeaconSession]:
        """创建或更新信标会话"""
        try:
            # 生成会话ID（基于请求特征）
            url = request_data.get('url', '')
            headers = request_data.get('headers', {})
            
            # 尝试从请求中提取会话标识
            session_id = self._extract_session_id(request_data, detection_result)
            
            # 检查是否已存在
            if session_id in self._sessions:
                session = self._sessions[session_id]
                session.last_seen = datetime.utcnow()
                session.status = BeaconStatus.ONLINE
                session.is_proxy_forwarded = True
                
                # 通知更新
                for callback in self._callbacks['on_session_update']:
                    try:
                        callback(session)
                    except Exception as e:
                        logger.error(f"会话更新通知失败: {e}")
                
                return session
            
            # 创建新会话
            hostname = self._extract_hostname(request_data)
            username = self._extract_username(request_data)
            internal_ip = self._extract_internal_ip(request_data)
            external_ip = request_data.get('client_ip', '')
            os_info = self._extract_os_info(request_data, detection_result)
            
            session = BeaconSession(
                id=str(uuid.uuid4())[:12],
                session_id=session_id,
                hostname=hostname,
                username=username,
                internal_ip=internal_ip,
                external_ip=external_ip,
                os_info=os_info,
                architecture=self._extract_architecture(request_data),
                process_name=self._extract_process_name(request_data),
                process_id=self._extract_process_id(request_data),
                integrity_level=self._extract_integrity_level(request_data),
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                status=BeaconStatus.ONLINE,
                protocol=C2Protocol.HTTPS if 'https' in url else C2Protocol.HTTP,
                sleep_interval=60,
                jitter=20,
                is_proxy_forwarded=True,
            )
            
            self._sessions[session_id] = session
            self._session_history[session_id] = []
            
            # 通知新会话
            for callback in self._callbacks['on_new_session']:
                try:
                    callback(session)
                except Exception as e:
                    logger.error(f"新会话通知失败: {e}")
            
            return session
            
        except Exception as e:
            logger.error(f"创建/更新会话失败: {e}")
            return None
    
    def send_command(self, session_id: str, command_type: str, 
                     command_data: str) -> Optional[C2Command]:
        """向信标发送命令"""
        try:
            if session_id not in self._sessions:
                logger.error(f"会话不存在: {session_id}")
                return None
            
            command = C2Command(
                id=str(uuid.uuid4())[:12],
                session_id=session_id,
                command_type=command_type,
                command_data=command_data,
                status='pending',
                created_at=datetime.utcnow(),
            )
            
            self._commands[command.id] = command
            self._sessions[session_id].commands_sent += 1
            
            # 记录到会话历史
            if session_id in self._session_history:
                self._session_history[session_id].append({
                    'timestamp': datetime.utcnow(),
                    'type': 'command_sent',
                    'command_id': command.id,
                    'command_type': command_type,
                })
            
            return command
            
        except Exception as e:
            logger.error(f"发送命令失败: {e}")
            return None
    
    def update_command_result(self, command_id: str, result: str, 
                               error: str = None):
        """更新命令执行结果"""
        try:
            if command_id not in self._commands:
                logger.error(f"命令不存在: {command_id}")
                return
            
            command = self._commands[command_id]
            command.result = result
            command.error = error
            command.status = 'failed' if error else 'completed'
            command.completed_at = datetime.utcnow()
            
            # 更新会话统计
            if command.session_id in self._sessions:
                self._sessions[command.session_id].commands_completed += 1
                
                # 记录到会话历史
                if command.session_id in self._session_history:
                    self._session_history[command.session_id].append({
                        'timestamp': datetime.utcnow(),
                        'type': 'command_result',
                        'command_id': command_id,
                        'result': result[:100] if result else '',
                    })
            
            # 通知结果
            for callback in self._callbacks['on_command_result']:
                try:
                    callback(command)
                except Exception as e:
                    logger.error(f"命令结果通知失败: {e}")
            
        except Exception as e:
            logger.error(f"更新命令结果失败: {e}")
    
    def get_active_sessions(self) -> List[BeaconSession]:
        """获取活跃会话"""
        now = datetime.utcnow()
        active = []
        for session in self._sessions.values():
            # 5分钟内有过通信视为活跃
            if (now - session.last_seen).total_seconds() < 300:
                active.append(session)
            else:
                session.status = BeaconStatus.OFFLINE
        return active
    
    def get_session_history(self, session_id: str) -> List[Dict]:
        """获取会话历史"""
        return self._session_history.get(session_id, [])
    
    def on_new_session(self, callback: Callable):
        """注册新会话回调"""
        self._callbacks['on_new_session'].append(callback)
    
    def on_session_update(self, callback: Callable):
        """注册会话更新回调"""
        self._callbacks['on_session_update'].append(callback)
    
    def on_command_result(self, callback: Callable):
        """注册命令结果回调"""
        self._callbacks['on_command_result'].append(callback)
    
    def _extract_session_id(self, request_data: Dict, detection: Dict) -> str:
        """提取会话ID"""
        # 尝试从Cookie中提取
        headers = request_data.get('headers', {})
        cookie = headers.get('cookie', headers.get('Cookie', ''))
        
        # 尝试常见会话标识字段
        for field in ['SESSION', 'JSESSIONID', 'PHPSESSID', 'ASPSESSIONID']:
            if field in cookie:
                return cookie.split(f'{field}=')[1].split(';')[0]
        
        # 基于URL和User-Agent生成唯一ID
        url = request_data.get('url', '')
        ua = headers.get('user-agent', headers.get('User-Agent', ''))
        raw_id = f"{url}:{ua}"
        return hashlib.md5(raw_id.encode()).hexdigest()[:16]
    
    def _extract_hostname(self, request_data: Dict) -> str:
        """提取主机名"""
        headers = request_data.get('headers', {})
        body = request_data.get('body', '')
        
        # 尝试从body中提取
        try:
            data = json.loads(body) if body else {}
            for field in ['hostname', 'computername', 'host', 'name']:
                if field in data:
                    return str(data[field])
        except:
            pass
        
        return 'unknown'
    
    def _extract_username(self, request_data: Dict) -> str:
        """提取用户名"""
        body = request_data.get('body', '')
        try:
            data = json.loads(body) if body else {}
            for field in ['username', 'user', 'login', 'account']:
                if field in data:
                    return str(data[field])
        except:
            pass
        
        return 'unknown'
    
    def _extract_internal_ip(self, request_data: Dict) -> str:
        """提取内网IP"""
        body = request_data.get('body', '')
        try:
            data = json.loads(body) if body else {}
            for field in ['internal_ip', 'local_ip', 'ip', 'address']:
                if field in data:
                    return str(data[field])
        except:
            pass
        
        return ''
    
    def _extract_os_info(self, request_data: Dict, detection: Dict) -> str:
        """提取操作系统信息"""
        body = request_data.get('body', '')
        try:
            data = json.loads(body) if body else {}
            for field in ['os', 'os_version', 'platform', 'system']:
                if field in data:
                    return str(data[field])
        except:
            pass
        
        return 'unknown'
    
    def _extract_architecture(self, request_data: Dict) -> str:
        """提取架构信息"""
        body = request_data.get('body', '')
        try:
            data = json.loads(body) if body else {}
            for field in ['arch', 'architecture', 'bit']:
                if field in data:
                    return str(data[field])
        except:
            pass
        
        return 'unknown'
    
    def _extract_process_name(self, request_data: Dict) -> str:
        """提取进程名"""
        body = request_data.get('body', '')
        try:
            data = json.loads(body) if body else {}
            for field in ['process', 'process_name', 'exe']:
                if field in data:
                    return str(data[field])
        except:
            pass
        
        return 'unknown'
    
    def _extract_process_id(self, request_data: Dict) -> int:
        """提取进程ID"""
        body = request_data.get('body', '')
        try:
            data = json.loads(body) if body else {}
            for field in ['pid', 'process_id']:
                if field in data:
                    return int(data[field])
        except:
            pass
        
        return 0
    
    def _extract_integrity_level(self, request_data: Dict) -> str:
        """提取完整性级别"""
        body = request_data.get('body', '')
        try:
            data = json.loads(body) if body else {}
            for field in ['integrity', 'integrity_level', 'privilege']:
                if field in data:
                    return str(data[field])
        except:
            pass
        
        return 'unknown'


class C2LinkageEngine:
    """C2框架联动引擎"""
    
    def __init__(self):
        self.detector = C2BeaconDetector()
        self.session_manager = C2SessionManager()
        
        self._c2_detected_callbacks: List[Callable] = []
        self._command_result_callbacks: List[Callable] = []
        
        # 注册内部回调
        self.session_manager.on_new_session(self._on_new_session)
        self.session_manager.on_command_result(self._on_command_result)
    
    def process_traffic(self, request_data: Dict[str, Any], 
                       response_data: Dict[str, Any]):
        """处理流量，检测C2信标"""
        try:
            # 检测C2信标
            detection = self.detector.detect_c2_beacon(request_data)
            
            if detection and (detection['is_c2'] or detection['confidence'] > 0.3):
                # 创建或更新会话
                session = self.session_manager.create_or_update_session(
                    detection, request_data
                )
                
                if session:
                    # 通知C2检测事件
                    for callback in self._c2_detected_callbacks:
                        try:
                            callback(session, detection)
                        except Exception as e:
                            logger.error(f"C2检测通知失败: {e}")
            
        except Exception as e:
            logger.error(f"C2联动处理失败: {e}")
    
    def send_command(self, session_id: str, command_type: str, 
                     command_data: str) -> Optional[C2Command]:
        """向信标发送命令"""
        return self.session_manager.send_command(session_id, command_type, command_data)
    
    def get_active_sessions(self) -> List[BeaconSession]:
        """获取活跃会话"""
        return self.session_manager.get_active_sessions()
    
    def get_session_history(self, session_id: str) -> List[Dict]:
        """获取会话历史"""
        return self.session_manager.get_session_history(session_id)
    
    def on_c2_detected(self, callback: Callable):
        """注册C2检测回调"""
        self._c2_detected_callbacks.append(callback)
    
    def on_command_result(self, callback: Callable):
        """注册命令结果回调"""
        self._command_result_callbacks.append(callback)
    
    def _on_new_session(self, session: BeaconSession):
        """新会话内部回调"""
        logger.info(f"检测到新C2信标会话: {session.session_id} ({session.hostname})")
    
    def _on_command_result(self, command: C2Command):
        """命令结果内部回调"""
        for callback in self._command_result_callbacks:
            try:
                callback(command)
            except Exception as e:
                logger.error(f"命令结果通知失败: {e}")
