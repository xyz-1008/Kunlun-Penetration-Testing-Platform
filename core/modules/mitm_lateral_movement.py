"""
横向移动模块联动 - MITM代理与横向移动模块深度集成
功能：
- 代理检测到内网IP请求时自动标记
- 自动识别横向移动流量特征（SMB/WMI/WinRM）
- 代理捕获的凭据传输自动提取并加密存储到凭据库
- 内网资产发现后自动更新知识图谱中的网络拓扑
"""

import re
import json
import uuid
import hashlib
import logging
from typing import Dict, List, Any, Optional, Callable, Tuple
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class LateralMovementProtocol(Enum):
    """横向移动协议"""
    SMB = "smb"
    WMI = "wmi"
    WINRM = "winrm"
    RDP = "rdp"
    SSH = "ssh"
    PSEXEC = "psexec"
    DCOM = "dcom"
    RPC = "rpc"
    LDAP = "ldap"
    KERBEROS = "kerberos"


class CredentialType(Enum):
    """凭据类型"""
    PASSWORD = "password"
    HASH_NTLM = "hash_ntlm"
    HASH_KERBEROS = "hash_kerberos"
    CERTIFICATE = "certificate"
    TOKEN = "token"
    API_KEY = "api_key"


@dataclass
class InternalAsset:
    """内网资产"""
    id: str
    ip: str
    hostname: str
    os_type: str
    open_ports: List[int]
    services: Dict[str, Any]
    first_seen: datetime
    last_seen: datetime
    is_domain_controller: bool = False
    is_critical_asset: bool = False
    network_segment: str = ""
    vulnerability_count: int = 0


@dataclass
class Credential:
    """凭据"""
    id: str
    type: CredentialType
    username: str
    domain: str
    value: str  # 加密存储
    source_ip: str
    target_ip: str
    protocol: str
    captured_at: datetime
    is_validated: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LateralMovementEvent:
    """横向移动事件"""
    id: str
    timestamp: datetime
    source_ip: str
    target_ip: str
    protocol: LateralMovementProtocol
    username: str
    success: bool
    technique: str  # MITRE ATT&CK technique
    details: Dict[str, Any] = field(default_factory=dict)


class InternalIPDetector:
    """内网IP检测器"""
    
    def __init__(self):
        # RFC 1918 私有地址
        self._private_ranges = [
            (self._ip_to_int('10.0.0.0'), self._ip_to_int('10.255.255.255')),
            (self._ip_to_int('172.16.0.0'), self._ip_to_int('172.31.255.255')),
            (self._ip_to_int('192.168.0.0'), self._ip_to_int('192.168.255.255')),
        ]
        
        # 本地回环
        self._loopback_ranges = [
            (self._ip_to_int('127.0.0.0'), self._ip_to_int('127.255.255.255')),
        ]
        
        # APIPA
        self._apipa_ranges = [
            (self._ip_to_int('169.254.0.0'), self._ip_to_int('169.254.255.255')),
        ]
    
    def is_internal_ip(self, ip: str) -> bool:
        """检查是否为内网IP"""
        if not ip:
            return False
        
        try:
            ip_int = self._ip_to_int(ip)
            
            for start, end in self._private_ranges:
                if start <= ip_int <= end:
                    return True
            
            for start, end in self._loopback_ranges:
                if start <= ip_int <= end:
                    return True
            
            for start, end in self._apipa_ranges:
                if start <= ip_int <= end:
                    return True
            
            return False
            
        except:
            return False
    
    def get_network_segment(self, ip: str) -> str:
        """获取网段"""
        try:
            parts = ip.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except:
            pass
        return ""
    
    def _ip_to_int(self, ip: str) -> int:
        """IP转整数"""
        parts = ip.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])


class LateralMovementDetector:
    """横向移动流量检测器"""
    
    def __init__(self):
        # SMB流量特征
        self._smb_patterns = [
            r'\\x83\\x00',  # SMB over TCP
            r'SMB',  # SMB协议标识
            r'\\PIPE\\',  # 命名管道
            r'IPC\$',  # IPC共享
            r'ADMIN\$',  # 管理共享
            r'C\$',  # 默认共享
        ]
        
        # WMI流量特征
        self._wmi_patterns = [
            r'ROOT\\CIMV2',  # WMI命名空间
            r'Win32_Process',  # WMI类
            r'wmic',  # WMI命令行
            r'__Win32Provider',
        ]
        
        # WinRM流量特征
        self._winrm_patterns = [
            r'wsman',  # WinRM服务
            r'http://schemas.microsoft.com/wbem/wsman',
            r'/wsman',  # WinRM端点
            r'5985',  # WinRM HTTP端口
            r'5986',  # WinRM HTTPS端口
        ]
        
        # PsExec特征
        self._psexec_patterns = [
            r'PSEXESVC',  # PsExec服务
            r'psexec',
            r'\\WINDOWS\\PSEXESVC\.exe',
        ]
        
        # DCOM特征
        self._dcom_patterns = [
            r'MMC20.Application',
            r'Shell.Application',
            r'Excel.Application',
        ]
    
    def detect_lateral_movement(self, request_data: Dict[str, Any], 
                                 response_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """检测横向移动流量"""
        try:
            url = request_data.get('url', '')
            headers = request_data.get('headers', {})
            body = request_data.get('body', '')
            method = request_data.get('method', '')
            
            detection = {
                'is_lateral_movement': False,
                'protocol': None,
                'confidence': 0.0,
                'technique': '',
                'indicators': [],
            }
            
            # 检测SMB
            smb_score = self._check_patterns(url, headers, body, self._smb_patterns)
            if smb_score > 0.3:
                detection['is_lateral_movement'] = True
                detection['protocol'] = LateralMovementProtocol.SMB
                detection['confidence'] = smb_score
                detection['technique'] = 'T1021.002'  # SMB/Windows Admin Shares
                detection['indicators'].append('smb_traffic')
            
            # 检测WMI
            wmi_score = self._check_patterns(url, headers, body, self._wmi_patterns)
            if wmi_score > 0.3:
                detection['is_lateral_movement'] = True
                detection['protocol'] = LateralMovementProtocol.WMI
                detection['confidence'] = max(detection['confidence'], wmi_score)
                detection['technique'] = 'T1047'  # Windows Management Instrumentation
                detection['indicators'].append('wmi_traffic')
            
            # 检测WinRM
            winrm_score = self._check_patterns(url, headers, body, self._winrm_patterns)
            if winrm_score > 0.3:
                detection['is_lateral_movement'] = True
                detection['protocol'] = LateralMovementProtocol.WINRM
                detection['confidence'] = max(detection['confidence'], winrm_score)
                detection['technique'] = 'T1021.006'  # Windows Remote Management
                detection['indicators'].append('winrm_traffic')
            
            # 检测PsExec
            psexec_score = self._check_patterns(url, headers, body, self._psexec_patterns)
            if psexec_score > 0.3:
                detection['is_lateral_movement'] = True
                detection['protocol'] = LateralMovementProtocol.PSEXEC
                detection['confidence'] = max(detection['confidence'], psexec_score)
                detection['technique'] = 'T1570'  # Lateral Tool Transfer
                detection['indicators'].append('psexec_traffic')
            
            # 检测DCOM
            dcom_score = self._check_patterns(url, headers, body, self._dcom_patterns)
            if dcom_score > 0.3:
                detection['is_lateral_movement'] = True
                detection['protocol'] = LateralMovementProtocol.DCOM
                detection['confidence'] = max(detection['confidence'], dcom_score)
                detection['technique'] = 'T1009'  # Process Injection
                detection['indicators'].append('dcom_traffic')
            
            return detection if detection['is_lateral_movement'] else None
            
        except Exception as e:
            logger.error(f"横向移动检测失败: {e}")
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


class CredentialExtractor:
    """凭据提取器"""
    
    def __init__(self):
        # 常见凭据字段
        self._credential_fields = [
            'password', 'passwd', 'pwd', 'pass',
            'ntlm', 'nt_hash', 'lm_hash',
            'kerberos', 'ticket', 'tgt', 'tgs',
            'token', 'access_token', 'auth_token',
            'api_key', 'apikey', 'secret',
            'certificate', 'cert', 'pfx', 'p12',
        ]
        
        # 认证Header
        self._auth_headers = [
            'authorization', 'x-auth-token', 'x-api-key',
            'x-access-token', 'cookie', 'set-cookie',
        ]
    
    def extract_credentials(self, request_data: Dict[str, Any], 
                            response_data: Dict[str, Any]) -> List[Credential]:
        """提取凭据"""
        credentials = []
        
        try:
            # 从请求头提取
            headers = request_data.get('headers', {})
            source_ip = request_data.get('client_ip', '')
            target_ip = request_data.get('server_ip', '')
            
            for header in self._auth_headers:
                if header in headers:
                    value = headers[header]
                    cred_type = self._classify_credential(header, value)
                    if cred_type:
                        credentials.append(Credential(
                            id=str(uuid.uuid4())[:12],
                            type=cred_type,
                            username=self._extract_username(request_data),
                            domain=self._extract_domain(request_data),
                            value=self._encrypt_value(value),
                            source_ip=source_ip,
                            target_ip=target_ip,
                            protocol=request_data.get('protocol', 'http'),
                            captured_at=datetime.utcnow(),
                        ))
            
            # 从请求体提取
            body = request_data.get('body', '')
            if body:
                try:
                    data = json.loads(body) if body.startswith('{') else {}
                    for field in self._credential_fields:
                        if field in data:
                            cred_type = self._classify_credential(field, str(data[field]))
                            if cred_type:
                                credentials.append(Credential(
                                    id=str(uuid.uuid4())[:12],
                                    type=cred_type,
                                    username=data.get('username', data.get('user', '')),
                                    domain=data.get('domain', ''),
                                    value=self._encrypt_value(str(data[field])),
                                    source_ip=source_ip,
                                    target_ip=target_ip,
                                    protocol=request_data.get('protocol', 'http'),
                                    captured_at=datetime.utcnow(),
                                ))
                except:
                    # 尝试表单格式
                    for field in self._credential_fields:
                        pattern = rf'{field}=([^&\s]+)'
                        match = re.search(pattern, body)
                        if match:
                            credentials.append(Credential(
                                id=str(uuid.uuid4())[:12],
                                type=CredentialType.PASSWORD,
                                username=self._extract_username(request_data),
                                domain='',
                                value=self._encrypt_value(match.group(1)),
                                source_ip=source_ip,
                                target_ip=target_ip,
                                protocol=request_data.get('protocol', 'http'),
                                captured_at=datetime.utcnow(),
                            ))
            
        except Exception as e:
            logger.error(f"凭据提取失败: {e}")
        
        return credentials
    
    def _classify_credential(self, field: str, value: str) -> Optional[CredentialType]:
        """分类凭据类型"""
        field_lower = field.lower()
        
        if 'password' in field_lower or 'passwd' in field_lower or 'pwd' in field_lower:
            return CredentialType.PASSWORD
        
        if 'ntlm' in field_lower or 'nt_hash' in field_lower:
            return CredentialType.HASH_NTLM
        
        if 'kerberos' in field_lower or 'ticket' in field_lower:
            return CredentialType.HASH_KERBEROS
        
        if 'token' in field_lower:
            return CredentialType.TOKEN
        
        if 'api_key' in field_lower or 'apikey' in field_lower:
            return CredentialType.API_KEY
        
        if 'certificate' in field_lower or 'cert' in field_lower:
            return CredentialType.CERTIFICATE
        
        return None
    
    def _extract_username(self, request_data: Dict) -> str:
        """提取用户名"""
        body = request_data.get('body', '')
        try:
            data = json.loads(body) if body.startswith('{') else {}
            return data.get('username', data.get('user', data.get('login', '')))
        except:
            return ''
    
    def _extract_domain(self, request_data: Dict) -> str:
        """提取域名"""
        body = request_data.get('body', '')
        try:
            data = json.loads(body) if body.startswith('{') else {}
            return data.get('domain', data.get('realm', ''))
        except:
            return ''
    
    def _encrypt_value(self, value: str) -> str:
        """加密凭据值（简单示例，实际应使用更强的加密）"""
        # 实际应用中应使用AES或其他加密算法
        return hashlib.sha256(value.encode()).hexdigest()


class NetworkTopologyManager:
    """网络拓扑管理器"""
    
    def __init__(self):
        self._assets: Dict[str, InternalAsset] = {}
        self._connections: List[Tuple[str, str, str]] = []  # (source, target, protocol)
        self._callbacks: List[Callable] = []
    
    def update_topology(self, source_ip: str, target_ip: str, 
                        protocol: str, asset_info: Dict[str, Any] = None):
        """更新网络拓扑"""
        try:
            # 更新或创建目标资产
            if target_ip not in self._assets:
                asset = InternalAsset(
                    id=str(uuid.uuid4())[:12],
                    ip=target_ip,
                    hostname=asset_info.get('hostname', '') if asset_info else '',
                    os_type=asset_info.get('os_type', '') if asset_info else '',
                    open_ports=asset_info.get('open_ports', []) if asset_info else [],
                    services=asset_info.get('services', {}) if asset_info else {},
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    network_segment=InternalIPDetector().get_network_segment(target_ip),
                )
                self._assets[target_ip] = asset
            else:
                self._assets[target_ip].last_seen = datetime.utcnow()
                if asset_info:
                    if asset_info.get('hostname'):
                        self._assets[target_ip].hostname = asset_info['hostname']
                    if asset_info.get('os_type'):
                        self._assets[target_ip].os_type = asset_info['os_type']
                    if asset_info.get('open_ports'):
                        self._assets[target_ip].open_ports = list(set(
                            self._assets[target_ip].open_ports + asset_info['open_ports']
                        ))
            
            # 添加连接关系
            connection = (source_ip, target_ip, protocol)
            if connection not in self._connections:
                self._connections.append(connection)
                
                # 通知拓扑更新
                for callback in self._callbacks:
                    try:
                        callback(source_ip, target_ip, protocol)
                    except Exception as e:
                        logger.error(f"拓扑更新通知失败: {e}")
            
        except Exception as e:
            logger.error(f"更新网络拓扑失败: {e}")
    
    def get_assets(self) -> List[InternalAsset]:
        """获取所有资产"""
        return list(self._assets.values())
    
    def get_connections(self) -> List[Tuple[str, str, str]]:
        """获取所有连接"""
        return self._connections
    
    def on_topology_update(self, callback: Callable):
        """注册拓扑更新回调"""
        self._callbacks.append(callback)


class LateralMovementLinkage:
    """横向移动模块联动器"""
    
    def __init__(self):
        self.ip_detector = InternalIPDetector()
        self.lm_detector = LateralMovementDetector()
        self.credential_extractor = CredentialExtractor()
        self.topology_manager = NetworkTopologyManager()
        
        self._internal_ip_callbacks: List[Callable] = []
        self._lateral_movement_callbacks: List[Callable] = []
        self._credential_callbacks: List[Callable] = []
        self._topology_callbacks: List[Callable] = []
        
        # 注册内部回调
        self.topology_manager.on_topology_update(self._on_topology_update)
    
    def process_traffic(self, request_data: Dict[str, Any], 
                       response_data: Dict[str, Any]):
        """处理流量，检测横向移动"""
        try:
            source_ip = request_data.get('client_ip', '')
            target_ip = request_data.get('server_ip', '')
            
            # 检测内网IP
            is_internal = self.ip_detector.is_internal_ip(target_ip)
            
            if is_internal:
                # 通知内网IP请求
                for callback in self._internal_ip_callbacks:
                    try:
                        callback(request_data, target_ip)
                    except Exception as e:
                        logger.error(f"内网IP通知失败: {e}")
            
            # 检测横向移动流量
            lm_detection = self.lm_detector.detect_lateral_movement(request_data, response_data)
            
            if lm_detection:
                # 通知横向移动事件
                event = LateralMovementEvent(
                    id=str(uuid.uuid4())[:12],
                    timestamp=datetime.utcnow(),
                    source_ip=source_ip,
                    target_ip=target_ip,
                    protocol=lm_detection['protocol'],
                    username=self._extract_username(request_data),
                    success=response_data.get('status_code', 0) == 200,
                    technique=lm_detection['technique'],
                    details=lm_detection,
                )
                
                for callback in self._lateral_movement_callbacks:
                    try:
                        callback(event)
                    except Exception as e:
                        logger.error(f"横向移动通知失败: {e}")
                
                # 更新网络拓扑
                self.topology_manager.update_topology(
                    source_ip, target_ip, lm_detection['protocol'].value
                )
            
            # 提取凭据
            credentials = self.credential_extractor.extract_credentials(request_data, response_data)
            
            if credentials:
                for callback in self._credential_callbacks:
                    try:
                        callback(credentials)
                    except Exception as e:
                        logger.error(f"凭据通知失败: {e}")
                
                # 更新网络拓扑（如果有资产信息）
                if credentials:
                    self.topology_manager.update_topology(
                        source_ip, target_ip, 'credential_capture',
                        {'open_ports': [request_data.get('port', 0)]}
                    )
            
        except Exception as e:
            logger.error(f"横向移动联动处理失败: {e}")
    
    def on_internal_ip(self, callback: Callable):
        """注册内网IP回调"""
        self._internal_ip_callbacks.append(callback)
    
    def on_lateral_movement(self, callback: Callable):
        """注册横向移动回调"""
        self._lateral_movement_callbacks.append(callback)
    
    def on_credential(self, callback: Callable):
        """注册凭据回调"""
        self._credential_callbacks.append(callback)
    
    def on_topology_update(self, callback: Callable):
        """注册拓扑更新回调"""
        self._topology_callbacks.append(callback)
    
    def _extract_username(self, request_data: Dict) -> str:
        """提取用户名"""
        body = request_data.get('body', '')
        try:
            data = json.loads(body) if body.startswith('{') else {}
            return data.get('username', data.get('user', ''))
        except:
            return ''
    
    def _on_topology_update(self, source: str, target: str, protocol: str):
        """拓扑更新内部回调"""
        for callback in self._topology_callbacks:
            try:
                callback(source, target, protocol)
            except Exception as e:
                logger.error(f"拓扑更新通知失败: {e}")
