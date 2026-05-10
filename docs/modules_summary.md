# 昆仑安全测试工具 - 模块总结

## 已完成模块

### 1. 代理模块 (core/proxy/)
- **ProfessionalProxyServer**: 专业级HTTP/HTTPS代理服务器
  - 支持请求拦截和修改
  - 支持SSL证书自动生成
  - 支持WebSocket协议处理
  - 支持历史记录保存

- **WebSocketHandler**: WebSocket流量处理器
  - 支持WebSocket帧拦截和修改
  - 支持WebSocket流量重放
  - 支持连接状态监控

### 2. 请求重放模块 (core/repeater/)
- **RequestRepeater**: 专业级HTTP请求重放工具
  - 支持单个/批量请求重放
  - 支持并发请求
  - 支持参数Fuzzing（SQLi、XSS、LFI等）
  - 支持请求收藏和标签
  - 支持导入/导出请求
  - 支持响应对比

### 3. Webshell模块 (core/webshell/)
- **PHPConnector**: PHP Webshell连接器
  - 支持命令执行
  - 支持文件操作（读/写/删除/上传/下载）
  - 支持数据库操作
  - 支持反弹Shell
  - 支持多种编码方式（Base64、Hex、ROT13）

- **JSPConnector**: JSP Webshell连接器
  - 支持命令执行
  - 支持文件操作
  - 支持Java代码执行

- **ASPConnector**: ASP Webshell连接器
  - 支持命令执行
  - 支持文件操作
  - 支持VBScript执行

- **WebshellManager**: Webshell管理器
  - 支持Webshell添加/编辑/删除
  - 支持批量测试连接
  - 支持标签分类
  - 支持搜索和筛选
  - 支持导入/导出
  - 支持统计信息

- **WebshellGenerator**: Webshell代码生成器
  - 内置多种PHP/JSP/ASP模板
  - 支持基础/免杀/大马等类型
  - 支持代码混淆
  - 支持自定义密码
  - 支持自定义模板

### 4. 网络空间搜索模块 (core/search/)
- **NetworkSearch**: 网络空间搜索引擎
  - 支持FOFA搜索
  - 支持ZoomEye搜索
  - 支持Shodan搜索
  - 支持Censys搜索
  - 支持Hunter搜索
  - 支持多引擎并发搜索
  - 支持结果筛选和过滤
  - 支持导出为JSON/CSV/TXT
  - 支持统计信息

## 待完善模块

### 1. 暴力破解模块 (core/intruder/)
- 支持HTTP表单爆破
- 支持HTTP认证爆破
- 支持SSH/FTP/SMB等协议爆破
- 支持自定义字典
- 支持多线程/协程
- 支持代理

### 2. 编码解码模块 (core/encoder/)
- 支持Base64编码/解码
- 支持URL编码/解码
- 支持Hex编码/解码
- 支持Unicode编码/解码
- 支持MD5/SHA1/SHA256哈希
- 支持AES/DES加解密
- 支持各种Web安全编码

### 3. 综合测试脚本模块
- 集成所有模块的自动化测试
- 支持自定义测试流程
- 支持报告生成

## 使用说明

### 代理模块使用
```python
from core.proxy import ProfessionalProxyServer

proxy = ProfessionalProxyServer()
await proxy.start_proxy(port=8080)
```

### 请求重放使用
```python
from core.repeater import RequestRepeater

repeater = RequestRepeater()
req_id = repeater.add_request('GET', 'http://example.com')
await repeater.replay_request(req_id)
```

### Webshell管理使用
```python
from core.webshell import WebshellManager

manager = WebshellManager()
ws_id = manager.add_webshell('http://example.com/shell.php', 'php', 'password')
await manager.test_webshell(ws_id)
```

### 网络空间搜索使用
```python
from core.search import NetworkSearch

search = NetworkSearch()
search.set_api_key('fofa', 'your_email', 'your_key')
results = await search.search('title="后台登录"', engines=['fofa'])
```
