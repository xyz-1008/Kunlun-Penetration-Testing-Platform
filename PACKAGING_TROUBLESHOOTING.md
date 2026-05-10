# 昆仑渗透测试平台 - 打包故障排查指南

## 目录

1. [常见打包问题](#常见打包问题)
2. [PyInstaller相关问题](#pyinstaller相关问题)
3. [PyArmor相关问题](#pyarmor相关问题)
4. [平台特定问题](#平台特定问题)
5. [运行时问题](#运行时问题)
6. [性能优化](#性能优化)
7. [调试技巧](#调试技巧)

---

## 常见打包问题

### 1. 模块导入失败 (ModuleNotFoundError)

**症状**：
```
ModuleNotFoundError: No module named 'xxx'
```

**原因**：
- PyInstaller未检测到动态导入的模块
- 隐式导入未在spec文件中声明

**解决方案**：

1. 在`kunlun.spec`的`hiddenimports`中添加缺失模块：
```python
hiddenimports=[
    # ... 现有模块 ...
    'missing_module',
    'missing_module.submodule',
]
```

2. 使用`--hidden-import`命令行参数：
```bash
pyinstaller --hidden-import=missing_module main.py
```

3. 检查是否使用了以下动态导入模式：
```python
# 这些模式PyInstaller无法自动检测
import importlib
module = importlib.import_module('dynamic_module')

# 条件导入
if condition:
    import optional_module
```

### 2. 数据文件缺失

**症状**：
```
FileNotFoundError: [Errno 2] No such file or directory: 'rules/template.yaml'
```

**原因**：
- 数据文件未包含在打包中
- 路径使用`__file__`在打包后失效

**解决方案**：

1. 在`kunlun.spec`的`datas`中添加数据文件：
```python
datas=[
    ('rules/', 'rules'),
    ('templates/', 'templates'),
    ('certs/', 'certs'),
]
```

2. 使用`path_utils.py`统一处理路径：
```python
from utils.path_utils import PathUtils

# 正确方式
rules_dir = PathUtils.get_rules_path()

# 错误方式（打包后失效）
rules_dir = Path(__file__).parent / 'rules'
```

3. 验证数据文件是否包含：
```bash
# 查看打包内容
pyi-archive_viewer dist/KunLun_PenTest/KunLun_PenTest.exe
```

### 3. 打包体积过大

**症状**：
- 生成的EXE文件超过500MB
- 启动速度缓慢

**解决方案**：

1. 排除未使用的模块：
```python
excludes=[
    'tkinter',
    'matplotlib',
    'scipy.tests',
    'sklearn.tests',
    'pandas.tests',
]
```

2. 使用UPX压缩：
```bash
# 下载UPX: https://github.com/upx/upx/releases
pyinstaller --upx-dir=/path/to/upx kunlun.spec
```

3. 优化科学计算库：
```python
# 排除sklearn测试和示例
excludes=[
    'sklearn.tests',
    'sklearn.datasets.tests',
    'sklearn.utils.tests',
]
```

4. 使用`--onefile` vs `--onedir`权衡：
   - `--onefile`: 单文件，体积小，启动慢（需解压）
   - `--onedir`: 目录，体积大，启动快

### 4. C扩展库打包失败

**症状**：
```
ImportError: DLL load failed: 找不到指定的模块
```

**原因**：
- C扩展的`.pyd`/`.so`/`.dylib`文件未正确包含
- 依赖的系统库缺失

**解决方案**：

1. 在`binaries`中显式添加：
```python
binaries=[
    ('path/to/library.pyd', '.'),
    ('path/to/libcrypto.dll', '.'),
]
```

2. 检查依赖库：
```bash
# Windows: 使用Dependencies工具
# Linux: ldd命令
lddist/KunLun_PenTest/libpython3.10.so.1.0

# macOS: otool命令
otool -L dist/KunLun_PenTest/libpython3.10.dylib
```

3. 安装Visual C++ Redistributable (Windows)：
   - 下载: https://aka.ms/vs/17/release/vc_redist.x64.exe

---

## PyInstaller相关问题

### 5. PyQt6打包问题

**症状**：
- GUI无法启动
- 缺少Qt平台插件

**解决方案**：

1. 确保Qt平台插件包含：
```python
datas=[
    # PyQt6平台插件
    ('path/to/PyQt6/Qt6/plugins/platforms/*', 'PyQt6/Qt6/plugins/platforms'),
]
```

2. 设置Qt插件路径：
```python
import os
import sys

if getattr(sys, 'frozen', False):
    # 打包后环境
    os.environ['QT_QPA_PLATFORM_PLUGIN_PATH'] = os.path.join(
        sys._MEIPASS, 'PyQt6', 'Qt6', 'plugins', 'platforms'
    )
```

3. 测试Qt插件：
```python
from PyQt6.QtWidgets import QApplication
import sys

app = QApplication(sys.argv)
print("Qt平台:", app.platformName())
```

### 6. asyncio事件循环问题

**症状**：
```
RuntimeError: This event loop is already running
```

**解决方案**：

1. 使用`asyncio.run()`而非`loop.run_until_complete()`：
```python
# 正确方式
async def main():
    await some_async_function()

asyncio.run(main())

# 错误方式
loop = asyncio.get_event_loop()
loop.run_until_complete(some_async_function())
```

2. 打包后使用`nest_asyncio`（如需要）：
```python
import nest_asyncio
nest_asyncio.apply()
```

### 7. multiprocessing问题

**症状**：
```
RuntimeError: An attempt has been made to start a new process before the
current process has finished its bootstrapping phase.
```

**解决方案**：

1. 在`main.py`开头添加：
```python
if __name__ == '__main__':
    import multiprocessing
    multiprocessing.freeze_support()
    main()
```

2. 使用`if __name__ == '__main__':`保护所有顶层代码

---

## PyArmor相关问题

### 8. PyArmor加密后导入失败

**症状**：
```
ImportError: cannot import name 'xxx' from 'yyy'
```

**解决方案**：

1. 检查加密配置：
```bash
# 使用--recursive递归加密所有模块
pyarmor gen --recursive --output dist_encrypted main.py
```

2. 排除不需要加密的文件：
```bash
pyarmor gen --exclude "tests/*" --exclude "config/*" main.py
```

3. 验证加密结果：
```bash
# 检查加密后的文件
ls dist_encrypted/
python -c "import sys; sys.path.insert(0, 'dist_encrypted'); import main"
```

### 9. PyArmor许可证问题

**症状**：
```
PyArmorError: License expired or invalid
```

**解决方案**：

1. 检查许可证状态：
```bash
pyarmor --version
pyarmor license
```

2. 更新许可证：
```bash
pyarmor register --license-file license.lic
```

3. 设置许可证过期时间：
```bash
pyarmor gen --expire 2025-12-31 main.py
```

---

## 平台特定问题

### 10. Windows UAC提权问题

**症状**：
- MITM代理无法启动（需要管理员权限）
- 端口绑定失败（Access denied）

**解决方案**：

1. 在spec文件中启用UAC：
```python
exe = EXE(
    ...
    uac_admin=True,
    uac_uiaccess=False,
)
```

2. 创建manifest文件（可选）：
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
```

3. 在代码中检测权限：
```python
from utils.path_utils import PathUtils

if not PathUtils.is_admin():
    print("需要管理员权限，请右键以管理员身份运行")
    sys.exit(1)
```

### 11. Windows杀软误报

**症状**：
- EXE文件被Defender/360/火绒误报为病毒
- 用户无法下载或运行

**解决方案**：

1. 代码签名（最有效）：
   - 购买代码签名证书
   - 使用`signtool`签名：
   ```bash
   signtool sign /f certificate.pfx /p password /t http://timestamp.digicert.com KunLun_PenTest.exe
   ```

2. 提交白名单：
   - Microsoft Defender: https://www.microsoft.com/en-us/wdsi/support/report-false-positive-malware
   - 360: https://bbs.360.cn/
   - 火绒: https://bbs.huorong.cn/

3. 使用PyInstaller选项减少误报：
```bash
# 不使用UPX（可能被误报）
pyinstaller --noupx kunlun.spec

# 使用不同的bootloader
pyinstaller --bootloader-ignore-signals kunlun.spec
```

### 12. Linux依赖缺失

**症状**：
```
libxcb-xinerama.so.0: cannot open shared object file
```

**解决方案**：

1. 安装系统依赖：
```bash
# Ubuntu/Debian
sudo apt-get install -y \
    libxcb-xinerama0 \
    libxcb-cursor0 \
    libxcb1 \
    libx11-xcb1 \
    libgl1-mesa-glx \
    libglib2.0-0

# CentOS/RHEL
sudo yum install -y \
    libxcb \
    libX11 \
    mesa-libGL \
    glib2
```

2. 使用AppImage提高兼容性：
```bash
# 安装linuxdeploy
wget https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage
chmod +x linuxdeploy-x86_64.AppImage

# 创建AppImage
./linuxdeploy-x86_64.AppImage --appdir AppDir --executable KunLun_PenTest --output appimage
```

3. 提供安装脚本：
```bash
#!/bin/bash
# install.sh
echo "检查系统依赖..."
if ! dpkg -l | grep -q libxcb-xinerama0; then
    echo "安装缺失的依赖..."
    sudo apt-get install -y libxcb-xinerama0
fi

echo "解压程序..."
tar -xzf KunLun_PenTest-Linux-x64-*.tar.gz

echo "添加执行权限..."
chmod +x KunLun_PenTest

echo "安装完成！运行: ./KunLun_PenTest"
```

### 13. macOS Gatekeeper拦截

**症状**：
```
"KunLun_PenTest.app" cannot be opened because the developer cannot be verified.
```

**解决方案**：

1. 代码签名：
```bash
# 需要Apple Developer证书
codesign --force --deep --sign "Developer ID Application: Your Name (TEAM_ID)" \
    KunLun_PenTest.app
```

2. 公证（Notarization）：
```bash
# 创建app-specific password: https://appleid.apple.com/
xcrun notarytool submit KunLun_PenTest.dmg \
    --apple-id "your@apple.id" \
    --password "app-specific-password" \
    --team-id "TEAM_ID" \
    --wait

# 装订公证票
xcrun stapler staple KunLun_PenTest.dmg
```

3. 临时解决方案（用户侧）：
   - 系统偏好设置 > 安全性与隐私 > 仍要打开
   - 或使用`xattr -d com.apple.quarantine KunLun_PenTest.app`

---

## 运行时问题

### 14. 证书生成失败

**症状**：
```
PermissionError: [Errno 13] Permission denied: 'certs/ca.key'
```

**解决方案**：

1. 使用用户数据目录：
```python
from utils.path_utils import PathUtils

# 正确：使用用户数据目录
cert_dir = PathUtils.get_certs_path()

# 错误：使用程序目录（可能需要管理员权限）
cert_dir = PathUtils.get_runtime_path('certs')
```

2. 检查目录权限：
```python
import os
import stat

cert_dir = PathUtils.get_certs_path()
cert_dir.mkdir(parents=True, exist_ok=True)

# 确保目录可写
os.chmod(cert_dir, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
```

### 15. 插件加载失败

**症状**：
```
Plugin load failed: No module named 'plugins.custom_plugin'
```

**解决方案**：

1. 确保插件目录在sys.path中：
```python
import sys
from utils.path_utils import PathUtils

plugin_dir = PathUtils.get_plugins_path()
if str(plugin_dir) not in sys.path:
    sys.path.insert(0, str(plugin_dir))
```

2. 使用importlib正确加载：
```python
import importlib.util
from pathlib import Path

def load_plugin(plugin_path: Path):
    spec = importlib.util.spec_from_file_location(
        plugin_path.stem,
        plugin_path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
```

3. 检查插件依赖：
```python
# 在插件中声明依赖
__plugin_info__ = {
    "name": "custom_plugin",
    "version": "1.0.0",
    "dependencies": ["requests", "beautifulsoup4"],
}
```

### 16. 数据库文件锁定

**症状**：
```
sqlite3.OperationalError: database is locked
```

**解决方案**：

1. 使用WAL模式：
```python
import sqlite3

conn = sqlite3.connect(database_path)
conn.execute("PRAGMA journal_mode=WAL")
conn.execute("PRAGMA busy_timeout=5000")
```

2. 避免并发写入：
```python
import threading

db_lock = threading.Lock()

def safe_db_operation():
    with db_lock:
        # 数据库操作
        pass
```

---

## 性能优化

### 17. 启动速度优化

**问题**：打包后启动缓慢（>10秒）

**解决方案**：

1. 使用`--onedir`模式替代`--onefile`：
   - `--onefile`: 每次启动需解压到临时目录
   - `--onedir`: 直接运行，启动更快

2. 延迟导入：
```python
# 不要在最顶层导入
# from heavy_module import HeavyClass  # 启动时加载

def use_heavy_module():
    from heavy_module import HeavyClass  # 使用时加载
    return HeavyClass()
```

3. 优化spec文件：
```python
# 排除不必要的模块
excludes=[
    'matplotlib',
    'scipy',
    'pandas.tests',
]
```

### 18. 内存占用优化

**问题**：运行时内存占用过高（>2GB）

**解决方案**：

1. 使用生成器替代列表：
```python
# 错误：加载全部数据到内存
results = [process(item) for item in large_dataset]

# 正确：使用生成器
results = (process(item) for item in large_dataset)
```

2. 及时释放资源：
```python
import gc

def process_large_data():
    try:
        # 处理数据
        pass
    finally:
        # 清理
        gc.collect()
```

3. 监控内存使用：
```python
import psutil
import os

def get_memory_usage():
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / 1024 / 1024  # MB

print(f"内存使用: {get_memory_usage():.2f} MB")
```

---

## 调试技巧

### 19. 启用PyInstaller调试模式

```bash
# 控制台模式（查看输出）
pyinstaller --console kunlun.spec

# 启用调试信息
pyinstaller --debug all kunlun.spec
```

### 20. 查看打包内容

```bash
# 查看归档内容
pyi-archive_viewer dist/KunLun_PenTest/KunLun_PenTest.exe

# 提取文件
pyi-archive_viewer -x module_name dist/KunLun_PenTest/KunLun_PenTest.exe
```

### 21. 运行时路径调试

在`main.py`开头添加：
```python
from utils.path_utils import PathUtils

PathUtils.print_debug_info()
```

### 22. 日志记录

```python
import logging
from utils.path_utils import PathUtils

# 配置日志
log_dir = PathUtils.get_logs_path()
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=log_dir / 'kunlun.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# 记录启动信息
logging.info("昆仑渗透测试平台启动")
logging.info(f"平台: {PathUtils.get_platform()}")
logging.info(f"打包环境: {PathUtils.is_frozen()}")
```

### 23. 使用测试脚本验证

```bash
# 运行打包验证测试
python test_packaged.py --verbose --output report.json

# 查看测试报告
cat report.json
```

---

## 快速参考

### 常用命令

```bash
# 安装依赖
pip install pyinstaller pyarmor

# PyArmor加密
python pyarmor_obfuscate.py --advanced --output dist_encrypted

# PyInstaller打包
pyinstaller --clean kunlun.spec

# 运行测试
python test_packaged.py --verbose

# 查看打包内容
pyi-archive_viewer dist/KunLun_PenTest/KunLun_PenTest.exe
```

### 文件清单

| 文件 | 用途 |
|------|------|
| `kunlun.spec` | PyInstaller打包配置 |
| `pyarmor_obfuscate.py` | PyArmor加密脚本 |
| `utils/path_utils.py` | 运行时路径处理 |
| `test_packaged.py` | 打包验证测试 |
| `.github/workflows/release.yml` | GitHub Actions工作流 |

### 环境变量

| 变量 | 用途 |
|------|------|
| `PYINSTALLER_DEBUG` | 启用PyInstaller调试 |
| `QT_QPA_PLATFORM_PLUGIN_PATH` | Qt插件路径 |
| `PYTHONPATH` | Python模块搜索路径 |

---

## 获取帮助

如果以上方法无法解决问题：

1. 查看日志文件：`~/.local/share/KunLun_PenTest/logs/kunlun.log`
2. 运行测试脚本：`python test_packaged.py --verbose`
3. 提交Issue：https://github.com/your-org/kunlun-pentest/issues
4. 联系支持：support@kunlun-pentest.com
