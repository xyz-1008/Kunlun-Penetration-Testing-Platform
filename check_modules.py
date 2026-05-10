import re
import os
from pathlib import Path

# 读取 main.py 中已注册的模块
main_py = Path(r"d:\ai项目\测试项目\开发\渗透测试工具1.0.1\AutoPenTest_Desktop\main.py")
content = main_py.read_text(encoding='utf-8')
registered = set(re.findall(r'"([a-z_0-9]+)":\s*ModuleMeta\(', content))

# 扫描 core/modules 目录中的所有 .py 文件
modules_dir = Path(r"d:\ai项目\测试项目\开发\渗透测试工具1.0.1\AutoPenTest_Desktop\core\modules")
all_modules = set()

for py_file in modules_dir.glob("*.py"):
    module_name = py_file.stem
    if module_name in ('__init__', 'base', 'event_bus'):
        continue
    all_modules.add(module_name)

# 找出未注册的模块
unregistered = all_modules - registered

print(f"已注册模块数量: {len(registered)}")
print(f"未注册模块数量: {len(unregistered)}")
print(f"\n未注册的模块列表:")
for mod in sorted(unregistered):
    print(f"  - {mod}")
