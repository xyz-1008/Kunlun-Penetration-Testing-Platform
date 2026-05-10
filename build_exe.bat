@echo off
REM 昆仑安全测试平台 Pro - 打包脚本
REM 使用方法: build_exe.bat

echo ========================================
echo 昆仑安全测试平台 Pro - 打包为EXE
echo ========================================
echo.

REM 检查Python环境
python --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未找到Python，请先安装Python 3.8+
    pause
    exit /b 1
)

echo [1/4] 检查依赖...
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo [提示] 正在安装PyInstaller...
    pip install pyinstaller
)

echo [2/4] 安装项目依赖...
pip install -r requirements.txt

echo [3/4] 开始打包...
pyinstaller --clean platform.spec

echo [4/4] 打包完成！
echo.
echo 输出文件: dist\KunlunPenTestPlatform.exe
echo.
echo 注意：
echo 1. 配置文件、数据目录需手动复制到exe同级目录
echo 2. 首次运行会自动创建必要的目录结构
echo.
pause
