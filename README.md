# 昆仑渗透测试平台 (KunLun Penetration Testing Platform)

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.1-blue.svg)
![Python](https://img.shields.io/badge/python-3.10+-green.svg)
![License](https://img.shields.io/badge/license-Commercial-red.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

**一款企业级全功能渗透测试平台 | 295+模块 | AI驱动 | 跨平台**

[功能特性](#-功能特性) • [快速开始](#-快速开始) • [安装说明](#-安装说明) • [模块列表](#-模块列表) • [打包发布](#-打包发布) • [技术支持](#-技术支持)

</div>

---

## 📖 项目简介

昆仑渗透测试平台是一款功能强大的企业级渗透测试工具，集成295+专业安全测试模块，涵盖信息收集、漏洞扫描、漏洞利用、后渗透测试、域控攻击、C2框架等完整攻击链。平台采用PyQt6构建现代化GUI界面，支持CLI命令行模式，适用于Windows、Linux、macOS全平台。

### 🎯 核心优势

- **全功能覆盖**: 从信息收集到后渗透，覆盖完整渗透测试流程
- **AI驱动**: 集成AI引擎，智能分析、自动编排、辅助决策
- **模块化架构**: 295+独立模块，可按需加载，灵活扩展
- **跨平台支持**: Windows 10/11、Ubuntu 20.04+、macOS 11+
- **企业级**: 支持团队协作、知识图谱、ATT&CK映射、自动化报告

---

## ✨ 功能特性

### 🔍 信息收集与侦察
- 端口扫描与服务识别
- 子域名枚举与DNS侦察
- Web指纹识别与技术栈分析
- 空间搜索引擎集成
- 资产管理与分类

### 🛡️ 漏洞扫描与检测
- Nuclei模板引擎（HTTP/DNS/TCP多协议）
- 被动扫描引擎（MITM代理集成）
- GraphQL安全测试
- gRPC/Protobuf安全测试
- JWT/OAuth/OIDC漏洞检测
- 反序列化漏洞检测（Java/PHP/Python）

### 💥 漏洞利用
- WebLogic漏洞利用
- Shiro反序列化利用
- 反连平台（DNS/HTTP/LDAP/RMI）
- Shellcode生成与Payload管理
- 内存Shell生成器

### 🌐 MITM代理
- HTTP/HTTPS中间人代理
- HTTP/2协议支持
- HTTP/3 QUIC协议支持
- WebSocket拦截与修改
- 流量重放与模糊测试
- 自动证书签发

### 🏢 域控攻击
- DCSync/DCShadow攻击
- Shadow Credentials
- Skeleton Key
- AdminSDHolder滥用
- GPO后门
- DSRM后门
- 跨域信任利用
- ADCS权限提升

### 📡 C2框架
- Beacon生命周期管理
- 多通道通信（HTTP/DNS/TCP/UDP）
- Domain Fronting
- Malleable Profile配置
- DGA域名生成
- 内存加密与休眠
- P2P网状网络
- 后量子加密

### 🔐 权限提升
- Windows/Linux权限提升
- 云环境权限提升
- AI辅助提权决策树
- 强化学习代理
- 知识图谱分析

### 🤖 AI安全
- AI模型安全测试
- 提示词注入检测
- AI辅助渗透测试
- 智能报告生成
- 联邦学习支持

### 📊 报告与分析
- 自动化报告生成
- ATT&CK框架映射
- 知识图谱可视化
- 团队协作与项目管理
- 漏洞生命周期管理

---

## 🚀 快速开始

### 环境要求

- **Python**: 3.10+
- **操作系统**: Windows 10/11、Ubuntu 20.04+、macOS 11+
- **内存**: 8GB+（推荐16GB）
- **磁盘**: 5GB+可用空间

### 安装步骤

#### 1. 克隆仓库

```bash
git clone https://github.com/your-org/kunlun.git
cd kunlun
```

#### 2. 安装依赖

```bash
pip install -r requirements.txt
```

#### 3. 运行程序

**GUI模式**（推荐）:
```bash
python main.py
```

**CLI模式**:
```bash
python main.py --cli
```

---

## 📦 打包发布

### 本地打包

#### Windows

```bash
# 1. 安装打包工具
pip install pyinstaller pyarmor

# 2. PyArmor加密（可选）
python pyarmor_obfuscate.py --advanced --output dist_encrypted

# 3. PyInstaller打包
pyinstaller --clean kunlun.spec

# 4. 验证打包
python test_packaged.py --verbose
```

打包产物位于: `dist/KunLun_PenTest/`

#### Linux/macOS

```bash
# 安装系统依赖（Ubuntu）
sudo apt-get install -y build-essential libssl-dev libffi-dev python3-dev

# 打包
pip install pyinstaller pyarmor
pyinstaller --clean kunlun.spec
```

### GitHub Actions自动构建

推送版本标签触发自动构建：

```bash
git tag v1.0.1
git push origin v1.0.1
```

构建产物将自动发布到GitHub Release页面。

### 发布产物

| 平台 | 文件格式 | 说明 |
|------|----------|------|
| Windows x64 | `.zip` | 单文件EXE，UAC提权 |
| Linux x64 | `.tar.gz` | 二进制文件，需chmod +x |
| macOS x64 | `.dmg` | .app应用包 |

---

## 📚 模块列表

### 核心模块 (CORE)
- Nuclei模板引擎
- 指纹识别
- 被动扫描器
- 攻击编排器
- MITM代理
- 爬虫引擎
- 端口扫描器
- 空间搜索引擎
- Intruder
- Repeater
- Web Fuzzer
- 反向Shell
- PoC验证
- Sequencer
- Decoder
- Comparer
- 编解码器
- 目标管理
- 资产管理
- 漏洞管理

### 网络模块 (NETWORK)
- HTTP/3代理
- QUIC协议栈
- TLS指纹
- MITM高级功能
- MITM诊断
- MITM性能优化
- MITM安全审计

### 攻击模块 (ATTACK)
- 反序列化攻击
- GraphQL攻击
- JWT/OAuth攻击
- 域控攻击
- WebLogic利用
- Shiro利用
- 内存Shell
- 会话/MFA绕过
- Shadow Credentials
- Skeleton Key
- RASP/WAF绕过

### C2模块
- Beacon生命周期
- 通道管理
- Domain Fronting
- Malleable Profile
- DGA生成器
- 内存加密
- P2P网状网络
- 后量子加密
- 自毁机制
- 群体智能

### AI模块
- AI安全引擎
- AI对话
- AI学习
- AI报告
- AI渗透测试
- 联邦学习
- 知识图谱

### 报告模块 (REPORT)
- 报告生成器
- ATT&CK集成
- 知识图谱可视化
- 导出管理

---

## 🛠️ 配置文件

### 目录结构

```
kunlun/
├── config/              # 配置文件
│   ├── app.yaml        # 应用配置
│   ├── api_keys.json   # API密钥（需自行配置）
│   └── secrets.enc     # 加密密钥
├── rules/              # Nuclei模板
├── profiles/           # Profile模板
├── templates/          # 报告模板
├── plugins/            # 插件目录
└── certs/              # 证书目录（自动生成）
```

### 首次运行

首次运行时会自动：
1. 生成MITM CA证书
2. 创建用户数据目录
3. 初始化数据库
4. 加载默认配置

---

## 📖 使用文档

### 基础使用

1. **启动程序**: 双击EXE或运行`python main.py`
2. **创建项目**: 文件 > 新建项目
3. **添加目标**: 目标 > 添加目标
4. **开始扫描**: 选择模块 > 点击开始
5. **查看结果**: 结果面板查看漏洞详情
6. **生成报告**: 报告 > 生成报告

### 高级功能

- **MITM代理**: 配置浏览器代理为127.0.0.1:8080
- **C2框架**: 生成Payload > 部署监听器 > 等待上线
- **域控攻击**: 需要域管理员权限
- **AI辅助**: 配置API密钥后启用

---

## ⚠️ 免责声明

本工具仅供安全研究和授权测试使用。使用者必须：

1. 仅在授权范围内使用本工具
2. 获得目标系统所有者的书面许可
3. 遵守当地法律法规
4. 对测试结果保密

**开发者不对任何滥用行为负责。**

---

## 📄 许可证

本项目为商业闭源软件，未经授权不得复制、修改、分发。

---

## 🤝 技术支持

- **文档**: [在线文档](https://docs.kunlun-pentest.com)
- **Issue**: [GitHub Issues](https://github.com/your-org/kunlun/issues)
- **邮件**: support@kunlun-pentest.com
- **社区**: [Discord](https://discord.gg/kunlun)

---

## 🙏 致谢

感谢以下开源项目的贡献：

- [PyQt6](https://www.riverbankcomputing.com/software/pyqt/)
- [PyInstaller](https://www.pyinstaller.org/)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [aioquic](https://github.com/aiortc/aioquic)
- [scapy](https://scapy.net/)
- [ cryptography](https://cryptography.io/)

---

<div align="center">

**昆仑渗透测试平台** • 让安全测试更智能、更高效

Made with ❤️ by KunLun Security Team

</div>
