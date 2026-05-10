<<<<<<< HEAD
# 昆仑渗透测试平台 (KunLun Penetration Testing Platform)

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.1-blue.svg)
![Python](https://img.shields.io/badge/python-3.10+-green.svg)
![License](https://img.shields.io/badge/license-Commercial-red.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

**一款企业级全功能渗透测试平台 | 295+模块 | AI驱动 | 跨平台**

[功能特性](#-功能特性) • [快速开始](#-快速开始) • [安装说明](#-安装说明) • [模块列表](#-模块列表) • [打包发布](#-打包发布) • [技术支持](#-技术支持)
=======
# 昆仑安全测试平台 Pro v1.0

<div align="center">

**自动化渗透测试桌面应用**

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/xyz-1008/Kunlun-Penetration-Testing-Platform/releases)
[![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
>>>>>>> 1e3868f81504fbff990a75cd3c46bc563f1b315d

</div>

---

<<<<<<< HEAD
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
=======
## 简介

昆仑安全测试平台是一款专业的自动化渗透测试桌面应用，参考 Burp Suite 的设计理念，为安全研究人员提供全面的安全测试工具集。

## 功能特性

### 核心模块

| 模块 | 功能描述 |
|------|----------|
| **Dashboard** | 任务概览、快速操作、事件日志 |
| **Target** | 目标管理、站点配置、范围定义 |
| **Proxy** | HTTP/HTTPS 代理拦截、请求修改 |
| **Intruder** | 暴力破解、字典攻击、自定义Payload |
| **Repeater** | 请求重放、参数修改、响应分析 |
| **Sequencer** | 会话令牌分析、随机性检测 |
| **Decoder** | 编解码工具、哈希计算 |
| **Comparer** | 数据对比、差异分析 |

### 扩展模块

| 模块 | 功能描述 |
|------|----------|
| **MITM代理** | 中间人攻击、流量劫持 |
| **网络爬虫** | 自动爬取、站点地图生成 |
| **漏洞扫描** | PoC验证、自动化检测 |
| **WebFuzzer** | Web模糊测试 |
| **YakRunner** | 脚本执行引擎 |
| **端口扫描** | 端口探测、服务识别 |
| **PoC管理** | 漏洞验证脚本管理 |
| **反向Shell** | 反弹Shell管理 |
| **空间搜索** | 网络空间资产搜索 |
| **插件商店** | 插件市场、扩展管理 |
| **知识库** | 安全知识库、漏洞库 |
| **AI安全检测** | AI辅助安全分析 |
| **攻击编排** | 自动化攻击链编排 |
| **指纹识别** | 技术栈识别、框架检测 |
| **资产管理** | 资产发现、管理 |
| **漏洞管理** | 漏洞跟踪、状态管理 |

## 快速开始

### 系统要求

- **操作系统**: Windows 10/11 (64位)
- **内存**: 至少 4GB RAM
- **磁盘空间**: 至少 500MB 可用空间
- **网络**: 需要网络连接进行在线功能

### 安装步骤

1. 从 [Releases](https://github.com/xyz-1008/Kunlun-Penetration-Testing-Platform/releases) 下载最新版本的 `AutoPenTest.exe`
2. 双击运行即可，无需安装

### 首次使用

1. 双击 `AutoPenTest.exe` 启动应用
2. 在 Dashboard 中查看快速操作
3. 在 Target 中添加测试目标
4. 使用 Proxy 拦截和修改请求
5. 使用其他模块进行安全测试

## 界面预览

应用采用 Burp Suite 风格的深色主题设计，包含：

- **顶部菜单栏**: 文件、视图、工具、帮助
- **模块标签栏**: 快速切换不同功能模块
- **状态栏**: 显示内存、磁盘使用情况和就绪状态

## 项目结构

```
Kunlun-Penetration-Testing-Platform/
├── AutoPenTest.exe          # 主程序（Windows可执行文件）
├── README.md                # 项目说明文档
├── USER_GUIDE.md            # 用户使用指南
├── CHANGELOG.md             # 更新日志
└── LICENSE                  # MIT 许可证
```

## 安全声明

本工具仅供安全研究和授权测试使用。使用者应：

- 仅在获得授权的情况下测试目标系统
- 遵守当地法律法规
- 对未经授权的测试行为承担全部责任

## 许可证

本项目采用 [MIT License](LICENSE) 开源协议。

## 联系方式

**微信联系方式ID：XY5431008**

**微信公众号：昆仑AI安全实验室**

- **项目地址**: [GitHub](https://github.com/xyz-1008/Kunlun-Penetration-Testing-Platform)
- **问题反馈**: [Issues](https://github.com/xyz-1008/Kunlun-Penetration-Testing-Platform/issues)
>>>>>>> 1e3868f81504fbff990a75cd3c46bc563f1b315d

---

<div align="center">
<<<<<<< HEAD
**昆仑渗透测试平台** • 让安全测试更智能、更高效

Made with ❤️ by KunLun Security Team
=======
**昆仑安全测试平台** - 专业、高效、易用的安全测试工具
>>>>>>> 1e3868f81504fbff990a75cd3c46bc563f1b315d

</div>
