"""
昆仑安全测试平台 Pro - 核心入口文件
=====================================
所有功能模块的统一入口，支持 GUI 和 CLI 双模式启动。

架构设计:
    main.py (本文件)
    ├── KunLunApplication (应用主控)
    │   ├── Application 单例 (core.application)
    │   │   ├── EventBus (事件总线)
    │   │   ├── DataBus (数据总线)
    │   │   └── ModuleRegistry (模块注册中心)
    │   ├── GUI 模块 (PySide6)
    │   │   ├── Dashboard / Target / Proxy / Intruder / Repeater
    │   │   ├── Sequencer / Decoder / Comparer / MITM代理
    │   │   ├── 网络爬虫 / 漏洞扫描 / WebFuzzer / YakRunner
    │   │   ├── 端口扫描 / PoC管理 / 反向Shell / 编解码
    │   │   ├── 空间搜索 / 插件商店 / 知识库 / AI安全检测
    │   │   ├── 攻击编排 / 指纹识别 / 资产管理 / 漏洞管理
    │   │   ├── 插件扩展 / 报告
    │   │   └── Nuclei模板引擎 (集成面板)
    │   └── 后端模块
    │       ├── NucleiExecutor (Nuclei模板执行引擎)
    │       ├── FingerprintRecognition (资产指纹识别)
    │       ├── PassiveScanner (被动扫描引擎)
    │       ├── AttackOrchestrationSystem (攻击编排)
    │       └── PluginManager (插件管理器)
    └── CLI 模式 (argparse)
        ├── nuclei update/search/stats/validate/test
        ├── scan (主动扫描)
        └── fingerprint (指纹识别)

新增模块对接方式:
    1. 在 core/modules/ 下创建模块文件
    2. 在 core/modules/__init__.py 中导出
    3. 在 _MODULE_REGISTRY 中注册模块元信息
    4. 模块自动通过事件总线与其他模块通信

启动方式:
    python main.py                    # GUI 模式
    python main.py --cli nuclei stats # CLI 模式
    python main.py --help             # 查看帮助
"""

from __future__ import annotations

import sys
import os
import logging
import argparse
import asyncio
import signal
import threading
import inspect
from pathlib import Path
from typing import Dict, Any, Optional, Callable, List, Type, Union
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

# =============================================================================
# 路径初始化
# =============================================================================
_PROJECT_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(_PROJECT_ROOT))

# =============================================================================
# 日志初始化（最早执行）
# =============================================================================
_LOG_DIR = _PROJECT_ROOT / "logs"
_LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler(_LOG_DIR / "kunlun.log", encoding='utf-8'),
        logging.StreamHandler(sys.stdout),
    ]
)

_logger = logging.getLogger("KunLun.Main")


# =============================================================================
# 模块注册表 - 所有模块的元信息集中管理
# =============================================================================

class ModuleCategory(Enum):
    """模块分类"""
    CORE = "core"               # 核心后端模块
    NETWORK = "network"         # 网络相关
    ATTACK = "attack"           # 攻击相关
    ANALYSIS = "analysis"       # 分析相关
    MANAGEMENT = "management"   # 管理相关
    EXTENSION = "extension"     # 扩展/插件
    REPORT = "report"           # 报告相关
    AI = "ai"                   # AI相关


@dataclass
class ModuleMeta:
    """模块元信息 - 用于自动发现和注册"""
    module_id: str                          # 唯一标识
    category: ModuleCategory                # 分类
    display_name: str                       # 显示名称
    description: str = ""                   # 描述
    import_path: str = ""                   # 导入路径 (core.modules.xxx)
    class_name: str = ""                    # 类名
    dependencies: List[str] = field(default_factory=list)  # 依赖模块ID
    lazy_load: bool = True                  # 是否延迟加载
    gui_tab_label: str = ""                 # GUI标签页名称（空则不显示标签）
    gui_tab_order: int = 999                # GUI标签页排序
    cli_commands: List[str] = field(default_factory=list)  # CLI命令
    enabled: bool = True                    # 是否启用
    backend_only: bool = False              # 是否纯后端模块（无GUI）


# 所有模块的注册表
_MODULE_REGISTRY: Dict[str, ModuleMeta] = {
    # ==================== 核心后端模块 ====================
    "nuclei_executor": ModuleMeta(
        module_id="nuclei_executor",
        category=ModuleCategory.CORE,
        display_name="Nuclei模板引擎",
        description="Nuclei YAML模板适配引擎，支持HTTP/DNS/TCP多协议执行",
        import_path="core.modules.nuclei_executor",
        class_name="NucleiExecutor",
        gui_tab_label="Nuclei引擎",
        gui_tab_order=50,
        cli_commands=["nuclei"],
        backend_only=False,
    ),
    "fingerprint": ModuleMeta(
        module_id="fingerprint",
        category=ModuleCategory.CORE,
        display_name="指纹识别引擎",
        description="资产指纹识别，支持Web/服务/操作系统指纹",
        import_path="core.modules.fingerprint",
        class_name="FingerprintRecognitionModule",
        gui_tab_label="指纹识别",
        gui_tab_order=51,
        cli_commands=["fingerprint"],
    ),
    "passive_scanner": ModuleMeta(
        module_id="passive_scanner",
        category=ModuleCategory.CORE,
        display_name="被动扫描引擎",
        description="被动漏洞扫描，分析流量自动发现漏洞",
        import_path="core.modules.passive_scanner",
        class_name="PassiveScannerIntegration",
        backend_only=True,
    ),
    "attack_orchestrator": ModuleMeta(
        module_id="attack_orchestrator",
        category=ModuleCategory.CORE,
        display_name="攻击编排系统",
        description="自动化攻击路径规划与利用编排",
        import_path="core.modules.attack_orchestrator",
        class_name="AttackOrchestrationSystem",
        gui_tab_label="攻击编排",
        gui_tab_order=52,
    ),

    # ==================== 网络模块 ====================
    "proxy": ModuleMeta(
        module_id="proxy",
        category=ModuleCategory.NETWORK,
        display_name="HTTP代理",
        description="HTTP/HTTPS代理拦截与修改",
        import_path="core.modules.proxy",
        class_name="ProxyModule",
        gui_tab_label="Proxy",
        gui_tab_order=2,
    ),
    "mitm": ModuleMeta(
        module_id="mitm",
        category=ModuleCategory.NETWORK,
        display_name="MITM代理",
        description="中间人代理，支持HTTP/1.1/HTTP2/WebSocket",
        import_path="core.modules.mitm",
        class_name="MITMModule",
        gui_tab_label="MITM代理",
        gui_tab_order=8,
    ),
    "spider": ModuleMeta(
        module_id="spider",
        category=ModuleCategory.NETWORK,
        display_name="网络爬虫",
        description="智能网络爬虫，自动发现站点结构",
        import_path="core.modules.spider",
        class_name="SpiderModule",
        gui_tab_label="网络爬虫",
        gui_tab_order=9,
    ),
    "portscan": ModuleMeta(
        module_id="portscan",
        category=ModuleCategory.NETWORK,
        display_name="端口扫描",
        description="多协议端口扫描与服务识别",
        import_path="core.modules.portscan",
        class_name="PortScanModule",
        gui_tab_label="端口扫描",
        gui_tab_order=13,
    ),
    "space_engine": ModuleMeta(
        module_id="space_engine",
        category=ModuleCategory.NETWORK,
        display_name="空间搜索",
        description="网络空间搜索引擎聚合查询",
        import_path="core.modules.space_engine",
        class_name="SpaceEngineModule",
        gui_tab_label="空间搜索",
        gui_tab_order=17,
    ),

    # ==================== 攻击模块 ====================
    "intruder": ModuleMeta(
        module_id="intruder",
        category=ModuleCategory.ATTACK,
        display_name="Intruder",
        description="自动化攻击载荷注入与模糊测试",
        import_path="core.modules.intruder",
        class_name="IntruderModule",
        gui_tab_label="Intruder",
        gui_tab_order=3,
    ),
    "repeater": ModuleMeta(
        module_id="repeater",
        category=ModuleCategory.ATTACK,
        display_name="Repeater",
        description="HTTP请求重放与手动测试",
        import_path="core.modules.repeater",
        class_name="RepeaterModule",
        gui_tab_label="Repeater",
        gui_tab_order=4,
    ),
    "webfuzzer": ModuleMeta(
        module_id="webfuzzer",
        category=ModuleCategory.ATTACK,
        display_name="WebFuzzer",
        description="Web应用模糊测试工具",
        import_path="core.modules.webfuzzer",
        class_name="WebFuzzerModule",
        gui_tab_label="WebFuzzer",
        gui_tab_order=11,
    ),
    "reverseshell": ModuleMeta(
        module_id="reverseshell",
        category=ModuleCategory.ATTACK,
        display_name="反向Shell",
        description="多协议反向Shell生成与管理",
        import_path="core.modules.reverseshell",
        class_name="ReverseShellHandler",
        gui_tab_label="反向Shell",
        gui_tab_order=15,
    ),
    "poc": ModuleMeta(
        module_id="poc",
        category=ModuleCategory.ATTACK,
        display_name="PoC管理",
        description="PoC/EXP管理与Python沙箱执行",
        import_path="core.modules.poc",
        class_name="POCModule",
        gui_tab_label="PoC管理",
        gui_tab_order=14,
    ),

    # ==================== 分析模块 ====================
    "sequencer": ModuleMeta(
        module_id="sequencer",
        category=ModuleCategory.ANALYSIS,
        display_name="Sequencer",
        description="会话Token随机性分析",
        import_path="core.modules.sequencer",
        class_name="SequencerModule",
        gui_tab_label="Sequencer",
        gui_tab_order=5,
    ),
    "decoder": ModuleMeta(
        module_id="decoder",
        category=ModuleCategory.ANALYSIS,
        display_name="Decoder",
        description="多格式编解码工具",
        import_path="core.modules.decoder",
        class_name="DecoderModule",
        gui_tab_label="Decoder",
        gui_tab_order=6,
    ),
    "comparer": ModuleMeta(
        module_id="comparer",
        category=ModuleCategory.ANALYSIS,
        display_name="Comparer",
        description="请求/响应差异对比分析",
        import_path="core.modules.comparer",
        class_name="ComparerModule",
        gui_tab_label="Comparer",
        gui_tab_order=7,
    ),
    "codec": ModuleMeta(
        module_id="codec",
        category=ModuleCategory.ANALYSIS,
        display_name="编解码",
        description="高级编解码与加密解密工具集",
        import_path="core.modules.codec",
        class_name="CodecModule",
        gui_tab_label="编解码",
        gui_tab_order=16,
    ),

    # ==================== 管理模块 ====================
    "target": ModuleMeta(
        module_id="target",
        category=ModuleCategory.MANAGEMENT,
        display_name="Target",
        description="目标范围管理与站点地图",
        import_path="core.modules.target",
        class_name="TargetModule",
        gui_tab_label="Target",
        gui_tab_order=1,
    ),
    "asset": ModuleMeta(
        module_id="asset",
        category=ModuleCategory.MANAGEMENT,
        display_name="资产管理",
        description="资产发现、管理与监控",
        import_path="core.modules.asset_manager",
        class_name="AssetModule",
        gui_tab_label="资产管理",
        gui_tab_order=53,
    ),
    "vuln": ModuleMeta(
        module_id="vuln",
        category=ModuleCategory.MANAGEMENT,
        display_name="漏洞管理",
        description="漏洞生命周期管理与追踪",
        import_path="core.modules.vuln_manager",
        class_name="VulnerabilityModule",
        gui_tab_label="漏洞管理",
        gui_tab_order=54,
    ),
    "poc_verify": ModuleMeta(
        module_id="poc_verify",
        category=ModuleCategory.MANAGEMENT,
        display_name="漏洞扫描",
        description="自动化漏洞扫描与验证",
        import_path="core.modules.poc_verification_ui",
        class_name="PoCVerificationModule",
        gui_tab_label="漏洞扫描",
        gui_tab_order=10,
    ),

    # ==================== 扩展模块 ====================
    "plugin_mgmt": ModuleMeta(
        module_id="plugin_mgmt",
        category=ModuleCategory.EXTENSION,
        display_name="插件扩展",
        description="企业级插件管理与热加载",
        import_path="core.modules.plugin_management_ui",
        class_name="PluginManagementModule",
        gui_tab_label="插件扩展",
        gui_tab_order=55,
    ),
    "pluginstore": ModuleMeta(
        module_id="pluginstore",
        category=ModuleCategory.EXTENSION,
        display_name="插件商店",
        description="插件市场，一键安装社区插件",
        import_path="core.modules.pluginstore",
        class_name="PluginStoreModule",
        gui_tab_label="插件商店",
        gui_tab_order=18,
    ),
    "yakrunner": ModuleMeta(
        module_id="yakrunner",
        category=ModuleCategory.EXTENSION,
        display_name="YakRunner",
        description="Yak语言脚本执行引擎",
        import_path="core.modules.yakrunner",
        class_name="YakRunnerModule",
        gui_tab_label="YakRunner",
        gui_tab_order=12,
    ),

    # ==================== AI模块 ====================
    "ai_security": ModuleMeta(
        module_id="ai_security",
        category=ModuleCategory.AI,
        display_name="AI安全检测",
        description="AI驱动的智能安全检测与分析",
        import_path="core.modules.ai_security",
        class_name="AISecurityDetectionModule",
        gui_tab_label="AI安全检测",
        gui_tab_order=20,
    ),
    "knowledge_base": ModuleMeta(
        module_id="knowledge_base",
        category=ModuleCategory.AI,
        display_name="知识库",
        description="安全知识库与SRC漏洞挖掘学习平台",
        import_path="core.modules.knowledge_base",
        class_name="KnowledgeBaseModule",
        gui_tab_label="知识库",
        gui_tab_order=19,
    ),

    # ==================== 报告模块 ====================
    "report": ModuleMeta(
        module_id="report",
        category=ModuleCategory.REPORT,
        display_name="报告",
        description="多格式报告生成（JSON/HTML/PDF）",
        import_path="core.modules.report_generator",
        class_name="ReportGenerator",
        gui_tab_label="报告",
        gui_tab_order=56,
    ),

    # ==================== MITM高级模块 ====================
    "mitm_advanced": ModuleMeta(
        module_id="mitm_advanced",
        category=ModuleCategory.NETWORK,
        display_name="MITM高级功能",
        description="MITM代理高级功能扩展",
        import_path="core.modules.mitm_advanced",
        class_name="MITMAdvancedModule",
        backend_only=True,
    ),
    "mitm_proxy_engine": ModuleMeta(
        module_id="mitm_proxy_engine",
        category=ModuleCategory.NETWORK,
        display_name="MITM代理引擎",
        description="MITM代理核心引擎",
        import_path="core.modules.mitm_proxy_engine",
        class_name="MITMProxyEngine",
        backend_only=True,
    ),
    "mitm_advanced_features": ModuleMeta(
        module_id="mitm_advanced_features",
        category=ModuleCategory.NETWORK,
        display_name="MITM流量处理",
        description="MITM流量处理与重放",
        import_path="core.modules.mitm_advanced_features",
        class_name="TrafficProcessor",
        backend_only=True,
    ),
    "mitm_script_extension": ModuleMeta(
        module_id="mitm_script_extension",
        category=ModuleCategory.NETWORK,
        display_name="MITM脚本扩展",
        description="MITM脚本管理器",
        import_path="core.modules.mitm_script_extension",
        class_name="ScriptManager",
        backend_only=True,
    ),
    "mitm_passive_scanner": ModuleMeta(
        module_id="mitm_passive_scanner",
        category=ModuleCategory.NETWORK,
        display_name="MITM被动扫描",
        description="MITM流量被动扫描",
        import_path="core.modules.mitm_passive_scanner",
        class_name="PassiveScanner",
        backend_only=True,
    ),
    "mitm_h2_engine": ModuleMeta(
        module_id="mitm_h2_engine",
        category=ModuleCategory.NETWORK,
        display_name="HTTP/2代理引擎",
        description="HTTP/2协议代理支持",
        import_path="core.modules.mitm_h2_engine",
        class_name="H2ProxyEngine",
        backend_only=True,
    ),
    "mitm_h3_engine": ModuleMeta(
        module_id="mitm_h3_engine",
        category=ModuleCategory.NETWORK,
        display_name="HTTP/3代理引擎",
        description="HTTP/3/QUIC协议代理支持",
        import_path="core.modules.mitm_h3_engine",
        class_name="H3ProxyEngine",
        backend_only=True,
    ),
    "mitm_replay_engine": ModuleMeta(
        module_id="mitm_replay_engine",
        category=ModuleCategory.NETWORK,
        display_name="MITM流量重放",
        description="MITM流量捕获与重放引擎",
        import_path="core.modules.mitm_replay_engine",
        class_name="TrafficReplayerEngine",
        backend_only=True,
    ),
    "mitm_adaptive_protocol": ModuleMeta(
        module_id="mitm_adaptive_protocol",
        category=ModuleCategory.NETWORK,
        display_name="自适应协议管理",
        description="MITM自适应协议协商",
        import_path="core.modules.mitm_adaptive_protocol",
        class_name="AdaptiveProtocolManager",
        backend_only=True,
    ),
    "mitm_security_hardening": ModuleMeta(
        module_id="mitm_security_hardening",
        category=ModuleCategory.NETWORK,
        display_name="MITM安全加固",
        description="MITM证书与域名安全管理",
        import_path="core.modules.mitm_security_hardening",
        class_name="CertificateKeyManager",
        backend_only=True,
    ),
    "mitm_network_simulation": ModuleMeta(
        module_id="mitm_network_simulation",
        category=ModuleCategory.NETWORK,
        display_name="网络环境模拟",
        description="MITM网络环境模拟与延迟注入",
        import_path="core.modules.mitm_network_simulation",
        class_name="NetworkEnvironmentManager",
        backend_only=True,
    ),
    "mitm_mock_response": ModuleMeta(
        module_id="mitm_mock_response",
        category=ModuleCategory.NETWORK,
        display_name="Mock响应",
        description="MITM Mock响应规则管理",
        import_path="core.modules.mitm_mock_response",
        class_name="MockManager",
        backend_only=True,
    ),
    "mitm_advanced_filter": ModuleMeta(
        module_id="mitm_advanced_filter",
        category=ModuleCategory.NETWORK,
        display_name="MITM高级过滤",
        description="MITM流量搜索与高级过滤",
        import_path="core.modules.mitm_advanced_filter",
        class_name="AdvancedFilterManager",
        backend_only=True,
    ),
    "mitm_app_integration": ModuleMeta(
        module_id="mitm_app_integration",
        category=ModuleCategory.NETWORK,
        display_name="MITM应用集成",
        description="MITM与主应用集成",
        import_path="core.modules.mitm_app_integration",
        class_name="MITMModuleIntegration",
        backend_only=True,
    ),
    "mitm_c2_linkage": ModuleMeta(
        module_id="mitm_c2_linkage",
        category=ModuleCategory.NETWORK,
        display_name="MITM-C2联动",
        description="MITM与C2通信联动",
        import_path="core.modules.mitm_c2_linkage",
        class_name="C2LinkageEngine",
        backend_only=True,
    ),
    "mitm_asset_linkage": ModuleMeta(
        module_id="mitm_asset_linkage",
        category=ModuleCategory.NETWORK,
        display_name="MITM-资产联动",
        description="MITM流量与资产管理联动",
        import_path="core.modules.mitm_asset_linkage",
        class_name="AssetLinkageEngine",
        backend_only=True,
    ),

    # ==================== 反序列化攻击模块 ====================
    "deser_integration": ModuleMeta(
        module_id="deser_integration",
        category=ModuleCategory.ATTACK,
        display_name="反序列化集成",
        description="Java/Python反序列化攻击集成",
        import_path="core.modules.deser_integration",
        class_name="DeserializationIntegration",
        gui_tab_label="反序列化",
        gui_tab_order=60,
    ),
    "deserialization_exploit": ModuleMeta(
        module_id="deserialization_exploit",
        category=ModuleCategory.ATTACK,
        display_name="反序列化利用",
        description="反序列化漏洞利用引擎",
        import_path="core.modules.deserialization_exploit",
        class_name="DeserializationExploit",
        backend_only=True,
    ),
    "deser_parser": ModuleMeta(
        module_id="deser_parser",
        category=ModuleCategory.ATTACK,
        display_name="反序列化解析",
        description="反序列化数据解析",
        import_path="core.modules.deser_parser",
        class_name="DeserParser",
        backend_only=True,
    ),
    "deser_sandbox": ModuleMeta(
        module_id="deser_sandbox",
        category=ModuleCategory.ATTACK,
        display_name="反序列化沙箱",
        description="反序列化安全沙箱执行",
        import_path="core.modules.deser_sandbox",
        class_name="DeserSandbox",
        backend_only=True,
    ),
    "java_deser_detector": ModuleMeta(
        module_id="java_deser_detector",
        category=ModuleCategory.ATTACK,
        display_name="Java反序列化检测",
        description="Java反序列化漏洞检测",
        import_path="core.modules.java_deser_detector",
        class_name="JavaDeserDetector",
        backend_only=True,
    ),
    "gadget_chain_manager": ModuleMeta(
        module_id="gadget_chain_manager",
        category=ModuleCategory.ATTACK,
        display_name="Gadget链管理",
        description="反序列化Gadget链管理",
        import_path="core.modules.gadget_chain_manager",
        class_name="GadgetChainManager",
        backend_only=True,
    ),
    "jndi_bypass": ModuleMeta(
        module_id="jndi_bypass",
        category=ModuleCategory.ATTACK,
        display_name="JNDI绕过",
        description="JNDI注入与Bypass引擎",
        import_path="core.modules.jndi_bypass",
        class_name="JndiBypassEngine",
        backend_only=True,
    ),
    "java_ecosystem": ModuleMeta(
        module_id="java_ecosystem",
        category=ModuleCategory.ATTACK,
        display_name="Java生态系统",
        description="Java生态漏洞利用",
        import_path="core.modules.java_ecosystem",
        class_name="JavaEcosystem",
        backend_only=True,
    ),
    "deser_attack_pipeline": ModuleMeta(
        module_id="deser_attack_pipeline",
        category=ModuleCategory.ATTACK,
        display_name="反序列化攻击链",
        description="反序列化自动化攻击流水线",
        import_path="core.modules.deser_attack_pipeline",
        class_name="DeserAttackPipeline",
        backend_only=True,
    ),
    "deser_knowledge_base": ModuleMeta(
        module_id="deser_knowledge_base",
        category=ModuleCategory.ATTACK,
        display_name="反序列化知识库",
        description="反序列化漏洞知识库",
        import_path="core.modules.deser_knowledge_base",
        class_name="DeserKnowledgeBase",
        backend_only=True,
    ),
    "deser_community": ModuleMeta(
        module_id="deser_community",
        category=ModuleCategory.ATTACK,
        display_name="反序列化社区",
        description="反序列化社区资源集成",
        import_path="core.modules.deser_community",
        class_name="DeserCommunity",
        backend_only=True,
    ),
    "deser_report": ModuleMeta(
        module_id="deser_report",
        category=ModuleCategory.REPORT,
        display_name="反序列化报告",
        description="反序列化攻击报告生成",
        import_path="core.modules.deser_report",
        class_name="DeserReport",
        backend_only=True,
    ),
    "mem_shell_generator": ModuleMeta(
        module_id="mem_shell_generator",
        category=ModuleCategory.ATTACK,
        display_name="内存马生成",
        description="Java内存马生成器",
        import_path="core.modules.mem_shell_generator",
        class_name="MemShellGenerator",
        backend_only=True,
    ),
    "payload_generator": ModuleMeta(
        module_id="payload_generator",
        category=ModuleCategory.ATTACK,
        display_name="Payload生成",
        description="多平台Payload生成器",
        import_path="core.modules.payload_generator",
        class_name="PayloadGenerator",
        backend_only=True,
    ),
    "payload_obfuscator": ModuleMeta(
        module_id="payload_obfuscator",
        category=ModuleCategory.ATTACK,
        display_name="Payload混淆",
        description="Payload混淆与免杀",
        import_path="core.modules.payload_obfuscator",
        class_name="PayloadObfuscator",
        backend_only=True,
    ),

    # ==================== GraphQL/gRPC模块 ====================
    "graphql_integration": ModuleMeta(
        module_id="graphql_integration",
        category=ModuleCategory.ATTACK,
        display_name="GraphQL集成",
        description="GraphQL接口测试集成",
        import_path="core.modules.graphql_integration",
        class_name="GraphQLIntegration",
        gui_tab_label="GraphQL",
        gui_tab_order=61,
    ),
    "graphql_attacks": ModuleMeta(
        module_id="graphql_attacks",
        category=ModuleCategory.ATTACK,
        display_name="GraphQL攻击",
        description="GraphQL漏洞攻击",
        import_path="core.modules.graphql_attacks",
        class_name="GraphQLAttacks",
        backend_only=True,
    ),
    "graphql_advanced_attacks": ModuleMeta(
        module_id="graphql_advanced_attacks",
        category=ModuleCategory.ATTACK,
        display_name="GraphQL高级攻击",
        description="GraphQL高级攻击技术",
        import_path="core.modules.graphql_advanced_attacks",
        class_name="GraphQLAdvancedAttacks",
        backend_only=True,
    ),
    "graphql_detector": ModuleMeta(
        module_id="graphql_detector",
        category=ModuleCategory.ATTACK,
        display_name="GraphQL检测",
        description="GraphQL端点检测",
        import_path="core.modules.graphql_detector",
        class_name="GraphQLDetector",
        backend_only=True,
    ),
    "graphql_introspector": ModuleMeta(
        module_id="graphql_introspector",
        category=ModuleCategory.ATTACK,
        display_name="GraphQL内省",
        description="GraphQL Schema内省",
        import_path="core.modules.graphql_introspector",
        class_name="GraphQLIntrospector",
        backend_only=True,
    ),
    "graphql_authz_tester": ModuleMeta(
        module_id="graphql_authz_tester",
        category=ModuleCategory.ATTACK,
        display_name="GraphQL鉴权测试",
        description="GraphQL授权绕过测试",
        import_path="core.modules.graphql_authz_tester",
        class_name="GraphQLAuthzTester",
        backend_only=True,
    ),
    "graphql_jwt_test": ModuleMeta(
        module_id="graphql_jwt_test",
        category=ModuleCategory.ATTACK,
        display_name="GraphQL-JWT测试",
        description="GraphQL JWT认证测试",
        import_path="core.modules.graphql_jwt_test",
        class_name="GraphQLJWTTestManager",
        backend_only=True,
    ),
    "graphql_subscription_test": ModuleMeta(
        module_id="graphql_subscription_test",
        category=ModuleCategory.ATTACK,
        display_name="GraphQL订阅测试",
        description="GraphQL WebSocket订阅测试",
        import_path="core.modules.graphql_subscription_test",
        class_name="GraphQLSubscriptionTest",
        backend_only=True,
    ),
    "graphql_attack_pipeline": ModuleMeta(
        module_id="graphql_attack_pipeline",
        category=ModuleCategory.ATTACK,
        display_name="GraphQL攻击流水线",
        description="GraphQL自动化攻击流水线",
        import_path="core.modules.graphql_attack_pipeline",
        class_name="GraphQLAttackPipeline",
        backend_only=True,
    ),
    "graphql_deep_injection": ModuleMeta(
        module_id="graphql_deep_injection",
        category=ModuleCategory.ATTACK,
        display_name="GraphQL深度注入",
        description="GraphQL深度注入攻击",
        import_path="core.modules.graphql_deep_injection",
        class_name="GraphQLDeepInjection",
        backend_only=True,
    ),
    "graphql_enterprise": ModuleMeta(
        module_id="graphql_enterprise",
        category=ModuleCategory.ATTACK,
        display_name="GraphQL企业版",
        description="GraphQL企业级功能",
        import_path="core.modules.graphql_enterprise",
        class_name="GraphQLEnterprise",
        backend_only=True,
    ),
    "graphql_platform_integration": ModuleMeta(
        module_id="graphql_platform_integration",
        category=ModuleCategory.ATTACK,
        display_name="GraphQL平台集成",
        description="GraphQL与平台集成",
        import_path="core.modules.graphql_platform_integration",
        class_name="GraphQLPlatformIntegration",
        backend_only=True,
    ),
    "grpc_integration": ModuleMeta(
        module_id="grpc_integration",
        category=ModuleCategory.ATTACK,
        display_name="gRPC集成",
        description="gRPC接口测试集成",
        import_path="core.modules.grpc_integration",
        class_name="GrpcIntegration",
        gui_tab_label="gRPC",
        gui_tab_order=62,
    ),
    "grpc_parser": ModuleMeta(
        module_id="grpc_parser",
        category=ModuleCategory.ATTACK,
        display_name="gRPC解析",
        description="gRPC Protobuf解析",
        import_path="core.modules.grpc_parser",
        class_name="GrpcParser",
        backend_only=True,
    ),
    "grpc_repeater": ModuleMeta(
        module_id="grpc_repeater",
        category=ModuleCategory.ATTACK,
        display_name="gRPC重放",
        description="gRPC请求重放",
        import_path="core.modules.grpc_repeater",
        class_name="GrpcRepeater",
        backend_only=True,
    ),
    "grpc_exploit": ModuleMeta(
        module_id="grpc_exploit",
        category=ModuleCategory.ATTACK,
        display_name="gRPC利用",
        description="gRPC漏洞利用",
        import_path="core.modules.grpc_exploit",
        class_name="GrpcExploit",
        backend_only=True,
    ),

    # ==================== JWT/OAuth/OIDC模块 ====================
    "jwt_editor": ModuleMeta(
        module_id="jwt_editor",
        category=ModuleCategory.ATTACK,
        display_name="JWT编辑器",
        description="JWT Token编辑与测试",
        import_path="core.modules.jwt_editor",
        class_name="JWTEditorManager",
        gui_tab_label="JWT测试",
        gui_tab_order=63,
    ),
    "jwt_advanced_attacks": ModuleMeta(
        module_id="jwt_advanced_attacks",
        category=ModuleCategory.ATTACK,
        display_name="JWT高级攻击",
        description="JWT嵌套与高级攻击",
        import_path="core.modules.jwt_advanced_attacks",
        class_name="JWTAdvancedAttacksManager",
        backend_only=True,
    ),
    "jwt_attack_orchestration": ModuleMeta(
        module_id="jwt_attack_orchestration",
        category=ModuleCategory.ATTACK,
        display_name="JWT攻击编排",
        description="JWT攻击工作流编排",
        import_path="core.modules.jwt_attack_orchestration",
        class_name="JWTAttackOrchestrationManager",
        backend_only=True,
    ),
    "jwt_diagnostic_ai": ModuleMeta(
        module_id="jwt_diagnostic_ai",
        category=ModuleCategory.AI,
        display_name="JWT诊断AI",
        description="AI驱动JWT漏洞诊断",
        import_path="core.modules.jwt_diagnostic_ai",
        class_name="JWTDiagnosticAIManager",
        backend_only=True,
    ),
    "jwt_info_leak": ModuleMeta(
        module_id="jwt_info_leak",
        category=ModuleCategory.ATTACK,
        display_name="JWT信息泄露",
        description="JWT敏感信息泄露检测",
        import_path="core.modules.jwt_info_leak",
        class_name="JWTInfoLeakManager",
        backend_only=True,
    ),
    "jwt_obfuscation": ModuleMeta(
        module_id="jwt_obfuscation",
        category=ModuleCategory.ATTACK,
        display_name="JWT混淆",
        description="JWT混淆与绕过",
        import_path="core.modules.jwt_obfuscation",
        class_name="JWTObfuscationManager",
        backend_only=True,
    ),
    "jwt_oauth_integration": ModuleMeta(
        module_id="jwt_oauth_integration",
        category=ModuleCategory.ATTACK,
        display_name="JWT-OAuth集成",
        description="JWT与OAuth联动测试",
        import_path="core.modules.jwt_oauth_integration",
        class_name="JWTOAuthIntegrationManager",
        backend_only=True,
    ),
    "jwt_oauth_passive_rules": ModuleMeta(
        module_id="jwt_oauth_passive_rules",
        category=ModuleCategory.ATTACK,
        display_name="JWT-OAuth被动规则",
        description="JWT-OAuth被动扫描规则",
        import_path="core.modules.jwt_oauth_passive_rules",
        class_name="JWTOAuthPassiveRulesEngine",
        backend_only=True,
    ),
    "jwt_oauth_poc_gen": ModuleMeta(
        module_id="jwt_oauth_poc_gen",
        category=ModuleCategory.ATTACK,
        display_name="JWT-OAuth PoC生成",
        description="JWT-OAuth概念验证生成",
        import_path="core.modules.jwt_oauth_poc_gen",
        class_name="JWTOAuthPoCManager",
        backend_only=True,
    ),
    "jwt_oauth_scenarios": ModuleMeta(
        module_id="jwt_oauth_scenarios",
        category=ModuleCategory.ATTACK,
        display_name="JWT-OAuth场景",
        description="JWT-OAuth攻击场景",
        import_path="core.modules.jwt_oauth_scenarios",
        class_name="JWTOAuthScenariosManager",
        backend_only=True,
    ),
    "oauth_analyzer": ModuleMeta(
        module_id="oauth_analyzer",
        category=ModuleCategory.ATTACK,
        display_name="OAuth分析器",
        description="OAuth流程分析",
        import_path="core.modules.oauth_analyzer",
        class_name="OAuthAnalyzerManager",
        backend_only=True,
    ),
    "oauth_deep_test": ModuleMeta(
        module_id="oauth_deep_test",
        category=ModuleCategory.ATTACK,
        display_name="OAuth深度测试",
        description="OAuth深度测试",
        import_path="core.modules.oauth_deep_test",
        class_name="OAuthDeepTestManager",
        backend_only=True,
    ),
    "oauth21_audit": ModuleMeta(
        module_id="oauth21_audit",
        category=ModuleCategory.ATTACK,
        display_name="OAuth 2.1审计",
        description="OAuth 2.1安全审计",
        import_path="core.modules.oauth21_audit",
        class_name="OAuth21AuditManager",
        backend_only=True,
    ),
    "oauth_cross_client": ModuleMeta(
        module_id="oauth_cross_client",
        category=ModuleCategory.ATTACK,
        display_name="OAuth跨客户端",
        description="OAuth跨客户端攻击",
        import_path="core.modules.oauth_cross_client",
        class_name="OAuthCrossClientManager",
        backend_only=True,
    ),
    "oidc_analyzer": ModuleMeta(
        module_id="oidc_analyzer",
        category=ModuleCategory.ATTACK,
        display_name="OIDC分析",
        description="OpenID Connect分析",
        import_path="core.modules.oidc_analyzer",
        class_name="OIDCAnalyzerManager",
        backend_only=True,
    ),
    "oidc_deep_exploit": ModuleMeta(
        module_id="oidc_deep_exploit",
        category=ModuleCategory.ATTACK,
        display_name="OIDC深度利用",
        description="OIDC深度利用",
        import_path="core.modules.oidc_deep_exploit",
        class_name="OIDCDeepExploitManager",
        backend_only=True,
    ),
    "cross_protocol_token": ModuleMeta(
        module_id="cross_protocol_token",
        category=ModuleCategory.ATTACK,
        display_name="跨协议Token",
        description="跨协议Token攻击",
        import_path="core.modules.cross_protocol_token",
        class_name="CrossProtocolTokenManager",
        backend_only=True,
    ),
    "jwt_parser_exploits": ModuleMeta(
        module_id="jwt_parser_exploits",
        category=ModuleCategory.ATTACK,
        display_name="JWT解析器利用",
        description="JWT解析器差异利用",
        import_path="core.modules.jwt_parser_exploits",
        class_name="JWTParserExploitsManager",
        backend_only=True,
    ),

    # ==================== 域渗透模块 ====================
    "domain_attack_integration": ModuleMeta(
        module_id="domain_attack_integration",
        category=ModuleCategory.ATTACK,
        display_name="域攻击集成",
        description="域渗透攻击集成",
        import_path="core.modules.domain_attack_integration",
        class_name="DomainAttackIntegration",
        gui_tab_label="域渗透",
        gui_tab_order=64,
    ),
    "domain_attack_panel": ModuleMeta(
        module_id="domain_attack_panel",
        category=ModuleCategory.ATTACK,
        display_name="域攻击面板",
        description="域渗透攻击面板",
        import_path="core.modules.domain_attack_panel",
        class_name="DomainAttackPanel",
        backend_only=True,
    ),
    "domain_decision_engine": ModuleMeta(
        module_id="domain_decision_engine",
        category=ModuleCategory.ATTACK,
        display_name="域决策引擎",
        description="域渗透决策引擎",
        import_path="core.modules.domain_decision_engine",
        class_name="DomainDecisionEngine",
        backend_only=True,
    ),
    "domain_privesc": ModuleMeta(
        module_id="domain_privesc",
        category=ModuleCategory.ATTACK,
        display_name="域提权",
        description="域环境提权",
        import_path="core.modules.domain_privesc",
        class_name="DomainPrivescDetector",
        backend_only=True,
    ),
    "domain_auto_explore": ModuleMeta(
        module_id="domain_auto_explore",
        category=ModuleCategory.ATTACK,
        display_name="域自动探测",
        description="域环境自动探测",
        import_path="core.modules.domain_auto_explore",
        class_name="DomainAutoExplore",
        backend_only=True,
    ),
    "domain_stealth": ModuleMeta(
        module_id="domain_stealth",
        category=ModuleCategory.ATTACK,
        display_name="域隐蔽",
        description="域操作隐蔽化",
        import_path="core.modules.domain_stealth",
        class_name="DomainStealth",
        backend_only=True,
    ),
    "domain_persistence_recovery": ModuleMeta(
        module_id="domain_persistence_recovery",
        category=ModuleCategory.ATTACK,
        display_name="域持久化",
        description="域持久化与恢复",
        import_path="core.modules.domain_persistence_recovery",
        class_name="DomainPersistence",
        backend_only=True,
    ),
    "domain_self_test": ModuleMeta(
        module_id="domain_self_test",
        category=ModuleCategory.ATTACK,
        display_name="域自测",
        description="域环境自测",
        import_path="core.modules.domain_self_test",
        class_name="DomainSelfTest",
        backend_only=True,
    ),
    "adcs_escalation": ModuleMeta(
        module_id="adcs_escalation",
        category=ModuleCategory.ATTACK,
        display_name="ADCS提权",
        description="ADCS证书服务提权",
        import_path="core.modules.adcs_escalation",
        class_name="ADCSEscalation",
        backend_only=True,
    ),
    "dcsync_attack": ModuleMeta(
        module_id="dcsync_attack",
        category=ModuleCategory.ATTACK,
        display_name="DCSync攻击",
        description="DCSync密码哈希同步",
        import_path="core.modules.dcsync_attack",
        class_name="DCSyncAttack",
        backend_only=True,
    ),
    "dcshadow": ModuleMeta(
        module_id="dcshadow",
        category=ModuleCategory.ATTACK,
        display_name="DCShadow",
        description="DCShadow影子域控",
        import_path="core.modules.dcshadow",
        class_name="DCShadow",
        backend_only=True,
    ),
    "gpo_backdoor": ModuleMeta(
        module_id="gpo_backdoor",
        category=ModuleCategory.ATTACK,
        display_name="GPO后门",
        description="组策略后门",
        import_path="core.modules.gpo_backdoor",
        class_name="GPOBackdoor",
        backend_only=True,
    ),
    "dsrm_backdoor": ModuleMeta(
        module_id="dsrm_backdoor",
        category=ModuleCategory.ATTACK,
        display_name="DSRM后门",
        description="DSRM密码后门",
        import_path="core.modules.dsrm_backdoor",
        class_name="DSRMBackdoor",
        backend_only=True,
    ),
    "adminsdholder": ModuleMeta(
        module_id="adminsdholder",
        category=ModuleCategory.ATTACK,
        display_name="AdminSDHolder",
        description="AdminSDHolder ACL攻击",
        import_path="core.modules.adminsdholder",
        class_name="AdminSDHolder",
        backend_only=True,
    ),
    "cross_domain_trust": ModuleMeta(
        module_id="cross_domain_trust",
        category=ModuleCategory.ATTACK,
        display_name="跨域信任",
        description="跨域信任利用",
        import_path="core.modules.cross_domain_trust",
        class_name="CrossDomainTrust",
        backend_only=True,
    ),
    "cross_forest_exploit": ModuleMeta(
        module_id="cross_forest_exploit",
        category=ModuleCategory.ATTACK,
        display_name="跨林利用",
        description="跨森林攻击",
        import_path="core.modules.cross_forest_exploit",
        class_name="CrossForestExploit",
        backend_only=True,
    ),

    # ==================== C2通信模块 ====================
    "c2_automation": ModuleMeta(
        module_id="c2_automation",
        category=ModuleCategory.CORE,
        display_name="C2自动化",
        description="C2通信自动化",
        import_path="core.modules.c2_automation",
        class_name="C2AutomationManager",
        backend_only=True,
    ),
    "c2_observability": ModuleMeta(
        module_id="c2_observability",
        category=ModuleCategory.CORE,
        display_name="C2可观测性",
        description="C2通信监控与告警",
        import_path="core.modules.c2_observability",
        class_name="C2ObservabilityManager",
        backend_only=True,
    ),
    "beacon_lifecycle": ModuleMeta(
        module_id="beacon_lifecycle",
        category=ModuleCategory.CORE,
        display_name="Beacon生命周期",
        description="Beacon全生命周期管理",
        import_path="core.modules.beacon_lifecycle",
        class_name="BeaconLifecycleManager",
        backend_only=True,
    ),
    "beacon_profile_adapter": ModuleMeta(
        module_id="beacon_profile_adapter",
        category=ModuleCategory.CORE,
        display_name="Beacon配置适配",
        description="Beacon Profile适配器",
        import_path="core.modules.beacon_profile_adapter",
        class_name="C2ProfileManager",
        backend_only=True,
    ),
    "channel_manager": ModuleMeta(
        module_id="channel_manager",
        category=ModuleCategory.CORE,
        display_name="通道管理",
        description="C2通信通道管理",
        import_path="core.modules.channel_manager",
        class_name="ChannelManager",
        backend_only=True,
    ),
    "domain_fronting": ModuleMeta(
        module_id="domain_fronting",
        category=ModuleCategory.CORE,
        display_name="域名前置",
        description="域名前置通信",
        import_path="core.modules.domain_fronting",
        class_name="DomainFrontingEngine",
        backend_only=True,
    ),
    "blockchain_c2": ModuleMeta(
        module_id="blockchain_c2",
        category=ModuleCategory.CORE,
        display_name="区块链C2",
        description="基于区块链的C2通信",
        import_path="core.modules.blockchain_c2",
        class_name="BlockchainC2Manager",
        backend_only=True,
    ),
    "cloud_native_c2": ModuleMeta(
        module_id="cloud_native_c2",
        category=ModuleCategory.CORE,
        display_name="云原生C2",
        description="云原生C2基础设施",
        import_path="core.modules.cloud_native_c2",
        class_name="CloudNativeC2Manager",
        backend_only=True,
    ),
    "dga_generator": ModuleMeta(
        module_id="dga_generator",
        category=ModuleCategory.CORE,
        display_name="DGA生成",
        description="域名生成算法",
        import_path="core.modules.dga_generator",
        class_name="DGAGenerator",
        backend_only=True,
    ),
    "extreme_comms": ModuleMeta(
        module_id="extreme_comms",
        category=ModuleCategory.CORE,
        display_name="极端通信",
        description="极端环境通信",
        import_path="core.modules.extreme_comms",
        class_name="ExtremeCommManager",
        backend_only=True,
    ),
    "hibernation": ModuleMeta(
        module_id="hibernation",
        category=ModuleCategory.CORE,
        display_name="休眠",
        description="Beacon休眠管理",
        import_path="core.modules.hibernation",
        class_name="HibernationManager",
        backend_only=True,
    ),
    "memory_encryption": ModuleMeta(
        module_id="memory_encryption",
        category=ModuleCategory.CORE,
        display_name="内存加密",
        description="Beacon内存加密",
        import_path="core.modules.memory_encryption",
        class_name="MemoryEncryptionManager",
        backend_only=True,
    ),
    "evasion_tester": ModuleMeta(
        module_id="evasion_tester",
        category=ModuleCategory.ATTACK,
        display_name="免杀测试",
        description="免杀能力测试",
        import_path="core.modules.evasion_tester",
        class_name="EvasionTester",
        backend_only=True,
    ),
    "genetic_profile_engine": ModuleMeta(
        module_id="genetic_profile_engine",
        category=ModuleCategory.CORE,
        display_name="遗传配置引擎",
        description="基于遗传算法的配置优化",
        import_path="core.modules.genetic_profile_engine",
        class_name="GeneticProfileEngine",
        backend_only=True,
    ),
    "ai_traffic_gan": ModuleMeta(
        module_id="ai_traffic_gan",
        category=ModuleCategory.AI,
        display_name="AI流量GAN",
        description="AI生成仿真流量",
        import_path="core.modules.ai_traffic_gan",
        class_name="AITrafficManager",
        backend_only=True,
    ),
    "digital_twin_sim": ModuleMeta(
        module_id="digital_twin_sim",
        category=ModuleCategory.CORE,
        display_name="数字孪生仿真",
        description="C2环境数字孪生",
        import_path="core.modules.digital_twin_sim",
        class_name="DigitalTwinSimulationManager",
        backend_only=True,
    ),
    "cognitive_warfare": ModuleMeta(
        module_id="cognitive_warfare",
        category=ModuleCategory.ATTACK,
        display_name="认知战",
        description="社会工程学与认知战",
        import_path="core.modules.cognitive_warfare",
        class_name="CognitiveWarfareManager",
        backend_only=True,
    ),
    "p2p_mesh": ModuleMeta(
        module_id="p2p_mesh",
        category=ModuleCategory.CORE,
        display_name="P2P网格",
        description="P2P网格通信",
        import_path="core.modules.p2p_mesh",
        class_name="P2PMeshManager",
        backend_only=True,
    ),
    "kernel_beacon": ModuleMeta(
        module_id="kernel_beacon",
        category=ModuleCategory.CORE,
        display_name="内核Beacon",
        description="内核级Beacon",
        import_path="core.modules.kernel_beacon",
        class_name="KernelBeaconManager",
        backend_only=True,
    ),
    "polymorphic_engine": ModuleMeta(
        module_id="polymorphic_engine",
        category=ModuleCategory.ATTACK,
        display_name="多态引擎",
        description="Shellcode/二进制多态",
        import_path="core.modules.polymorphic_engine",
        class_name="ShellcodePolymorphicEngine",
        backend_only=True,
    ),

    # ==================== 提权模块 ====================
    "privesc_collector": ModuleMeta(
        module_id="privesc_collector",
        category=ModuleCategory.ATTACK,
        display_name="提权信息收集",
        description="系统提权向量收集",
        import_path="core.modules.privesc_collector",
        class_name="PrivescCollector",
        backend_only=True,
    ),
    "privesc_analyzer": ModuleMeta(
        module_id="privesc_analyzer",
        category=ModuleCategory.ATTACK,
        display_name="提权分析",
        description="提权风险分析",
        import_path="core.modules.privesc_analyzer",
        class_name="PrivescAnalyzer",
        backend_only=True,
    ),
    "privesc_beacon": ModuleMeta(
        module_id="privesc_beacon",
        category=ModuleCategory.ATTACK,
        display_name="提权-Beacon集成",
        description="提权与Beacon集成",
        import_path="core.modules.privesc_beacon",
        class_name="PrivescBeaconIntegration",
        backend_only=True,
    ),
    "privesc_exploit_engine": ModuleMeta(
        module_id="privesc_exploit_engine",
        category=ModuleCategory.ATTACK,
        display_name="提权利用引擎",
        description="提权漏洞利用",
        import_path="core.modules.privesc_exploit_engine",
        class_name="PrivescExploitEngine",
        backend_only=True,
    ),
    "privesc_decision_tree": ModuleMeta(
        module_id="privesc_decision_tree",
        category=ModuleCategory.ATTACK,
        display_name="提权决策树",
        description="提权路径决策",
        import_path="core.modules.privesc_decision_tree",
        class_name="PrivescDecisionTreeBuilder",
        backend_only=True,
    ),
    "privesc_report": ModuleMeta(
        module_id="privesc_report",
        category=ModuleCategory.REPORT,
        display_name="提权报告",
        description="提权攻击报告",
        import_path="core.modules.privesc_report",
        class_name="PrivescReportGenerator",
        backend_only=True,
    ),
    "privesc_arsenal": ModuleMeta(
        module_id="privesc_arsenal",
        category=ModuleCategory.ATTACK,
        display_name="提权军火库",
        description="提权工具库",
        import_path="core.modules.privesc_arsenal",
        class_name="PrivescArsenalManager",
        backend_only=True,
    ),
    "privesc_evasion": ModuleMeta(
        module_id="privesc_evasion",
        category=ModuleCategory.ATTACK,
        display_name="提权免杀",
        description="EDR/AMSI/ETW绕过",
        import_path="core.modules.privesc_evasion",
        class_name="EDRDetector",
        backend_only=True,
    ),
    "privesc_rl_agent": ModuleMeta(
        module_id="privesc_rl_agent",
        category=ModuleCategory.AI,
        display_name="提权RL代理",
        description="强化学习提权",
        import_path="core.modules.privesc_rl_agent",
        class_name="PrivescRLFramework",
        backend_only=True,
    ),
    "privesc_graph": ModuleMeta(
        module_id="privesc_graph",
        category=ModuleCategory.ATTACK,
        display_name="提权图",
        description="提权攻击图",
        import_path="core.modules.privesc_graph",
        class_name="PrivescGraphInterface",
        backend_only=True,
    ),
    "privesc_audit": ModuleMeta(
        module_id="privesc_audit",
        category=ModuleCategory.MANAGEMENT,
        display_name="提权审计",
        description="提权操作审计",
        import_path="core.modules.privesc_audit",
        class_name="PrivescAuditModule",
        backend_only=True,
    ),
    "cloud_privesc": ModuleMeta(
        module_id="cloud_privesc",
        category=ModuleCategory.ATTACK,
        display_name="云提权",
        description="云环境/容器提权",
        import_path="core.modules.cloud_privesc",
        class_name="CloudPrivescDetector",
        backend_only=True,
    ),
    "knowledge_base_module": ModuleMeta(
        module_id="knowledge_base_module",
        category=ModuleCategory.MANAGEMENT,
        display_name="知识库接口",
        description="GTFOBins/LOLBAS知识库",
        import_path="core.modules.knowledge_base",
        class_name="KnowledgeBaseInterface",
        backend_only=True,
    ),
    "poc_research": ModuleMeta(
        module_id="poc_research",
        category=ModuleCategory.ATTACK,
        display_name="PoC研究",
        description="漏洞研究与PoC开发",
        import_path="core.modules.poc_research",
        class_name="PocResearchModule",
        backend_only=True,
    ),
    "privesc_stealth": ModuleMeta(
        module_id="privesc_stealth",
        category=ModuleCategory.ATTACK,
        display_name="提权隐蔽",
        description="内核级隐蔽技术",
        import_path="core.modules.privesc_stealth",
        class_name="PrivescStealthModule",
        backend_only=True,
    ),
    "privesc_self_healing": ModuleMeta(
        module_id="privesc_self_healing",
        category=ModuleCategory.ATTACK,
        display_name="提权自愈",
        description="系统自愈与回滚",
        import_path="core.modules.privesc_self_healing",
        class_name="PrivescSelfHealingModule",
        backend_only=True,
    ),
    "privesc_cross_platform": ModuleMeta(
        module_id="privesc_cross_platform",
        category=ModuleCategory.ATTACK,
        display_name="提权跨平台",
        description="Windows/Linux提权",
        import_path="core.modules.privesc_cross_platform",
        class_name="PrivescCrossPlatformModule",
        backend_only=True,
    ),
    "privesc_scheduler": ModuleMeta(
        module_id="privesc_scheduler",
        category=ModuleCategory.ATTACK,
        display_name="提权调度",
        description="定时提权检查",
        import_path="core.modules.privesc_scheduler",
        class_name="PrivescSchedulerModule",
        backend_only=True,
    ),
    "privesc_self_test": ModuleMeta(
        module_id="privesc_self_test",
        category=ModuleCategory.ATTACK,
        display_name="提权自测",
        description="提权规则自测",
        import_path="core.modules.privesc_self_test",
        class_name="PrivescSelfTestModule",
        backend_only=True,
    ),
    "privesc_observability": ModuleMeta(
        module_id="privesc_observability",
        category=ModuleCategory.MANAGEMENT,
        display_name="提权可观测",
        description="提权性能与诊断",
        import_path="core.modules.privesc_observability",
        class_name="PrivescObservabilityModule",
        backend_only=True,
    ),
    "privesc_config": ModuleMeta(
        module_id="privesc_config",
        category=ModuleCategory.MANAGEMENT,
        display_name="提权配置",
        description="提权模块配置管理",
        import_path="core.modules.privesc_config",
        class_name="PrivescConfigModule",
        backend_only=True,
    ),

    # ==================== AI模块 ====================
    "ai_engine": ModuleMeta(
        module_id="ai_engine",
        category=ModuleCategory.AI,
        display_name="AI引擎",
        description="AI核心引擎",
        import_path="core.modules.ai_engine",
        class_name="AIEngine",
        backend_only=True,
    ),
    "ai_conversation": ModuleMeta(
        module_id="ai_conversation",
        category=ModuleCategory.AI,
        display_name="AI对话",
        description="AI对话系统",
        import_path="core.modules.ai_conversation",
        class_name="AIConversation",
        backend_only=True,
    ),
    "ai_learning": ModuleMeta(
        module_id="ai_learning",
        category=ModuleCategory.AI,
        display_name="AI学习",
        description="AI自学习系统",
        import_path="core.modules.ai_learning",
        class_name="AILearningSystem",
        backend_only=True,
    ),
    "ai_report": ModuleMeta(
        module_id="ai_report",
        category=ModuleCategory.AI,
        display_name="AI报告",
        description="AI报告生成",
        import_path="core.modules.ai_report",
        class_name="AIReport",
        backend_only=True,
    ),
    "ai_penetration_test": ModuleMeta(
        module_id="ai_penetration_test",
        category=ModuleCategory.AI,
        display_name="AI渗透测试",
        description="AI自动渗透",
        import_path="core.modules.ai_penetration_test",
        class_name="AIPenetrationTest",
        backend_only=True,
    ),

    # ==================== 协作模块 ====================
    "collab_integration": ModuleMeta(
        module_id="collab_integration",
        category=ModuleCategory.MANAGEMENT,
        display_name="协作集成",
        description="团队协作集成",
        import_path="core.modules.collab_integration",
        class_name="CollaborationIntegration",
        backend_only=True,
    ),
    "collab_project": ModuleMeta(
        module_id="collab_project",
        category=ModuleCategory.MANAGEMENT,
        display_name="协作项目",
        description="项目管理",
        import_path="core.modules.collab_project",
        class_name="ProjectManager",
        backend_only=True,
    ),
    "collab_task": ModuleMeta(
        module_id="collab_task",
        category=ModuleCategory.MANAGEMENT,
        display_name="协作任务",
        description="任务管理",
        import_path="core.modules.collab_task",
        class_name="TaskManager",
        backend_only=True,
    ),
    "collab_chat": ModuleMeta(
        module_id="collab_chat",
        category=ModuleCategory.MANAGEMENT,
        display_name="协作聊天",
        description="团队聊天",
        import_path="core.modules.collab_chat",
        class_name="ChatManager",
        backend_only=True,
    ),
    "collab_dashboard": ModuleMeta(
        module_id="collab_dashboard",
        category=ModuleCategory.MANAGEMENT,
        display_name="协作面板",
        description="团队面板",
        import_path="core.modules.collab_dashboard",
        class_name="DashboardManager",
        backend_only=True,
    ),
    "collab_timeline": ModuleMeta(
        module_id="collab_timeline",
        category=ModuleCategory.MANAGEMENT,
        display_name="协作时间线",
        description="项目时间线",
        import_path="core.modules.collab_timeline",
        class_name="TimelineManager",
        backend_only=True,
    ),
    "collab_sharing": ModuleMeta(
        module_id="collab_sharing",
        category=ModuleCategory.MANAGEMENT,
        display_name="协作共享",
        description="资源共享",
        import_path="core.modules.collab_sharing",
        class_name="CollabSharing",
        backend_only=True,
    ),
    "collab_audit": ModuleMeta(
        module_id="collab_audit",
        category=ModuleCategory.MANAGEMENT,
        display_name="协作审计",
        description="操作审计",
        import_path="core.modules.collab_audit",
        class_name="AuditManager",
        backend_only=True,
    ),

    # ==================== 集群模块 ====================
    "cluster_manager": ModuleMeta(
        module_id="cluster_manager",
        category=ModuleCategory.MANAGEMENT,
        display_name="集群管理",
        description="分布式集群管理",
        import_path="core.modules.cluster_manager",
        class_name="ClusterManager",
        backend_only=True,
    ),
    "cluster_integration": ModuleMeta(
        module_id="cluster_integration",
        category=ModuleCategory.MANAGEMENT,
        display_name="集群集成",
        description="集群任务集成",
        import_path="core.modules.cluster_integration",
        class_name="ClusterIntegration",
        backend_only=True,
    ),
    "cluster_master": ModuleMeta(
        module_id="cluster_master",
        category=ModuleCategory.MANAGEMENT,
        display_name="集群主节点",
        description="主节点调度",
        import_path="core.modules.cluster_master",
        class_name="ClusterMaster",
        backend_only=True,
    ),
    "cluster_worker": ModuleMeta(
        module_id="cluster_worker",
        category=ModuleCategory.MANAGEMENT,
        display_name="集群工作节点",
        description="工作节点执行",
        import_path="core.modules.cluster_worker",
        class_name="ClusterWorker",
        backend_only=True,
    ),
    "cluster_communication": ModuleMeta(
        module_id="cluster_communication",
        category=ModuleCategory.MANAGEMENT,
        display_name="集群通信",
        description="集群节点通信",
        import_path="core.modules.cluster_communication",
        class_name="ClusterCommunicationManager",
        backend_only=True,
    ),

    # ==================== 联邦学习模块 ====================
    "federation_integration": ModuleMeta(
        module_id="federation_integration",
        category=ModuleCategory.AI,
        display_name="联邦集成",
        description="联邦学习集成",
        import_path="core.modules.federation_integration",
        class_name="FederationIntegration",
        backend_only=True,
    ),
    "federation_protocol": ModuleMeta(
        module_id="federation_protocol",
        category=ModuleCategory.AI,
        display_name="联邦协议",
        description="联邦通信协议",
        import_path="core.modules.federation_protocol",
        class_name="FederationProtocol",
        backend_only=True,
    ),
    "federation_security": ModuleMeta(
        module_id="federation_security",
        category=ModuleCategory.AI,
        display_name="联邦安全",
        description="联邦安全机制",
        import_path="core.modules.federation_security",
        class_name="FederationSecurityManager",
        backend_only=True,
    ),
    "federation_sync": ModuleMeta(
        module_id="federation_sync",
        category=ModuleCategory.AI,
        display_name="联邦同步",
        description="联邦数据同步",
        import_path="core.modules.federation_sync",
        class_name="FederationSyncEngine",
        backend_only=True,
    ),
    "federation_offline": ModuleMeta(
        module_id="federation_offline",
        category=ModuleCategory.AI,
        display_name="联邦离线",
        description="离线联邦模式",
        import_path="core.modules.federation_offline",
        class_name="FederationOffline",
        backend_only=True,
    ),
    "federation_cdn_p2p": ModuleMeta(
        module_id="federation_cdn_p2p",
        category=ModuleCategory.AI,
        display_name="联邦CDN/P2P",
        description="CDN与P2P分发",
        import_path="core.modules.federation_cdn_p2p",
        class_name="CDNManager",
        backend_only=True,
    ),
    "federation_registry": ModuleMeta(
        module_id="federation_registry",
        category=ModuleCategory.AI,
        display_name="联邦注册",
        description="联邦节点注册",
        import_path="core.modules.federation_registry",
        class_name="FederationRegistry",
        backend_only=True,
    ),

    # ==================== IoT模块 ====================
    "iot_modbus_scanner": ModuleMeta(
        module_id="iot_modbus_scanner",
        category=ModuleCategory.NETWORK,
        display_name="Modbus扫描",
        description="Modbus协议扫描",
        import_path="core.modules.iot_modbus_scanner",
        class_name="ModbusScanner",
        backend_only=True,
    ),
    "iot_coap_scanner": ModuleMeta(
        module_id="iot_coap_scanner",
        category=ModuleCategory.NETWORK,
        display_name="CoAP扫描",
        description="CoAP协议扫描",
        import_path="core.modules.iot_coap_scanner",
        class_name="CoAPScanner",
        backend_only=True,
    ),
    "iot_mqtt_scanner": ModuleMeta(
        module_id="iot_mqtt_scanner",
        category=ModuleCategory.NETWORK,
        display_name="MQTT扫描",
        description="MQTT协议扫描",
        import_path="core.modules.iot_mqtt_scanner",
        class_name="MQTTScanner",
        backend_only=True,
    ),

    # ==================== 知识图谱模块 ====================
    "knowledge_graph_integration": ModuleMeta(
        module_id="knowledge_graph_integration",
        category=ModuleCategory.AI,
        display_name="知识图谱",
        description="知识图谱集成",
        import_path="core.modules.knowledge_graph_integration",
        class_name="KnowledgeGraphIntegration",
        gui_tab_label="知识图谱",
        gui_tab_order=65,
    ),
    "knowledge_graph_builder": ModuleMeta(
        module_id="knowledge_graph_builder",
        category=ModuleCategory.AI,
        display_name="知识图谱构建",
        description="知识图谱构建引擎",
        import_path="core.modules.knowledge_graph_builder",
        class_name="KnowledgeGraphBuilder",
        backend_only=True,
    ),
    "knowledge_graph_query": ModuleMeta(
        module_id="knowledge_graph_query",
        category=ModuleCategory.AI,
        display_name="知识图谱查询",
        description="知识图谱查询引擎",
        import_path="core.modules.knowledge_graph_query",
        class_name="KnowledgeGraphQueryEngine",
        backend_only=True,
    ),
    "knowledge_graph_model": ModuleMeta(
        module_id="knowledge_graph_model",
        category=ModuleCategory.AI,
        display_name="知识图谱模型",
        description="知识图谱数据模型",
        import_path="core.modules.knowledge_graph_model",
        class_name="KnowledgeGraphModel",
        backend_only=True,
    ),
    "knowledge_graph_snapshot": ModuleMeta(
        module_id="knowledge_graph_snapshot",
        category=ModuleCategory.AI,
        display_name="知识图谱快照",
        description="知识图谱快照管理",
        import_path="core.modules.knowledge_graph_snapshot",
        class_name="KnowledgeGraphSnapshotManager",
        backend_only=True,
    ),
    "knowledge_graph_visualizer": ModuleMeta(
        module_id="knowledge_graph_visualizer",
        category=ModuleCategory.AI,
        display_name="知识图谱可视化",
        description="知识图谱可视化",
        import_path="core.modules.knowledge_graph_visualizer",
        class_name="KnowledgeGraphVisualizer",
        backend_only=True,
    ),

    # ==================== 导出模块 ====================
    "export_manager": ModuleMeta(
        module_id="export_manager",
        category=ModuleCategory.REPORT,
        display_name="导出管理",
        description="多格式导出管理",
        import_path="core.modules.export_manager",
        class_name="ExportManager",
        backend_only=True,
    ),
    "export_integration": ModuleMeta(
        module_id="export_integration",
        category=ModuleCategory.REPORT,
        display_name="导出集成",
        description="导出功能集成",
        import_path="core.modules.export_integration",
        class_name="ExportIntegration",
        backend_only=True,
    ),
    "har_exporter": ModuleMeta(
        module_id="har_exporter",
        category=ModuleCategory.REPORT,
        display_name="HAR导出",
        description="HAR格式流量导出",
        import_path="core.modules.har_exporter",
        class_name="HARExporter",
        backend_only=True,
    ),
    "pcap_exporter": ModuleMeta(
        module_id="pcap_exporter",
        category=ModuleCategory.REPORT,
        display_name="PCAP导出",
        description="PCAP流量导出",
        import_path="core.modules.pcap_exporter",
        class_name="PCAPExporter",
        backend_only=True,
    ),

    # ==================== 企业集成模块 ====================
    "enterprise_integration": ModuleMeta(
        module_id="enterprise_integration",
        category=ModuleCategory.MANAGEMENT,
        display_name="企业集成",
        description="SIEM/SOAR/SAST/DAST集成",
        import_path="core.modules.enterprise_integration",
        class_name="EnterpriseIntegrationManager",
        backend_only=True,
    ),
    "enterprise_template_manager": ModuleMeta(
        module_id="enterprise_template_manager",
        category=ModuleCategory.MANAGEMENT,
        display_name="企业模板",
        description="企业测试模板管理",
        import_path="core.modules.enterprise_template_manager",
        class_name="EnterpriseTemplateManager",
        backend_only=True,
    ),
    "attack_chain_template": ModuleMeta(
        module_id="attack_chain_template",
        category=ModuleCategory.ATTACK,
        display_name="攻击链模板",
        description="攻击链模板库",
        import_path="core.modules.attack_chain_template",
        class_name="AttackChainTemplate",
        backend_only=True,
    ),

    # ==================== ATT&CK模块 ====================
    "attck_integration": ModuleMeta(
        module_id="attck_integration",
        category=ModuleCategory.MANAGEMENT,
        display_name="ATT&CK集成",
        description="MITRE ATT&CK框架集成",
        import_path="core.modules.attck_integration",
        class_name="AttckIntegration",
        backend_only=True,
    ),
    "attck_mapper": ModuleMeta(
        module_id="attck_mapper",
        category=ModuleCategory.MANAGEMENT,
        display_name="ATT&CK映射",
        description="攻击技术映射到ATT&CK",
        import_path="core.modules.attck_mapper",
        class_name="AttckMapper",
        backend_only=True,
    ),
    "attck_visualizer": ModuleMeta(
        module_id="attck_visualizer",
        category=ModuleCategory.MANAGEMENT,
        display_name="ATT&CK可视化",
        description="ATT&CK矩阵可视化",
        import_path="core.modules.attck_visualizer",
        class_name="AttckVisualizer",
        backend_only=True,
    ),
    "attck_techniques_db": ModuleMeta(
        module_id="attck_techniques_db",
        category=ModuleCategory.MANAGEMENT,
        display_name="ATT&CK技术库",
        description="ATT&CK技术数据库",
        import_path="core.modules.attck_techniques_db",
        class_name="AttckTechniquesDB",
        backend_only=True,
    ),

    # ==================== 学习路径模块 ====================
    "learning_path": ModuleMeta(
        module_id="learning_path",
        category=ModuleCategory.AI,
        display_name="学习路径",
        description="渗透测试学习路径",
        import_path="core.modules.learning_path",
        class_name="LearningPathManager",
        backend_only=True,
    ),

    # ==================== OOB检测模块 ====================
    "oob_detector": ModuleMeta(
        module_id="oob_detector",
        category=ModuleCategory.ATTACK,
        display_name="OOB检测",
        description="带外数据检测",
        import_path="core.modules.oob_detector",
        class_name="OOBManager",
        backend_only=True,
    ),

    # ==================== HTTP/3模块 ====================
    "http3_proxy": ModuleMeta(
        module_id="http3_proxy",
        category=ModuleCategory.NETWORK,
        display_name="HTTP/3代理",
        description="HTTP/3/QUIC代理",
        import_path="core.modules.http3_proxy",
        class_name="HTTP3Proxy",
        backend_only=True,
    ),
    "http3_frames": ModuleMeta(
        module_id="http3_frames",
        category=ModuleCategory.NETWORK,
        display_name="HTTP/3帧解析",
        description="HTTP/3帧解析引擎",
        import_path="core.modules.http3_frames",
        class_name="HTTP3Frames",
        backend_only=True,
    ),

    # ==================== 移动安全模块 ====================
    "mobile_apk_parser": ModuleMeta(
        module_id="mobile_apk_parser",
        category=ModuleCategory.ATTACK,
        display_name="APK解析",
        description="Android APK解析",
        import_path="core.modules.mobile_apk_parser",
        class_name="MobileApkParser",
        backend_only=True,
    ),
    "mobile_ipa_parser": ModuleMeta(
        module_id="mobile_ipa_parser",
        category=ModuleCategory.ATTACK,
        display_name="IPA解析",
        description="iOS IPA解析",
        import_path="core.modules.mobile_ipa_parser",
        class_name="MobileIpaParser",
        backend_only=True,
    ),
    "mobile_sensitive_detector": ModuleMeta(
        module_id="mobile_sensitive_detector",
        category=ModuleCategory.ATTACK,
        display_name="移动端敏感检测",
        description="移动端敏感信息检测",
        import_path="core.modules.mobile_sensitive_detector",
        class_name="MobileSensitiveDetector",
        backend_only=True,
    ),
    "mobile_iot_integration": ModuleMeta(
        module_id="mobile_iot_integration",
        category=ModuleCategory.ATTACK,
        display_name="移动/IoT集成",
        description="移动与IoT安全集成",
        import_path="core.modules.mobile_iot_integration",
        class_name="MobileIoTIntegration",
        backend_only=True,
    ),
    # ==================== 新增模块注册 ====================
    "asset_manager": ModuleMeta(
        module_id="asset_manager",
        category=ModuleCategory.MANAGEMENT,
        display_name="资产管理",
        description="资产管理模块",
        import_path="core.modules.asset_manager",
        class_name="AssetModule",
        gui_tab_label="资产管理",
        gui_tab_order=274,
        cli_commands=["asset"],
        backend_only=False,
    ),
    "extender": ModuleMeta(
        module_id="extender",
        category=ModuleCategory.EXTENSION,
        display_name="扩展器",
        description="Burp扩展器兼容模块",
        import_path="core.modules.extender",
        class_name="ExtenderModule",
        gui_tab_label="扩展器",
        gui_tab_order=290,
        cli_commands=[],
        backend_only=False,
    ),
    "fingerprint_matcher": ModuleMeta(
        module_id="fingerprint_matcher",
        category=ModuleCategory.ANALYSIS,
        display_name="指纹匹配",
        description="指纹匹配器",
        import_path="core.modules.fingerprint_matcher",
        class_name="FingerprintMatcher",
        gui_tab_label="指纹匹配",
        gui_tab_order=291,
        cli_commands=[],
        backend_only=True,
    ),
    "malleable_profile": ModuleMeta(
        module_id="malleable_profile",
        category=ModuleCategory.ATTACK,
        display_name="Malleable Profile",
        description="Malleable C2 Profile管理",
        import_path="core.modules.malleable_profile",
        class_name="MalleableProfile",
        gui_tab_label="Malleable",
        gui_tab_order=292,
        cli_commands=[],
        backend_only=True,
    ),
    "mitm_diagnostics": ModuleMeta(
        module_id="mitm_diagnostics",
        category=ModuleCategory.NETWORK,
        display_name="MITM诊断",
        description="MITM代理诊断工具",
        import_path="core.modules.mitm_diagnostics",
        class_name="MITMDiagnosticsModule",
        gui_tab_label="MITM诊断",
        gui_tab_order=201,
        cli_commands=[],
        backend_only=True,
    ),
    "mitm_fuzzer_integration": ModuleMeta(
        module_id="mitm_fuzzer_integration",
        category=ModuleCategory.NETWORK,
        display_name="MITM模糊测试",
        description="MITM代理模糊测试集成",
        import_path="core.modules.mitm_fuzzer_integration",
        class_name="MITMFuzzerIntegration",
        gui_tab_label="MITM模糊测试",
        gui_tab_order=202,
        cli_commands=[],
        backend_only=True,
    ),
    "mitm_h2_advanced": ModuleMeta(
        module_id="mitm_h2_advanced",
        category=ModuleCategory.NETWORK,
        display_name="HTTP/2高级",
        description="HTTP/2协议高级功能",
        import_path="core.modules.mitm_h2_advanced",
        class_name="MITMH2Advanced",
        gui_tab_label="HTTP/2高级",
        gui_tab_order=203,
        cli_commands=[],
        backend_only=True,
    ),
    "mitm_h3_advanced": ModuleMeta(
        module_id="mitm_h3_advanced",
        category=ModuleCategory.NETWORK,
        display_name="HTTP/3高级",
        description="HTTP/3/QUIC协议高级功能",
        import_path="core.modules.mitm_h3_advanced",
        class_name="MITMH3Advanced",
        gui_tab_label="HTTP/3高级",
        gui_tab_order=204,
        cli_commands=[],
        backend_only=True,
    ),
    "mitm_lateral_movement": ModuleMeta(
        module_id="mitm_lateral_movement",
        category=ModuleCategory.NETWORK,
        display_name="MITM横向移动",
        description="MITM代理横向移动协议",
        import_path="core.modules.mitm_lateral_movement",
        class_name="MITMLateralMovement",
        gui_tab_label="MITM横向移动",
        gui_tab_order=205,
        cli_commands=[],
        backend_only=True,
    ),
    "mitm_mobile_support": ModuleMeta(
        module_id="mitm_mobile_support",
        category=ModuleCategory.NETWORK,
        display_name="MITM移动端",
        description="MITM代理移动端支持",
        import_path="core.modules.mitm_mobile_support",
        class_name="MITMMobileSupport",
        gui_tab_label="MITM移动端",
        gui_tab_order=206,
        cli_commands=[],
        backend_only=True,
    ),
    "mitm_performance": ModuleMeta(
        module_id="mitm_performance",
        category=ModuleCategory.NETWORK,
        display_name="MITM性能",
        description="MITM代理性能优化",
        import_path="core.modules.mitm_performance",
        class_name="MITMPerformance",
        gui_tab_label="MITM性能",
        gui_tab_order=207,
        cli_commands=[],
        backend_only=True,
    ),
    "mitm_protocol_negotiator": ModuleMeta(
        module_id="mitm_protocol_negotiator",
        category=ModuleCategory.NETWORK,
        display_name="MITM协议协商",
        description="MITM代理协议协商器",
        import_path="core.modules.mitm_protocol_negotiator",
        class_name="MITMProtocolNegotiator",
        gui_tab_label="MITM协议协商",
        gui_tab_order=208,
        cli_commands=[],
        backend_only=True,
    ),
    "mitm_replay_fuzzer": ModuleMeta(
        module_id="mitm_replay_fuzzer",
        category=ModuleCategory.NETWORK,
        display_name="MITM重放模糊",
        description="MITM代理重放和模糊测试",
        import_path="core.modules.mitm_replay_fuzzer",
        class_name="MITMReplayFuzzer",
        gui_tab_label="MITM重放模糊",
        gui_tab_order=209,
        cli_commands=[],
        backend_only=True,
    ),
    "mitm_reverse_integration": ModuleMeta(
        module_id="mitm_reverse_integration",
        category=ModuleCategory.NETWORK,
        display_name="MITM逆向集成",
        description="MITM代理逆向工程集成",
        import_path="core.modules.mitm_reverse_integration",
        class_name="MITMReverseIntegration",
        gui_tab_label="MITM逆向集成",
        gui_tab_order=210,
        cli_commands=[],
        backend_only=True,
    ),
    "mitm_reverse_linkage": ModuleMeta(
        module_id="mitm_reverse_linkage",
        category=ModuleCategory.NETWORK,
        display_name="MITM逆向联动",
        description="MITM代理逆向联动协议",
        import_path="core.modules.mitm_reverse_linkage",
        class_name="MITMReverseLinkage",
        gui_tab_label="MITM逆向联动",
        gui_tab_order=211,
        cli_commands=[],
        backend_only=True,
    ),
    "mitm_security": ModuleMeta(
        module_id="mitm_security",
        category=ModuleCategory.NETWORK,
        display_name="MITM安全",
        description="MITM代理安全模块",
        import_path="core.modules.mitm_security",
        class_name="MITMSecurityModule",
        gui_tab_label="MITM安全",
        gui_tab_order=212,
        cli_commands=[],
        backend_only=True,
    ),
    "mitm_security_audit": ModuleMeta(
        module_id="mitm_security_audit",
        category=ModuleCategory.NETWORK,
        display_name="MITM安全审计",
        description="MITM代理安全审计日志",
        import_path="core.modules.mitm_security_audit",
        class_name="MITMSecurityAudit",
        gui_tab_label="MITM安全审计",
        gui_tab_order=213,
        cli_commands=[],
        backend_only=True,
    ),
    "mitm_traffic_collaboration": ModuleMeta(
        module_id="mitm_traffic_collaboration",
        category=ModuleCategory.NETWORK,
        display_name="MITM流量协作",
        description="MITM代理流量协作标记",
        import_path="core.modules.mitm_traffic_collaboration",
        class_name="MITMTrafficCollaboration",
        gui_tab_label="MITM流量协作",
        gui_tab_order=214,
        cli_commands=[],
        backend_only=True,
    ),
    "mitm_vuln_linkage": ModuleMeta(
        module_id="mitm_vuln_linkage",
        category=ModuleCategory.NETWORK,
        display_name="MITM漏洞联动",
        description="MITM代理漏洞联动注入点",
        import_path="core.modules.mitm_vuln_linkage",
        class_name="MITMVulnLinkage",
        gui_tab_label="MITM漏洞联动",
        gui_tab_order=215,
        cli_commands=[],
        backend_only=True,
    ),
    "nuclei_helpers": ModuleMeta(
        module_id="nuclei_helpers",
        category=ModuleCategory.CORE,
        display_name="Nuclei辅助",
        description="Nuclei模板辅助函数",
        import_path="core.modules.nuclei_helpers",
        class_name="NucleiHelpers",
        gui_tab_label="Nuclei辅助",
        gui_tab_order=216,
        cli_commands=[],
        backend_only=True,
    ),
    "nuclei_models": ModuleMeta(
        module_id="nuclei_models",
        category=ModuleCategory.CORE,
        display_name="Nuclei模型",
        description="Nuclei数据模型",
        import_path="core.modules.nuclei_models",
        class_name="NucleiModels",
        gui_tab_label="Nuclei模型",
        gui_tab_order=217,
        cli_commands=[],
        backend_only=True,
    ),
    "plugin_debugger": ModuleMeta(
        module_id="plugin_debugger",
        category=ModuleCategory.MANAGEMENT,
        display_name="插件调试",
        description="插件调试器",
        import_path="core.modules.plugin_debugger",
        class_name="PluginDebugger",
        gui_tab_label="插件调试",
        gui_tab_order=218,
        cli_commands=[],
        backend_only=False,
    ),
    "plugin_dependency": ModuleMeta(
        module_id="plugin_dependency",
        category=ModuleCategory.MANAGEMENT,
        display_name="插件依赖",
        description="插件依赖管理",
        import_path="core.modules.plugin_dependency",
        class_name="PluginDependency",
        gui_tab_label="插件依赖",
        gui_tab_order=219,
        cli_commands=[],
        backend_only=True,
    ),
    "plugin_engine": ModuleMeta(
        module_id="plugin_engine",
        category=ModuleCategory.MANAGEMENT,
        display_name="插件引擎",
        description="插件核心引擎",
        import_path="core.modules.plugin_engine",
        class_name="PluginEngine",
        gui_tab_label="插件引擎",
        gui_tab_order=220,
        cli_commands=[],
        backend_only=True,
    ),
    "plugin_management_ui": ModuleMeta(
        module_id="plugin_management_ui",
        category=ModuleCategory.MANAGEMENT,
        display_name="插件管理UI",
        description="插件管理界面",
        import_path="core.modules.plugin_management_ui",
        class_name="PluginManagementModule",
        gui_tab_label="插件管理",
        gui_tab_order=221,
        cli_commands=["plugin"],
        backend_only=False,
    ),
    "plugin_manager": ModuleMeta(
        module_id="plugin_manager",
        category=ModuleCategory.MANAGEMENT,
        display_name="插件管理器",
        description="插件管理器",
        import_path="core.modules.plugin_manager",
        class_name="PluginManagerModule",
        gui_tab_label="插件管理",
        gui_tab_order=222,
        cli_commands=[],
        backend_only=False,
    ),
    "plugin_market": ModuleMeta(
        module_id="plugin_market",
        category=ModuleCategory.MANAGEMENT,
        display_name="插件市场",
        description="插件市场条目",
        import_path="core.modules.plugin_market",
        class_name="PluginMarket",
        gui_tab_label="插件市场",
        gui_tab_order=223,
        cli_commands=[],
        backend_only=False,
    ),
    "plugin_market_ops": ModuleMeta(
        module_id="plugin_market_ops",
        category=ModuleCategory.MANAGEMENT,
        display_name="插件市场运营",
        description="插件市场运营管理",
        import_path="core.modules.plugin_market_ops",
        class_name="PluginMarketOps",
        gui_tab_label="插件运营",
        gui_tab_order=224,
        cli_commands=[],
        backend_only=True,
    ),
    "plugin_sandbox": ModuleMeta(
        module_id="plugin_sandbox",
        category=ModuleCategory.MANAGEMENT,
        display_name="插件沙箱",
        description="插件沙箱执行环境",
        import_path="core.modules.plugin_sandbox",
        class_name="PluginSandbox",
        gui_tab_label="插件沙箱",
        gui_tab_order=225,
        cli_commands=[],
        backend_only=True,
    ),
    "plugin_security": ModuleMeta(
        module_id="plugin_security",
        category=ModuleCategory.MANAGEMENT,
        display_name="插件安全",
        description="插件安全检测",
        import_path="core.modules.plugin_security",
        class_name="PluginSecurity",
        gui_tab_label="插件安全",
        gui_tab_order=226,
        cli_commands=[],
        backend_only=True,
    ),
    "poc_engine": ModuleMeta(
        module_id="poc_engine",
        category=ModuleCategory.ATTACK,
        display_name="PoC引擎",
        description="PoC执行引擎",
        import_path="core.modules.poc_engine",
        class_name="PoCEngine",
        gui_tab_label="PoC引擎",
        gui_tab_order=227,
        cli_commands=[],
        backend_only=True,
    ),
    "poc_verification_manager": ModuleMeta(
        module_id="poc_verification_manager",
        category=ModuleCategory.ATTACK,
        display_name="PoC验证管理",
        description="PoC验证管理器",
        import_path="core.modules.poc_verification_manager",
        class_name="PoCVerificationManager",
        gui_tab_label="PoC验证",
        gui_tab_order=228,
        cli_commands=[],
        backend_only=True,
    ),
    "poc_verification_ui": ModuleMeta(
        module_id="poc_verification_ui",
        category=ModuleCategory.ATTACK,
        display_name="PoC验证UI",
        description="PoC验证界面",
        import_path="core.modules.poc_verification_ui",
        class_name="PoCVerificationModule",
        gui_tab_label="PoC验证",
        gui_tab_order=229,
        cli_commands=[],
        backend_only=False,
    ),
    "pqc_crypto": ModuleMeta(
        module_id="pqc_crypto",
        category=ModuleCategory.ATTACK,
        display_name="后量子加密",
        description="后量子密码学加密",
        import_path="core.modules.pqc_crypto",
        class_name="PQCCrypto",
        gui_tab_label="后量子加密",
        gui_tab_order=230,
        cli_commands=[],
        backend_only=True,
    ),
    "process_mask": ModuleMeta(
        module_id="process_mask",
        category=ModuleCategory.ATTACK,
        display_name="进程伪装",
        description="进程伪装模块",
        import_path="core.modules.process_mask",
        class_name="ProcessMask",
        gui_tab_label="进程伪装",
        gui_tab_order=231,
        cli_commands=[],
        backend_only=True,
    ),
    "profile_generator": ModuleMeta(
        module_id="profile_generator",
        category=ModuleCategory.ATTACK,
        display_name="Profile生成",
        description="C2 Profile生成器",
        import_path="core.modules.profile_generator",
        class_name="ProfileGenerator",
        gui_tab_label="Profile生成",
        gui_tab_order=236,
        cli_commands=[],
        backend_only=True,
    ),
    "profile_ide": ModuleMeta(
        module_id="profile_ide",
        category=ModuleCategory.ATTACK,
        display_name="Profile IDE",
        description="C2 Profile集成开发环境",
        import_path="core.modules.profile_ide",
        class_name="ProfileIDE",
        gui_tab_label="Profile IDE",
        gui_tab_order=237,
        cli_commands=[],
        backend_only=False,
    ),
    "profile_marketplace": ModuleMeta(
        module_id="profile_marketplace",
        category=ModuleCategory.ATTACK,
        display_name="Profile市场",
        description="C2 Profile市场管理",
        import_path="core.modules.profile_marketplace",
        class_name="ProfileMarketplace",
        gui_tab_label="Profile市场",
        gui_tab_order=238,
        cli_commands=[],
        backend_only=False,
    ),
    "profile_tester": ModuleMeta(
        module_id="profile_tester",
        category=ModuleCategory.ATTACK,
        display_name="Profile测试",
        description="C2 Profile测试器",
        import_path="core.modules.profile_tester",
        class_name="ProfileTester",
        gui_tab_label="Profile测试",
        gui_tab_order=239,
        cli_commands=[],
        backend_only=True,
    ),
    "protobuf_decoder": ModuleMeta(
        module_id="protobuf_decoder",
        category=ModuleCategory.ATTACK,
        display_name="Protobuf解码",
        description="Protobuf协议解码器",
        import_path="core.modules.protobuf_decoder",
        class_name="ProtobufDecoder",
        gui_tab_label="Protobuf解码",
        gui_tab_order=240,
        cli_commands=[],
        backend_only=True,
    ),
    "protobuf_schema": ModuleMeta(
        module_id="protobuf_schema",
        category=ModuleCategory.ATTACK,
        display_name="Protobuf模式",
        description="Protobuf模式管理器",
        import_path="core.modules.protobuf_schema",
        class_name="ProtobufSchema",
        gui_tab_label="Protobuf模式",
        gui_tab_order=241,
        cli_commands=[],
        backend_only=True,
    ),
    "quic_connection_pool": ModuleMeta(
        module_id="quic_connection_pool",
        category=ModuleCategory.NETWORK,
        display_name="QUIC连接池",
        description="QUIC连接池管理",
        import_path="core.modules.quic_connection_pool",
        class_name="QuicConnectionPool",
        gui_tab_label="QUIC连接池",
        gui_tab_order=242,
        cli_commands=[],
        backend_only=True,
    ),
    "quic_protocol": ModuleMeta(
        module_id="quic_protocol",
        category=ModuleCategory.NETWORK,
        display_name="QUIC协议栈",
        description="QUIC协议栈实现",
        import_path="core.modules.quic_protocol",
        class_name="QuicProtocolStack",
        gui_tab_label="QUIC协议",
        gui_tab_order=243,
        cli_commands=[],
        backend_only=True,
    ),
    "quic_tls": ModuleMeta(
        module_id="quic_tls",
        category=ModuleCategory.NETWORK,
        display_name="QUIC TLS",
        description="QUIC TLS握手",
        import_path="core.modules.quic_tls",
        class_name="QuicTlsHandshake",
        gui_tab_label="QUIC TLS",
        gui_tab_order=244,
        cli_commands=[],
        backend_only=True,
    ),
    "range_deployer": ModuleMeta(
        module_id="range_deployer",
        category=ModuleCategory.MANAGEMENT,
        display_name="靶场部署",
        description="渗透测试靶场部署",
        import_path="core.modules.range_deployer",
        class_name="RangeDeployer",
        gui_tab_label="靶场部署",
        gui_tab_order=245,
        cli_commands=[],
        backend_only=False,
    ),
    "range_integration": ModuleMeta(
        module_id="range_integration",
        category=ModuleCategory.MANAGEMENT,
        display_name="靶场集成",
        description="渗透测试靶场集成",
        import_path="core.modules.range_integration",
        class_name="RangeIntegration",
        gui_tab_label="靶场集成",
        gui_tab_order=246,
        cli_commands=[],
        backend_only=False,
    ),
    "range_manager": ModuleMeta(
        module_id="range_manager",
        category=ModuleCategory.MANAGEMENT,
        display_name="靶场管理",
        description="渗透测试靶场管理",
        import_path="core.modules.range_manager",
        class_name="RangeManager",
        gui_tab_label="靶场管理",
        gui_tab_order=247,
        cli_commands=[],
        backend_only=False,
    ),
    "rasp_waf_bypass": ModuleMeta(
        module_id="rasp_waf_bypass",
        category=ModuleCategory.ATTACK,
        display_name="RASP/WAF绕过",
        description="RASP和WAF绕过技术",
        import_path="core.modules.rasp_waf_bypass",
        class_name="RASPWAFBypass",
        gui_tab_label="RASP绕过",
        gui_tab_order=248,
        cli_commands=[],
        backend_only=True,
    ),
    "report_generator": ModuleMeta(
        module_id="report_generator",
        category=ModuleCategory.REPORT,
        display_name="报告生成",
        description="渗透测试报告生成器",
        import_path="core.modules.report_generator",
        class_name="ReportGenerator",
        gui_tab_label="报告生成",
        gui_tab_order=256,
        cli_commands=[],
        backend_only=False,
    ),
    "result_models": ModuleMeta(
        module_id="result_models",
        category=ModuleCategory.REPORT,
        display_name="结果模型",
        description="扫描结果数据模型",
        import_path="core.modules.result_models",
        class_name="ResultModels",
        gui_tab_label="结果模型",
        gui_tab_order=257,
        cli_commands=[],
        backend_only=True,
    ),
    "sandbox_executor": ModuleMeta(
        module_id="sandbox_executor",
        category=ModuleCategory.ATTACK,
        display_name="沙箱执行",
        description="沙箱执行器",
        import_path="core.modules.sandbox_executor",
        class_name="SandboxExecutor",
        gui_tab_label="沙箱执行",
        gui_tab_order=258,
        cli_commands=[],
        backend_only=True,
    ),
    "scanner": ModuleMeta(
        module_id="scanner",
        category=ModuleCategory.ATTACK,
        display_name="扫描器",
        description="漏洞扫描器模块",
        import_path="core.modules.scanner",
        class_name="ScannerModule",
        gui_tab_label="扫描器",
        gui_tab_order=259,
        cli_commands=["scan"],
        backend_only=False,
    ),
    "self_destruct": ModuleMeta(
        module_id="self_destruct",
        category=ModuleCategory.ATTACK,
        display_name="自毁机制",
        description="Beacon自毁机制",
        import_path="core.modules.self_destruct",
        class_name="SelfDestruct",
        gui_tab_label="自毁",
        gui_tab_order=232,
        cli_commands=[],
        backend_only=True,
    ),
    "self_healing_c2": ModuleMeta(
        module_id="self_healing_c2",
        category=ModuleCategory.ATTACK,
        display_name="C2自愈",
        description="C2通信自愈管理",
        import_path="core.modules.self_healing_c2",
        class_name="SelfHealingC2",
        gui_tab_label="C2自愈",
        gui_tab_order=233,
        cli_commands=[],
        backend_only=True,
    ),
    "session_mfa_bypass": ModuleMeta(
        module_id="session_mfa_bypass",
        category=ModuleCategory.ATTACK,
        display_name="会话/MFA绕过",
        description="会话和MFA绕过管理",
        import_path="core.modules.session_mfa_bypass",
        class_name="SessionMFABypass",
        gui_tab_label="MFA绕过",
        gui_tab_order=249,
        cli_commands=[],
        backend_only=True,
    ),
    "shadow_credentials": ModuleMeta(
        module_id="shadow_credentials",
        category=ModuleCategory.ATTACK,
        display_name="影子凭证",
        description="Active Directory影子凭证攻击",
        import_path="core.modules.shadow_credentials",
        class_name="ShadowCredentials",
        gui_tab_label="影子凭证",
        gui_tab_order=250,
        cli_commands=[],
        backend_only=True,
    ),
    "shiro_exploit": ModuleMeta(
        module_id="shiro_exploit",
        category=ModuleCategory.ATTACK,
        display_name="Shiro漏洞",
        description="Apache Shiro漏洞利用",
        import_path="core.modules.shiro_exploit",
        class_name="ShiroExploit",
        gui_tab_label="Shiro漏洞",
        gui_tab_order=251,
        cli_commands=[],
        backend_only=True,
    ),
    "siem_evasion": ModuleMeta(
        module_id="siem_evasion",
        category=ModuleCategory.ATTACK,
        display_name="SIEM绕过",
        description="SIEM检测绕过",
        import_path="core.modules.siem_evasion",
        class_name="SIEMEvasion",
        gui_tab_label="SIEM绕过",
        gui_tab_order=234,
        cli_commands=[],
        backend_only=True,
    ),
    "skeleton_key": ModuleMeta(
        module_id="skeleton_key",
        category=ModuleCategory.ATTACK,
        display_name="万能密钥",
        description="Active Directory万能密钥攻击",
        import_path="core.modules.skeleton_key",
        class_name="SkeletonKey",
        gui_tab_label="万能密钥",
        gui_tab_order=252,
        cli_commands=[],
        backend_only=True,
    ),
    "skill_evaluator": ModuleMeta(
        module_id="skill_evaluator",
        category=ModuleCategory.MANAGEMENT,
        display_name="技能评估",
        description="渗透测试技能评估器",
        import_path="core.modules.skill_evaluator",
        class_name="SkillEvaluator",
        gui_tab_label="技能评估",
        gui_tab_order=260,
        cli_commands=[],
        backend_only=False,
    ),
    "ssp_backdoor": ModuleMeta(
        module_id="ssp_backdoor",
        category=ModuleCategory.ATTACK,
        display_name="SSP后门",
        description="Security Support Provider后门",
        import_path="core.modules.ssp_backdoor",
        class_name="SSPBackdoor",
        gui_tab_label="SSP后门",
        gui_tab_order=253,
        cli_commands=[],
        backend_only=True,
    ),
    "supply_chain_hijack": ModuleMeta(
        module_id="supply_chain_hijack",
        category=ModuleCategory.ATTACK,
        display_name="供应链劫持",
        description="供应链劫持攻击管理",
        import_path="core.modules.supply_chain_hijack",
        class_name="SupplyChainHijack",
        gui_tab_label="供应链劫持",
        gui_tab_order=254,
        cli_commands=[],
        backend_only=True,
    ),
    "swarm_intelligence": ModuleMeta(
        module_id="swarm_intelligence",
        category=ModuleCategory.ATTACK,
        display_name="群体智能",
        description="群体智能C2管理",
        import_path="core.modules.swarm_intelligence",
        class_name="SwarmIntelligence",
        gui_tab_label="群体智能",
        gui_tab_order=235,
        cli_commands=[],
        backend_only=True,
    ),
    "template_ai_generator": ModuleMeta(
        module_id="template_ai_generator",
        category=ModuleCategory.EXTENSION,
        display_name="AI模板生成",
        description="AI模板生成器",
        import_path="core.modules.template_ai_generator",
        class_name="TemplateAIGenerator",
        gui_tab_label="AI模板",
        gui_tab_order=278,
        cli_commands=[],
        backend_only=False,
    ),
    "template_analytics": ModuleMeta(
        module_id="template_analytics",
        category=ModuleCategory.EXTENSION,
        display_name="模板分析",
        description="模板分析器",
        import_path="core.modules.template_analytics",
        class_name="TemplateAnalytics",
        gui_tab_label="模板分析",
        gui_tab_order=279,
        cli_commands=[],
        backend_only=True,
    ),
    "template_audit": ModuleMeta(
        module_id="template_audit",
        category=ModuleCategory.EXTENSION,
        display_name="模板审计",
        description="模板审计器",
        import_path="core.modules.template_audit",
        class_name="TemplateAudit",
        gui_tab_label="模板审计",
        gui_tab_order=280,
        cli_commands=[],
        backend_only=True,
    ),
    "template_commerce": ModuleMeta(
        module_id="template_commerce",
        category=ModuleCategory.EXTENSION,
        display_name="模板商务",
        description="模板商务管理",
        import_path="core.modules.template_commerce",
        class_name="TemplateCommerce",
        gui_tab_label="模板商务",
        gui_tab_order=281,
        cli_commands=[],
        backend_only=False,
    ),
    "template_editor": ModuleMeta(
        module_id="template_editor",
        category=ModuleCategory.EXTENSION,
        display_name="模板编辑",
        description="模板编辑器",
        import_path="core.modules.template_editor",
        class_name="TemplateEditor",
        gui_tab_label="模板编辑",
        gui_tab_order=282,
        cli_commands=[],
        backend_only=False,
    ),
    "template_executor": ModuleMeta(
        module_id="template_executor",
        category=ModuleCategory.EXTENSION,
        display_name="模板执行",
        description="模板执行器",
        import_path="core.modules.template_executor",
        class_name="TemplateExecutor",
        gui_tab_label="模板执行",
        gui_tab_order=283,
        cli_commands=[],
        backend_only=True,
    ),
    "template_incentive": ModuleMeta(
        module_id="template_incentive",
        category=ModuleCategory.EXTENSION,
        display_name="模板激励",
        description="模板激励管理",
        import_path="core.modules.template_incentive",
        class_name="TemplateIncentive",
        gui_tab_label="模板激励",
        gui_tab_order=284,
        cli_commands=[],
        backend_only=True,
    ),
    "template_integration": ModuleMeta(
        module_id="template_integration",
        category=ModuleCategory.EXTENSION,
        display_name="模板集成",
        description="模板集成管理",
        import_path="core.modules.template_integration",
        class_name="TemplateIntegration",
        gui_tab_label="模板集成",
        gui_tab_order=285,
        cli_commands=[],
        backend_only=True,
    ),
    "template_marketplace": ModuleMeta(
        module_id="template_marketplace",
        category=ModuleCategory.EXTENSION,
        display_name="模板市场",
        description="模板市场管理",
        import_path="core.modules.template_marketplace",
        class_name="TemplateMarketplace",
        gui_tab_label="模板市场",
        gui_tab_order=286,
        cli_commands=[],
        backend_only=False,
    ),
    "template_recorder": ModuleMeta(
        module_id="template_recorder",
        category=ModuleCategory.EXTENSION,
        display_name="模板记录",
        description="模板记录器",
        import_path="core.modules.template_recorder",
        class_name="TemplateRecorder",
        gui_tab_label="模板记录",
        gui_tab_order=287,
        cli_commands=[],
        backend_only=True,
    ),
    "template_replay": ModuleMeta(
        module_id="template_replay",
        category=ModuleCategory.EXTENSION,
        display_name="模板重放",
        description="模板重放器",
        import_path="core.modules.template_replay",
        class_name="TemplateReplay",
        gui_tab_label="模板重放",
        gui_tab_order=288,
        cli_commands=[],
        backend_only=True,
    ),
    "template_validator": ModuleMeta(
        module_id="template_validator",
        category=ModuleCategory.EXTENSION,
        display_name="模板验证",
        description="模板验证器",
        import_path="core.modules.template_validator",
        class_name="TemplateValidator",
        gui_tab_label="模板验证",
        gui_tab_order=289,
        cli_commands=[],
        backend_only=True,
    ),
    "test_ai_security": ModuleMeta(
        module_id="test_ai_security",
        category=ModuleCategory.AI,
        display_name="AI安全测试",
        description="AI安全测试模块",
        import_path="core.modules.test_ai_security",
        class_name="TestAiSecurity",
        gui_tab_label="AI安全测试",
        gui_tab_order=261,
        cli_commands=[],
        backend_only=True,
    ),
    "threat_intel": ModuleMeta(
        module_id="threat_intel",
        category=ModuleCategory.ANALYSIS,
        display_name="威胁情报",
        description="威胁情报客户端",
        import_path="core.modules.threat_intel",
        class_name="ThreatIntel",
        gui_tab_label="威胁情报",
        gui_tab_order=262,
        cli_commands=[],
        backend_only=False,
    ),
    "tls_fingerprint": ModuleMeta(
        module_id="tls_fingerprint",
        category=ModuleCategory.NETWORK,
        display_name="TLS指纹",
        description="TLS指纹识别",
        import_path="core.modules.tls_fingerprint",
        class_name="TLSFingerprint",
        gui_tab_label="TLS指纹",
        gui_tab_order=263,
        cli_commands=[],
        backend_only=True,
    ),
    "token_lifecycle": ModuleMeta(
        module_id="token_lifecycle",
        category=ModuleCategory.ATTACK,
        display_name="令牌生命周期",
        description="令牌生命周期管理",
        import_path="core.modules.token_lifecycle",
        class_name="TokenLifecycle",
        gui_tab_label="令牌管理",
        gui_tab_order=264,
        cli_commands=[],
        backend_only=True,
    ),
    "traffic_engine": ModuleMeta(
        module_id="traffic_engine",
        category=ModuleCategory.NETWORK,
        display_name="流量引擎",
        description="C2流量引擎",
        import_path="core.modules.traffic_engine",
        class_name="TrafficEngine",
        gui_tab_label="流量引擎",
        gui_tab_order=265,
        cli_commands=[],
        backend_only=True,
    ),
    "traffic_learner": ModuleMeta(
        module_id="traffic_learner",
        category=ModuleCategory.NETWORK,
        display_name="流量学习",
        description="C2流量学习器",
        import_path="core.modules.traffic_learner",
        class_name="TrafficLearner",
        gui_tab_label="流量学习",
        gui_tab_order=266,
        cli_commands=[],
        backend_only=True,
    ),
    "updater_checker": ModuleMeta(
        module_id="updater_checker",
        category=ModuleCategory.MANAGEMENT,
        display_name="更新检查",
        description="更新检查器",
        import_path="core.modules.updater_checker",
        class_name="UpdaterChecker",
        gui_tab_label="更新检查",
        gui_tab_order=267,
        cli_commands=[],
        backend_only=False,
    ),
    "updater_downloader": ModuleMeta(
        module_id="updater_downloader",
        category=ModuleCategory.MANAGEMENT,
        display_name="更新下载",
        description="更新下载器",
        import_path="core.modules.updater_downloader",
        class_name="UpdaterDownloader",
        gui_tab_label="更新下载",
        gui_tab_order=268,
        cli_commands=[],
        backend_only=False,
    ),
    "updater_installer": ModuleMeta(
        module_id="updater_installer",
        category=ModuleCategory.MANAGEMENT,
        display_name="更新安装",
        description="更新安装器",
        import_path="core.modules.updater_installer",
        class_name="UpdaterInstaller",
        gui_tab_label="更新安装",
        gui_tab_order=269,
        cli_commands=[],
        backend_only=False,
    ),
    "updater_plugin": ModuleMeta(
        module_id="updater_plugin",
        category=ModuleCategory.MANAGEMENT,
        display_name="插件更新",
        description="插件更新管理",
        import_path="core.modules.updater_plugin",
        class_name="UpdaterPlugin",
        gui_tab_label="插件更新",
        gui_tab_order=270,
        cli_commands=[],
        backend_only=False,
    ),
    "updater_ui": ModuleMeta(
        module_id="updater_ui",
        category=ModuleCategory.MANAGEMENT,
        display_name="更新界面",
        description="更新用户界面",
        import_path="core.modules.updater_ui",
        class_name="UpdaterUI",
        gui_tab_label="更新UI",
        gui_tab_order=271,
        cli_commands=[],
        backend_only=False,
    ),
    "updater_version": ModuleMeta(
        module_id="updater_version",
        category=ModuleCategory.MANAGEMENT,
        display_name="版本管理",
        description="版本管理器",
        import_path="core.modules.updater_version",
        class_name="UpdaterVersion",
        gui_tab_label="版本管理",
        gui_tab_order=272,
        cli_commands=[],
        backend_only=True,
    ),
    "vuln_manager": ModuleMeta(
        module_id="vuln_manager",
        category=ModuleCategory.MANAGEMENT,
        display_name="漏洞管理",
        description="漏洞管理模块",
        import_path="core.modules.vuln_manager",
        class_name="VulnerabilityModule",
        gui_tab_label="漏洞管理",
        gui_tab_order=273,
        cli_commands=["vuln"],
        backend_only=False,
    ),
    "weblogic_exploit": ModuleMeta(
        module_id="weblogic_exploit",
        category=ModuleCategory.ATTACK,
        display_name="WebLogic漏洞",
        description="Oracle WebLogic漏洞利用",
        import_path="core.modules.weblogic_exploit",
        class_name="WebLogicExploit",
        gui_tab_label="WebLogic",
        gui_tab_order=255,
        cli_commands=[],
        backend_only=True,
    ),
    "wireless_ble_scanner": ModuleMeta(
        module_id="wireless_ble_scanner",
        category=ModuleCategory.ATTACK,
        display_name="BLE扫描",
        description="蓝牙低功耗扫描器",
        import_path="core.modules.wireless_ble_scanner",
        class_name="WirelessBLEScanner",
        gui_tab_label="BLE扫描",
        gui_tab_order=275,
        cli_commands=[],
        backend_only=True,
    ),
    "workflow_editor": ModuleMeta(
        module_id="workflow_editor",
        category=ModuleCategory.MANAGEMENT,
        display_name="工作流编辑",
        description="工作流编辑器",
        import_path="core.modules.workflow_editor",
        class_name="WorkflowEditor",
        gui_tab_label="工作流编辑",
        gui_tab_order=276,
        cli_commands=[],
        backend_only=False,
    ),
    "workflow_engine": ModuleMeta(
        module_id="workflow_engine",
        category=ModuleCategory.MANAGEMENT,
        display_name="工作流引擎",
        description="工作流执行引擎",
        import_path="core.modules.workflow_engine",
        class_name="WorkflowEngine",
        gui_tab_label="工作流引擎",
        gui_tab_order=277,
        cli_commands=[],
        backend_only=True,
    ),
}


# =============================================================================
# 模块管理器 - 统一管理所有模块的加载与生命周期
# =============================================================================

class ModuleManager:
    """模块管理器

    负责所有模块的加载、初始化、生命周期管理。
    支持延迟加载、依赖解析、热注册。

    Attributes:
        _modules: 已加载的模块实例 {module_id: instance}
        _metas: 模块元信息
        _loaded_ids: 已加载的模块ID集合
        _app: Application单例引用
    """

    def __init__(self):
        self._modules: Dict[str, Any] = {}
        self._metas: Dict[str, ModuleMeta] = dict(_MODULE_REGISTRY)
        self._loaded_ids: set = set()
        self._app = None
        self._lock = threading.RLock()

    def set_application(self, app):
        """设置Application单例引用"""
        self._app = app

    def register_module_meta(self, meta: ModuleMeta):
        """注册新模块元信息（热注册）

        新增模块时调用此方法即可完成对接。

        Args:
            meta: 模块元信息
        """
        with self._lock:
            if meta.module_id in self._metas:
                _logger.warning(f"模块元信息已存在，将被覆盖: {meta.module_id}")
            self._metas[meta.module_id] = meta
            _logger.info(f"模块元信息已注册: {meta.module_id} ({meta.display_name})")

    def get_meta(self, module_id: str) -> Optional[ModuleMeta]:
        """获取模块元信息"""
        return self._metas.get(module_id)

    def get_all_metas(self) -> Dict[str, ModuleMeta]:
        """获取所有模块元信息"""
        return dict(self._metas)

    def get_metas_by_category(self, category: ModuleCategory) -> List[ModuleMeta]:
        """按分类获取模块元信息"""
        return [m for m in self._metas.values() if m.category == category]

    def get_gui_tab_metas(self) -> List[ModuleMeta]:
        """获取需要显示GUI标签的模块（按排序）"""
        tabs = [m for m in self._metas.values()
                if m.gui_tab_label and m.enabled and not m.backend_only]
        tabs.sort(key=lambda m: m.gui_tab_order)
        return tabs

    def load_module(self, module_id: str, **kwargs) -> Optional[Any]:
        """加载指定模块

        支持延迟加载，首次访问时才真正导入和实例化。

        Args:
            module_id: 模块ID
            **kwargs: 传递给模块构造函数的参数

        Returns:
            模块实例，加载失败返回None
        """
        with self._lock:
            if module_id in self._modules:
                return self._modules[module_id]

            meta = self._metas.get(module_id)
            if not meta:
                _logger.error(f"模块元信息不存在: {module_id}")
                return None

            if not meta.enabled:
                _logger.info(f"模块已禁用: {module_id}")
                return None

            try:
                # 解析依赖
                for dep_id in meta.dependencies:
                    if dep_id not in self._modules:
                        self.load_module(dep_id)

                # 动态导入
                if meta.import_path and meta.class_name:
                    import importlib
                    mod = importlib.import_module(meta.import_path)
                    cls = getattr(mod, meta.class_name)
                    instance = self._instantiate_class(cls, meta, **kwargs)
                else:
                    _logger.error(f"模块缺少导入路径或类名: {module_id}")
                    return None

                if instance is None:
                    return None

                self._modules[module_id] = instance
                self._loaded_ids.add(module_id)

                # 注册到Application
                if self._app and hasattr(self._app, 'register_module'):
                    try:
                        self._app.register_module(
                            module_id=module_id,
                            module_instance=instance,
                            dependencies=meta.dependencies,
                            lazy_load=meta.lazy_load,
                        )
                    except Exception as e:
                        _logger.debug(f"注册到Application跳过: {e}")

                _logger.info(f"模块已加载: {module_id} ({meta.display_name})")
                return instance

            except Exception as e:
                _logger.error(f"模块加载失败 [{module_id}]: {e}", exc_info=True)
                return None

    def _instantiate_class(self, cls, meta: ModuleMeta, **kwargs):
        """智能实例化类，自动处理构造函数参数

        策略:
        0. CLI模式下检查是否为QObject子类（需要GUI环境）
        1. 先用提供的 kwargs 尝试
        2. 失败则检查签名，为缺失参数提供 None
        3. 仍失败则尝试无参构造
        """
        try:
            from PySide6.QtCore import QObject
            if issubclass(cls, QObject):
                from PySide6.QtWidgets import QApplication
                if QApplication.instance() is None:
                    _logger.warning(f"模块 [{meta.module_id}] 继承自QObject，需要GUI环境，CLI模式下跳过")
                    return None
        except ImportError:
            pass

        if kwargs:
            try:
                return cls(**kwargs)
            except TypeError:
                pass

        try:
            sig = inspect.signature(cls.__init__)
            params = list(sig.parameters.values())[1:]  # 跳过 self

            resolved = {}
            for p in params:
                if p.name in kwargs:
                    resolved[p.name] = kwargs[p.name]
                elif p.default is not inspect.Parameter.empty:
                    resolved[p.name] = p.default
                else:
                    resolved[p.name] = None

            return cls(**resolved)
        except Exception:
            pass

        try:
            return cls()
        except Exception:
            pass

        _logger.warning(f"无法实例化模块 [{meta.module_id}]，跳过")
        return None

    def load_all(self, **kwargs) -> Dict[str, Any]:
        """加载所有启用的模块"""
        for module_id, meta in self._metas.items():
            if meta.enabled and module_id not in self._modules:
                self.load_module(module_id, **kwargs)
        return dict(self._modules)

    def load_category(self, category: ModuleCategory, **kwargs) -> Dict[str, Any]:
        """加载指定分类的所有模块"""
        loaded = {}
        for meta in self.get_metas_by_category(category):
            instance = self.load_module(meta.module_id, **kwargs)
            if instance:
                loaded[meta.module_id] = instance
        return loaded

    def get_module(self, module_id: str) -> Optional[Any]:
        """获取已加载的模块实例"""
        return self._modules.get(module_id)

    def is_loaded(self, module_id: str) -> bool:
        """检查模块是否已加载"""
        return module_id in self._loaded_ids

    def unload_module(self, module_id: str):
        """卸载模块"""
        with self._lock:
            if module_id in self._modules:
                instance = self._modules[module_id]
                if hasattr(instance, 'close'):
                    try:
                        if asyncio.iscoroutinefunction(instance.close):
                            try:
                                loop = asyncio.get_event_loop()
                                if loop.is_running():
                                    asyncio.ensure_future(instance.close())
                                else:
                                    asyncio.run(instance.close())
                            except RuntimeError:
                                pass
                        else:
                            instance.close()
                    except Exception as e:
                        _logger.error(f"模块关闭失败 [{module_id}]: {e}")

                del self._modules[module_id]
                self._loaded_ids.discard(module_id)
                _logger.info(f"模块已卸载: {module_id}")

    def shutdown_all(self):
        """关闭所有模块"""
        _logger.info("正在关闭所有模块...")
        for module_id in list(self._modules.keys()):
            self.unload_module(module_id)
        _logger.info("所有模块已关闭")

    def get_stats(self) -> Dict[str, Any]:
        """获取模块统计信息"""
        total = len(self._metas)
        loaded = len(self._loaded_ids)
        enabled = sum(1 for m in self._metas.values() if m.enabled)

        by_category = {}
        for cat in ModuleCategory:
            count = sum(1 for m in self._metas.values()
                       if m.category == cat and m.enabled)
            by_category[cat.value] = count

        return {
            "total_registered": total,
            "total_enabled": enabled,
            "total_loaded": loaded,
            "by_category": by_category,
            "loaded_modules": sorted(self._loaded_ids),
        }


# =============================================================================
# 全局模块管理器实例
# =============================================================================
_module_manager = ModuleManager()


def get_module_manager() -> ModuleManager:
    """获取全局模块管理器"""
    return _module_manager


def register_module(meta: ModuleMeta):
    """热注册新模块（供外部调用）

    使用示例:
        >>> from main import register_module, ModuleMeta, ModuleCategory
        >>> meta = ModuleMeta(
        ...     module_id="my_module",
        ...     category=ModuleCategory.EXTENSION,
        ...     display_name="我的模块",
        ...     import_path="plugins.my_module",
        ...     class_name="MyModule",
        ... )
        >>> register_module(meta)
    """
    _module_manager.register_module_meta(meta)


# =============================================================================
# KunLunApplication - 应用主控类
# =============================================================================

class KunLunApplication:
    """昆仑应用主控

    统一管理 Application 单例、模块管理器、GUI窗口。
    支持 GUI 和 CLI 双模式。

    Attributes:
        app_singleton: Application单例
        module_manager: 模块管理器
        gui_app: QApplication实例（GUI模式）
        main_window: 主窗口实例（GUI模式）
        mode: 运行模式 (gui/cli)
    """

    def __init__(self, mode: str = "gui"):
        self.mode = mode
        self.app_singleton = None
        self.module_manager = _module_manager
        self.gui_app = None
        self.main_window = None
        self._initialized = False
        self._shutdown_requested = False

    def initialize_backend(self, config_path: Optional[str] = None):
        """初始化后端核心

        加载 Application 单例、配置、数据库、事件总线。

        Args:
            config_path: 配置文件路径
        """
        if self._initialized:
            return

        _logger.info("=" * 60)
        _logger.info("昆仑安全测试平台 Pro - 初始化后端核心")
        _logger.info("=" * 60)

        try:
            from core.application import Application, initialize_app

            project_root = str(_PROJECT_ROOT)
            self.app_singleton = initialize_app(project_root=project_root)
            self.module_manager.set_application(self.app_singleton)

            _logger.info(f"项目根目录: {project_root}")
            _logger.info(f"数据库路径: {_PROJECT_ROOT / 'data' / 'app.db'}")
            _logger.info("后端核心初始化完成")

            self._initialized = True

        except Exception as e:
            _logger.error(f"后端初始化失败: {e}", exc_info=True)
            raise

    def initialize_modules(self, lazy: bool = True):
        """初始化所有模块

        Args:
            lazy: 是否延迟加载（GUI模式下推荐True）
        """
        if not self._initialized:
            self.initialize_backend()

        _logger.info("正在注册模块...")

        if not lazy:
            # CLI模式：加载纯后端模块 + 核心模块（即使有GUI标签也有后端功能）
            for meta in self.module_manager.get_all_metas().values():
                if not meta.enabled:
                    continue
                if self.mode == "cli":
                    if meta.backend_only or meta.category == ModuleCategory.CORE:
                        self.module_manager.load_module(meta.module_id)
                else:
                    self.module_manager.load_module(meta.module_id)
        else:
            # GUI模式：只预加载核心后端模块
            for meta in self.module_manager.get_metas_by_category(ModuleCategory.CORE):
                if meta.enabled:
                    self.module_manager.load_module(meta.module_id)

        stats = self.module_manager.get_stats()
        _logger.info(f"模块统计: {stats['total_loaded']}/{stats['total_enabled']} 已加载")

    def run_gui(self):
        """启动GUI模式"""
        if self.mode != "gui":
            raise RuntimeError("当前不是GUI模式")

        _logger.info("正在启动GUI...")

        from PySide6.QtWidgets import QApplication
        from PySide6.QtCore import Qt

        # 高DPI支持
        if hasattr(Qt, 'AA_EnableHighDpiScaling'):
            QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
        if hasattr(Qt, 'AA_UseHighDpiPixmaps'):
            QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

        self.gui_app = QApplication(sys.argv)
        self.gui_app.setStyle("Fusion")
        self._apply_global_stylesheet()

        # 创建主窗口
        self.main_window = AutoPenTestMainWindow(app=self)
        self.main_window.show()

        # 注册清理
        self.gui_app.aboutToQuit.connect(self._on_gui_quit)

        _logger.info("GUI已启动，进入事件循环")
        sys.exit(self.gui_app.exec())

    def _apply_global_stylesheet(self):
        """应用全局样式表"""
        self.gui_app.setStyleSheet("""
            QMainWindow { background: #2b2b2b; }
            QWidget { background: #2b2b2b; color: #bbbbbb; }
            QGroupBox {
                border: 1px solid #555555;
                border-radius: 4px;
                margin-top: 10px;
                padding-top: 10px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QPushButton {
                background: #3c3c3c;
                color: #bbbbbb;
                border: 1px solid #555555;
                border-radius: 3px;
                padding: 5px 10px;
            }
            QPushButton:hover { background: #4a4a4a; }
            QPushButton:pressed { background: #555555; }
            QLineEdit, QTextEdit, QPlainTextEdit {
                background: #1e1e1e;
                color: #bbbbbb;
                border: 1px solid #555555;
                border-radius: 3px;
                padding: 3px;
            }
            QTableWidget, QTreeWidget {
                background: #1e1e1e;
                color: #bbbbbb;
                border: 1px solid #555555;
                gridline-color: #3c3c3c;
            }
            QTableWidget::item:selected, QTreeWidget::item:selected {
                background: #094771;
            }
            QHeaderView::section {
                background: #3c3c3c;
                color: #bbbbbb;
                border: 1px solid #555555;
                padding: 4px;
            }
            QComboBox {
                background: #1e1e1e;
                color: #bbbbbb;
                border: 1px solid #555555;
                border-radius: 3px;
                padding: 3px;
            }
            QComboBox::drop-down { border: none; }
            QComboBox::down-arrow { image: none; border: none; }
            QScrollBar:vertical {
                background: #2b2b2b;
                width: 12px;
                border: 1px solid #555555;
            }
            QScrollBar::handle:vertical {
                background: #555555;
                min-height: 20px;
                border-radius: 3px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                background: none;
                border: none;
            }
            QStatusBar {
                background: #3c3c3c;
                color: #bbbbbb;
                border-top: 1px solid #555555;
            }
        """)

    def _on_gui_quit(self):
        """GUI退出时的清理"""
        _logger.info("GUI正在退出...")
        self.shutdown()

    async def run_cli_async(self, args: argparse.Namespace):
        """异步CLI模式入口

        Args:
            args: 解析后的命令行参数
        """
        _logger.info("CLI模式启动")

        if args.command == "nuclei":
            await self._cli_nuclei(args)
        elif args.command == "scan":
            await self._cli_scan(args)
        elif args.command == "fingerprint":
            await self._cli_fingerprint(args)
        elif args.command == "stats":
            self._cli_stats()
        elif args.command == "modules":
            self._cli_list_modules()
        else:
            _logger.error(f"未知命令: {args.command}")

    async def _cli_nuclei(self, args: argparse.Namespace):
        """CLI: Nuclei命令处理"""
        from core.modules.nuclei_executor import NucleiExecutor

        executor = NucleiExecutor(
            templates_dir=args.templates_dir or str(_PROJECT_ROOT / "templates" / "nuclei"),
            timeout=args.timeout,
            max_concurrency=args.concurrency,
        )

        try:
            if args.nuclei_action == "update":
                repo_url = args.repo or "https://github.com/projectdiscovery/nuclei-templates.git"
                _logger.info(f"正在从 {repo_url} 更新模板...")
                executor.loader.load_from_git(repo_url, update=True)
                print(f"模板更新完成")

            elif args.nuclei_action == "search":
                keyword = args.keyword
                results = executor.loader.search(keyword)
                print(f"\n搜索 '{keyword}' 结果 ({len(results)} 条):")
                print("-" * 60)
                for t in results[:20]:
                    print(f"  [{t.info.severity.value.upper()}] {t.id}")
                    print(f"    名称: {t.info.name}")
                    print(f"    标签: {', '.join(t.info.tags[:5])}")
                    print()

            elif args.nuclei_action == "stats":
                stats = executor.loader.stats
                print("\nNuclei模板统计:")
                print("-" * 40)
                print(f"  模板总数: {stats.total_templates}")
                print(f"  已加载: {stats.loaded_templates}")
                print(f"  失败: {stats.failed_templates}")
                if stats.by_severity:
                    print(f"\n  按严重程度:")
                    for sev, count in stats.by_severity.items():
                        print(f"    {sev}: {count}")
                if stats.by_protocol:
                    print(f"\n  按协议:")
                    for proto, count in stats.by_protocol.items():
                        print(f"    {proto}: {count}")

            elif args.nuclei_action == "validate":
                path = args.path
                try:
                    import yaml
                    with open(path, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                    template_id = data.get("id", "N/A")
                    print(f"✓ 模板有效: {template_id}")
                    print(f"  名称: {data.get('info', {}).get('name', 'N/A')}")
                    print(f"  严重程度: {data.get('info', {}).get('severity', 'N/A')}")
                except Exception as e:
                    print(f"✗ 模板无效: {e}")

            elif args.nuclei_action == "test":
                template_id = args.template_id
                target = args.url
                template = executor.loader.get_template(template_id)
                if not template:
                    print(f"模板不存在: {template_id}")
                    return
                result = await executor.execute(template, target)
                print(f"\n测试结果: {template_id}")
                print("-" * 40)
                print(f"  目标: {target}")
                print(f"  漏洞: {'是' if result.vulnerable else '否'}")
                print(f"  匹配: {'是' if result.matched else '否'}")
                if result.evidence:
                    print(f"  证据: {result.evidence[:200]}")
                print(f"  耗时: {result.response_time:.2f}s")

        finally:
            await executor.close()

    async def _cli_scan(self, args: argparse.Namespace):
        """CLI: 主动扫描"""
        _logger.info(f"开始扫描: {args.target}")
        print(f"扫描功能开发中... 目标: {args.target}")

    async def _cli_fingerprint(self, args: argparse.Namespace):
        """CLI: 指纹识别"""
        _logger.info(f"指纹识别: {args.target}")
        print(f"指纹识别功能开发中... 目标: {args.target}")

    def _cli_stats(self):
        """CLI: 显示统计信息"""
        stats = self.module_manager.get_stats()
        print("\n昆仑平台统计:")
        print("=" * 40)
        print(f"  注册模块总数: {stats['total_registered']}")
        print(f"  已启用模块:   {stats['total_enabled']}")
        print(f"  已加载模块:   {stats['total_loaded']}")
        print(f"\n  按分类统计:")
        for cat, count in stats['by_category'].items():
            print(f"    {cat}: {count}")
        print(f"\n  已加载模块列表:")
        for mid in stats['loaded_modules']:
            meta = self.module_manager.get_meta(mid)
            if meta:
                print(f"    [{meta.category.value}] {mid} - {meta.display_name}")

    def _cli_list_modules(self):
        """CLI: 列出所有模块"""
        print("\n已注册模块列表:")
        print("=" * 80)
        print(f"{'ID':<25} {'分类':<12} {'显示名称':<20} {'状态':<8}")
        print("-" * 80)
        for mid, meta in sorted(self.module_manager.get_all_metas().items()):
            status = "已加载" if self.module_manager.is_loaded(mid) else ("已禁用" if not meta.enabled else "未加载")
            print(f"{mid:<25} {meta.category.value:<12} {meta.display_name:<20} {status:<8}")

    def shutdown(self):
        """关闭应用"""
        if self._shutdown_requested:
            return
        self._shutdown_requested = True

        _logger.info("正在关闭昆仑平台...")

        self.module_manager.shutdown_all()

        if self.app_singleton and hasattr(self.app_singleton, 'shutdown'):
            try:
                self.app_singleton.shutdown()
            except Exception as e:
                _logger.error(f"Application关闭失败: {e}")

        _logger.info("昆仑平台已关闭")


# =============================================================================
# GUI组件 - 从原main.py保留
# =============================================================================

# 延迟导入PySide6，CLI模式下不需要
_HAS_PYSIDE6 = False
try:
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QStackedWidget,
        QVBoxLayout, QHBoxLayout, QWidget, QLayout,
        QMenuBar, QMenu, QStatusBar,
        QMessageBox, QToolBar, QLabel,
        QSplitter, QDockWidget, QPushButton,
        QGroupBox, QFormLayout, QComboBox,
        QLineEdit, QTextBrowser, QTableWidget,
        QTableWidgetItem, QHeaderView, QCheckBox,
        QSpinBox, QFrame, QTreeWidget, QTreeWidgetItem,
        QTextEdit, QFileDialog, QScrollArea,
        QToolButton, QSizePolicy, QLayoutItem,
    )
    from PySide6.QtCore import Qt, QTimer, QRect, QSize, Signal, QPoint
    from PySide6.QtGui import QAction, QIcon, QFont
    _HAS_PYSIDE6 = True
except ImportError:
    pass


if _HAS_PYSIDE6:

    class FlowLayout(QLayout):
        """流式布局 - 自动换行"""

        def __init__(self, parent=None, margin=2, h_spacing=2, v_spacing=2):
            super().__init__(parent)
            self._item_list = []
            self._h_space = h_spacing
            self._v_space = v_spacing
            self.setContentsMargins(margin, margin, margin, margin)

        def __del__(self):
            item = self.takeAt(0)
            while item:
                item = self.takeAt(0)

        def addItem(self, item):
            self._item_list.append(item)

        def addWidget(self, widget):
            if self.parentWidget():
                widget.setParent(self.parentWidget())
            self.addItem(QWidgetItem(widget))

        def horizontalSpacing(self):
            return self._h_space

        def verticalSpacing(self):
            return self._v_space

        def count(self):
            return len(self._item_list)

        def itemAt(self, index):
            if 0 <= index < len(self._item_list):
                return self._item_list[index]
            return None

        def takeAt(self, index):
            if 0 <= index < len(self._item_list):
                return self._item_list.pop(index)
            return None

        def expandingDirections(self):
            return Qt.Orientations(0)

        def hasHeightForWidth(self):
            return True

        def heightForWidth(self, width):
            return self._do_layout(QRect(0, 0, width, 0), True)

        def setGeometry(self, rect):
            super().setGeometry(rect)
            self._do_layout(rect, False)

        def sizeHint(self):
            return self.minimumSize()

        def minimumSize(self):
            size = QSize()
            for item in self._item_list:
                sz = item.sizeHint()
                size = size.expandedTo(sz)
            margins = self.contentsMargins()
            size += QSize(margins.left() + margins.right(), margins.top() + margins.bottom())
            return size

        def _do_layout(self, rect, test_only):
            x = rect.x()
            y = rect.y()
            line_height = 0

            for item in self._item_list:
                widget = item.widget()
                if widget and not widget.isVisible():
                    continue

                sz = item.sizeHint()
                if sz.width() <= 0:
                    sz = QSize(80, 28)

                space_x = self._h_space
                space_y = self._v_space
                next_x = x + sz.width() + space_x

                if next_x - space_x > rect.right() and line_height > 0:
                    x = rect.x()
                    y = y + line_height + space_y
                    next_x = x + sz.width() + space_x
                    line_height = 0

                if not test_only:
                    item.setGeometry(QRect(QPoint(x, y), sz))

                x = next_x
                line_height = max(line_height, sz.height())

            return y + line_height - rect.y()


    class QWidgetItem(QLayoutItem):
        """Widget布局项"""

        def __init__(self, widget):
            super().__init__()
            self._widget = widget

        def widget(self):
            return self._widget

        def sizeHint(self):
            if self._widget:
                return self._widget.sizeHint()
            return QSize()

        def minimumSize(self):
            if self._widget:
                return self._widget.minimumSizeHint()
            return QSize()

        def setGeometry(self, rect):
            if self._widget:
                self._widget.setGeometry(rect)

        def isEmpty(self):
            return self._widget is None


    class FlowTabBar(QWidget):
        """支持多行自动换行的标签导航栏"""

        currentChanged = Signal(int)

        def __init__(self, parent=None):
            super().__init__(parent)
            self._buttons = []
            self._current_index = -1
            self._tab_names = []

            self._wrapper = QWidget(self)
            self._flow_layout = FlowLayout(self._wrapper, margin=2, h_spacing=2, v_spacing=2)
            self._wrapper.setLayout(self._flow_layout)

            main_layout = QVBoxLayout(self)
            main_layout.setContentsMargins(0, 0, 0, 0)
            main_layout.setSpacing(0)
            main_layout.addWidget(self._wrapper)

            self.setStyleSheet("""
                QPushButton {
                    background: #3c3c3c;
                    color: #bbbbbb;
                    padding: 5px 12px;
                    border: none;
                    border-right: 1px solid #555555;
                    min-width: 70px;
                    font-size: 12px;
                }
                QPushButton:hover {
                    background: #4a4a4a;
                }
                QPushButton:checked {
                    background: #555555;
                    color: #ffffff;
                    font-weight: bold;
                }
            """)

        def sizeHint(self):
            if not self._buttons:
                return QSize(100, 30)
            width = self.width() if self.width() > 0 else (self.parent().width() if self.parent() else 800)
            height = self._flow_layout.heightForWidth(width)
            return QSize(width, max(height, 30))

        def minimumSizeHint(self):
            if not self._buttons:
                return QSize(100, 30)
            width = self.width() if self.width() > 0 else (self.parent().width() if self.parent() else 800)
            height = self._flow_layout.heightForWidth(width)
            return QSize(width, max(height, 30))

        def resizeEvent(self, event):
            super().resizeEvent(event)
            self._wrapper.resize(event.size())

        def addTab(self, name):
            btn = QPushButton(name)
            btn.setCheckable(True)
            btn.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Fixed)
            index = len(self._buttons)
            btn.clicked.connect(lambda checked, idx=index: self._on_button_clicked(idx))
            self._buttons.append(btn)
            self._tab_names.append(name)
            self._flow_layout.addWidget(btn)

            if self._current_index == -1:
                self._current_index = 0
                btn.setChecked(True)

            return len(self._buttons) - 1

        def _on_button_clicked(self, index):
            for i, btn in enumerate(self._buttons):
                btn.setChecked(i == index)
            if self._current_index != index:
                self._current_index = index
                self.currentChanged.emit(index)

        def setCurrentIndex(self, index):
            if 0 <= index < len(self._buttons):
                self._on_button_clicked(index)

        def currentIndex(self):
            return self._current_index

        def count(self):
            return len(self._buttons)

        def tabText(self, index):
            if 0 <= index < len(self._tab_names):
                return self._tab_names[index]
            return ""


    class FlowTabWidget(QWidget):
        """支持多行标签的TabWidget"""

        def __init__(self, parent=None):
            super().__init__(parent)
            self._tab_bar = FlowTabBar(self)
            self._stacked_widget = QStackedWidget(self)
            self._stacked_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

            layout = QVBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(0)
            layout.addWidget(self._tab_bar)
            layout.addWidget(self._stacked_widget, 1)

            self._tab_bar.currentChanged.connect(self._stacked_widget.setCurrentIndex)

        def addTab(self, widget, label):
            index = self._tab_bar.addTab(label)
            self._stacked_widget.addWidget(widget)
            return index

        def setCurrentIndex(self, index):
            self._tab_bar.setCurrentIndex(index)

        def currentIndex(self):
            return self._tab_bar.currentIndex()

        def count(self):
            return self._tab_bar.count()


    class AutoPenTestMainWindow(QMainWindow):
        """主窗口 - 参考Burp Suite设计

        集成所有GUI模块，通过模块管理器动态加载。
        """

        def __init__(self, app: KunLunApplication = None):
            super().__init__()

            self._kunlun_app = app
            self.modules = {}
            self._tab_widgets = {}  # module_id -> tab widget mapping

            self.setWindowTitle("昆仑安全测试平台 Pro v1.0")
            self.resize(1400, 900)

            self.setup_logging()
            self.setup_ui()
            self.setup_menu()
            self.setup_statusbar()

            self.logger.info("昆仑安全测试平台 GUI 已启动")

        def setup_logging(self):
            self.logger = logging.getLogger("KunLun.GUI")

        def setup_ui(self):
            central_widget = QWidget()
            self.setCentralWidget(central_widget)

            main_layout = QVBoxLayout(central_widget)
            main_layout.setContentsMargins(0, 0, 0, 0)
            main_layout.setSpacing(0)

            self.module_tab_widget = FlowTabWidget(self)

            self._init_modules()
            self._add_all_module_tabs()

            main_layout.addWidget(self.module_tab_widget)

        def _init_modules(self):
            """初始化所有GUI功能模块

            通过模块管理器动态加载，支持延迟实例化。
            新增模块只需在 _MODULE_REGISTRY 中注册即可自动出现在GUI中。
            """
            mgr = _module_manager

            # 获取所有需要GUI标签的模块
            gui_metas = mgr.get_gui_tab_metas()

            for meta in gui_metas:
                try:
                    instance = mgr.load_module(meta.module_id)
                    if instance:
                        self.modules[meta.module_id] = instance
                except Exception as e:
                    self.logger.error(f"GUI模块加载失败 [{meta.module_id}]: {e}")

        def _add_all_module_tabs(self):
            """添加所有模块标签页

            按 gui_tab_order 排序，Dashboard始终在第一位。
            """
            # Dashboard
            self.module_tab_widget.addTab(self._create_dashboard_tab(), "Dashboard")

            # 其他模块按排序添加
            mgr = _module_manager
            gui_metas = mgr.get_gui_tab_metas()

            for meta in gui_metas:
                instance = self.modules.get(meta.module_id)
                if not instance:
                    continue

                try:
                    ui = instance.get_ui() if hasattr(instance, 'get_ui') else None
                    if ui:
                        self.module_tab_widget.addTab(ui, meta.gui_tab_label)
                        self._tab_widgets[meta.module_id] = ui
                except Exception as e:
                    self.logger.error(f"添加标签页失败 [{meta.module_id}]: {e}")

        def _create_dashboard_tab(self):
            """创建Dashboard标签页"""
            widget = QWidget()
            layout = QVBoxLayout(widget)
            layout.setContentsMargins(10, 10, 10, 10)

            # 快速操作区域
            quick_group = QGroupBox("快速操作")
            quick_layout = QHBoxLayout(quick_group)

            new_scan_btn = QPushButton("新建扫描")
            new_scan_btn.setStyleSheet(
                "QPushButton { background: #4CAF50; color: white; padding: 8px 16px; border-radius: 4px; }")
            quick_layout.addWidget(new_scan_btn)

            new_task_btn = QPushButton("新建任务")
            new_task_btn.setStyleSheet(
                "QPushButton { background: #2196F3; color: white; padding: 8px 16px; border-radius: 4px; }")
            quick_layout.addWidget(new_task_btn)

            quick_layout.addStretch()
            layout.addWidget(quick_group)

            # 模块概览
            overview_group = QGroupBox("模块概览")
            overview_layout = QVBoxLayout(overview_group)

            self.modules_table = QTableWidget()
            self.modules_table.setColumnCount(4)
            self.modules_table.setHorizontalHeaderLabels(["模块", "分类", "状态", "描述"])
            self.modules_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

            mgr = _module_manager
            all_metas = mgr.get_all_metas()
            self.modules_table.setRowCount(len(all_metas))

            for row, (mid, meta) in enumerate(sorted(all_metas.items())):
                self.modules_table.setItem(row, 0, QTableWidgetItem(meta.display_name))
                self.modules_table.setItem(row, 1, QTableWidgetItem(meta.category.value))
                status = "已加载" if mgr.is_loaded(mid) else ("已禁用" if not meta.enabled else "就绪")
                self.modules_table.setItem(row, 2, QTableWidgetItem(status))
                self.modules_table.setItem(row, 3, QTableWidgetItem(meta.description))

            overview_layout.addWidget(self.modules_table)
            layout.addWidget(overview_group)

            # 事件日志
            event_group = QGroupBox("Event Log")
            event_layout = QVBoxLayout(event_group)

            self.event_log = QTextEdit()
            self.event_log.setReadOnly(True)
            self.event_log.setFont(QFont("Consolas", 9))
            event_layout.addWidget(self.event_log)

            layout.addWidget(event_group)

            return widget

        def setup_menu(self):
            """设置菜单栏"""
            menubar = self.menuBar()
            menubar.setStyleSheet(
                "QMenuBar { background: #2b2b2b; color: #bbbbbb; } "
                "QMenuBar::item { padding: 5px 10px; } "
                "QMenuBar::item:selected { background: #3c3c3c; }"
            )

            # 文件菜单
            file_menu = menubar.addMenu("文件")
            new_project = QAction("新建项目", self)
            new_project.setShortcut("Ctrl+N")
            file_menu.addAction(new_project)

            open_project = QAction("打开项目", self)
            open_project.setShortcut("Ctrl+O")
            file_menu.addAction(open_project)

            save_project = QAction("保存项目", self)
            save_project.setShortcut("Ctrl+S")
            file_menu.addAction(save_project)

            file_menu.addSeparator()

            import_menu = file_menu.addMenu("导入")
            import_menu.addAction(QAction("导入配置", self))
            import_menu.addAction(QAction("导入目标", self))
            import_menu.addAction(QAction("导入PoC", self))
            import_menu.addAction(QAction("导入插件", self))

            export_menu = file_menu.addMenu("导出")
            export_menu.addAction(QAction("导出报告", self))
            export_menu.addAction(QAction("导出配置", self))
            export_menu.addAction(QAction("导出结果", self))

            file_menu.addSeparator()

            exit_action = QAction("退出", self)
            exit_action.setShortcut("Ctrl+Q")
            exit_action.triggered.connect(self.close)
            file_menu.addAction(exit_action)

            # 视图菜单
            view_menu = menubar.addMenu("视图")
            show_toolbar = QAction("显示工具栏", self)
            show_toolbar.setCheckable(True)
            show_toolbar.setChecked(True)
            view_menu.addAction(show_toolbar)

            show_statusbar = QAction("显示状态栏", self)
            show_statusbar.setCheckable(True)
            show_statusbar.setChecked(True)
            view_menu.addAction(show_statusbar)

            view_menu.addSeparator()

            font_size = view_menu.addMenu("字体大小")
            font_size.addAction(QAction("小", self))
            font_size.addAction(QAction("正常", self))
            font_size.addAction(QAction("大", self))

            # 工具菜单
            tools_menu = menubar.addMenu("工具")
            tools_menu.addAction(QAction("主动扫描", self))
            tools_menu.addAction(QAction("爬虫", self))
            tools_menu.addSeparator()
            tools_menu.addAction(QAction("编解码器", self))
            tools_menu.addAction(QAction("对比器", self))
            tools_menu.addSeparator()

            settings_action = QAction("设置", self)
            settings_action.setShortcut("Ctrl+,")
            tools_menu.addAction(settings_action)

            # Nuclei菜单
            nuclei_menu = menubar.addMenu("Nuclei")
            nuclei_update = QAction("更新模板", self)
            nuclei_update.triggered.connect(self._on_nuclei_update)
            nuclei_menu.addAction(nuclei_update)

            nuclei_stats = QAction("模板统计", self)
            nuclei_stats.triggered.connect(self._on_nuclei_stats)
            nuclei_menu.addAction(nuclei_stats)

            nuclei_menu.addSeparator()
            nuclei_menu.addAction(QAction("模板管理", self))

            # 帮助菜单
            help_menu = menubar.addMenu("帮助")
            help_menu.addAction(QAction("文档", self))
            help_menu.addAction(QAction("检查更新", self))

            help_menu.addSeparator()

            about_action = QAction("关于", self)
            about_action.triggered.connect(self._show_about)
            help_menu.addAction(about_action)

        def _on_nuclei_update(self):
            """Nuclei模板更新"""
            try:
                from core.modules.nuclei_executor import NucleiExecutor
                executor = NucleiExecutor()
                executor.loader.load_from_git(
                    "https://github.com/projectdiscovery/nuclei-templates.git",
                    update=True
                )
                QMessageBox.information(self, "Nuclei", "模板更新完成")
            except Exception as e:
                QMessageBox.warning(self, "Nuclei", f"更新失败: {e}")

        def _on_nuclei_stats(self):
            """Nuclei模板统计"""
            try:
                from core.modules.nuclei_executor import NucleiExecutor
                executor = NucleiExecutor()
                stats = executor.loader.get_stats()
                msg = "\n".join(f"{k}: {v}" for k, v in stats.items())
                QMessageBox.information(self, "Nuclei统计", msg)
            except Exception as e:
                QMessageBox.warning(self, "Nuclei", f"获取统计失败: {e}")

        def setup_statusbar(self):
            self.status_bar = QStatusBar()
            self.setStatusBar(self.status_bar)
            self.status_bar.showMessage("就绪")

            self.memory_label = QLabel("内存: 0 MB")
            self.status_bar.addPermanentWidget(self.memory_label)

            self.disk_label = QLabel("磁盘: 0 KB")
            self.status_bar.addPermanentWidget(self.disk_label)

        def _show_about(self):
            QMessageBox.about(
                self, "关于",
                "昆仑安全测试平台 Pro v1.0\n\n"
                "自动化渗透测试桌面应用\n\n"
                "集成Nuclei模板引擎 | 多协议支持 | AI驱动检测\n"
                "昆仑安全实验室出品"
            )

        def closeEvent(self, event):
            """窗口关闭事件"""
            if self._kunlun_app:
                self._kunlun_app.shutdown()
            super().closeEvent(event)


# =============================================================================
# CLI参数解析
# =============================================================================

def _build_cli_parser() -> argparse.ArgumentParser:
    """构建CLI参数解析器"""
    parser = argparse.ArgumentParser(
        prog="kunlun",
        description="昆仑安全测试平台 Pro - 命令行工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python main.py                              # 启动GUI
  python main.py --cli nuclei stats           # Nuclei模板统计
  python main.py --cli nuclei search xss      # 搜索XSS模板
  python main.py --cli nuclei update          # 更新Nuclei模板
  python main.py --cli nuclei test --id http-missing-security-headers --url https://example.com
  python main.py --cli modules                # 列出所有模块
  python main.py --cli stats                  # 平台统计
        """,
    )

    parser.add_argument(
        "--cli", action="store_true",
        help="CLI模式（无GUI）"
    )
    parser.add_argument(
        "--config", type=str, default=None,
        help="配置文件路径"
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="启用调试日志"
    )

    subparsers = parser.add_subparsers(dest="command", help="子命令")

    # nuclei 子命令
    nuclei_parser = subparsers.add_parser("nuclei", help="Nuclei模板引擎管理")
    nuclei_sub = nuclei_parser.add_subparsers(dest="nuclei_action", help="操作")

    nuclei_update = nuclei_sub.add_parser("update", help="更新模板")
    nuclei_update.add_argument("--repo", type=str, help="Git仓库URL")

    nuclei_search = nuclei_sub.add_parser("search", help="搜索模板")
    nuclei_search.add_argument("keyword", type=str, help="搜索关键词")

    nuclei_sub.add_parser("stats", help="模板统计")

    nuclei_validate = nuclei_sub.add_parser("validate", help="校验模板")
    nuclei_validate.add_argument("path", type=str, help="模板文件路径")

    nuclei_test = nuclei_sub.add_parser("test", help="测试模板")
    nuclei_test.add_argument("--id", dest="template_id", type=str, required=True, help="模板ID")
    nuclei_test.add_argument("--url", dest="url", type=str, required=True, help="目标URL")

    # 通用参数
    nuclei_parser.add_argument("--templates-dir", type=str, help="模板目录")
    nuclei_parser.add_argument("--timeout", type=float, default=10.0, help="超时时间")
    nuclei_parser.add_argument("--concurrency", type=int, default=10, help="并发数")

    # scan 子命令
    scan_parser = subparsers.add_parser("scan", help="主动扫描")
    scan_parser.add_argument("target", type=str, help="目标URL")

    # fingerprint 子命令
    fp_parser = subparsers.add_parser("fingerprint", help="指纹识别")
    fp_parser.add_argument("target", type=str, help="目标URL")

    # stats 子命令
    subparsers.add_parser("stats", help="平台统计")

    # modules 子命令
    subparsers.add_parser("modules", help="列出所有模块")

    return parser


# =============================================================================
# 主入口
# =============================================================================

def main():
    """主入口函数

    根据参数自动选择 GUI 或 CLI 模式。
    """
    parser = _build_cli_parser()
    args = parser.parse_args()

    # 调试模式
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        _logger.setLevel(logging.DEBUG)
        _logger.debug("调试模式已启用")

    if args.cli:
        _run_cli(args)
    else:
        _run_gui(args)


def _run_gui(args: argparse.Namespace):
    """GUI模式入口"""
    if not _HAS_PYSIDE6:
        print("错误: GUI模式需要PySide6，请安装: pip install pyside6")
        sys.exit(1)

    app = KunLunApplication(mode="gui")
    app.initialize_backend(config_path=args.config)
    app.initialize_modules(lazy=True)
    app.run_gui()


def _run_cli(args: argparse.Namespace):
    """CLI模式入口"""
    if not args.command:
        print("错误: CLI模式需要指定命令，使用 --help 查看帮助")
        sys.exit(1)

    app = KunLunApplication(mode="cli")
    app.initialize_backend(config_path=args.config)
    app.initialize_modules(lazy=False)

    try:
        asyncio.run(app.run_cli_async(args))
    except KeyboardInterrupt:
        _logger.info("用户中断")
    finally:
        app.shutdown()


if __name__ == "__main__":
    main()
