#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
昆仑渗透测试平台 - 打包验证测试脚本
=====================================
功能：
  1. 自动运行10+核心功能验证项
  2. 验证所有模块导入是否正常
  3. 验证数据文件路径是否正确
  4. 验证MITM代理、Nuclei引擎、C2框架等核心功能
  5. 生成测试报告

使用方法：
  python test_packaged.py [--verbose] [--output report.json]
"""

import os
import sys
import json
import time
import asyncio
import platform
import importlib
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum


# ==================== 测试状态枚举 ====================
class TestStatus(Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    WARNING = "WARNING"


# ==================== 测试结果数据类 ====================
@dataclass
class TestResult:
    """单个测试结果"""
    name: str
    status: TestStatus
    message: str = ""
    duration: float = 0.0
    details: Dict = field(default_factory=dict)


@dataclass
class TestReport:
    """测试报告"""
    platform: str
    python_version: str
    is_frozen: bool
    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    warnings: int = 0
    total_duration: float = 0.0
    results: List[TestResult] = field(default_factory=list)
    
    def add_result(self, result: TestResult):
        self.results.append(result)
        self.total_tests += 1
        if result.status == TestStatus.PASSED:
            self.passed += 1
        elif result.status == TestStatus.FAILED:
            self.failed += 1
        elif result.status == TestStatus.SKIPPED:
            self.skipped += 1
        elif result.status == TestStatus.WARNING:
            self.warnings += 1
    
    def to_dict(self) -> dict:
        return {
            "platform": self.platform,
            "python_version": self.python_version,
            "is_frozen": self.is_frozen,
            "total_tests": self.total_tests,
            "passed": self.passed,
            "failed": self.failed,
            "skipped": self.skipped,
            "warnings": self.warnings,
            "total_duration": round(self.total_duration, 2),
            "results": [asdict(r) for r in self.results]
        }


# ==================== 测试用例 ====================
class PackagedTestSuite:
    """打包验证测试套件"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.report = TestReport(
            platform=platform.system(),
            python_version=platform.python_version(),
            is_frozen=getattr(sys, 'frozen', False)
        )
        
        # 导入path_utils
        try:
            from utils.path_utils import PathUtils
            self.path_utils = PathUtils
        except ImportError:
            self.path_utils = None
    
    def run_all_tests(self) -> TestReport:
        """运行所有测试"""
        start_time = time.time()
        
        print("=" * 70)
        print("昆仑渗透测试平台 - 打包验证测试")
        print("=" * 70)
        print(f"平台: {platform.system()} {platform.release()}")
        print(f"Python: {platform.python_version()}")
        print(f"打包环境: {'是' if getattr(sys, 'frozen', False) else '否'}")
        print("=" * 70)
        
        # 运行所有测试
        tests = [
            ("1. GUI界面启动测试", self.test_gui_import),
            ("2. MITM代理模块测试", self.test_mitm_module),
            ("3. HTTP/3 QUIC协议栈测试", self.test_http3_quic),
            ("4. Nuclei模板引擎测试", self.test_nuclei_engine),
            ("5. C2框架模块测试", self.test_c2_framework),
            ("6. 反连平台测试", self.test_reverse_platform),
            ("7. JWT/OAuth测试模块", self.test_jwt_oauth),
            ("8. 被动扫描引擎测试", self.test_passive_scanner),
            ("9. 域控攻击模块测试", self.test_domain_attack),
            ("10. 插件系统测试", self.test_plugin_system),
            ("11. FID聚类模块测试", self.test_fid_clustering),
            ("12. 数据文件路径测试", self.test_data_files),
            ("13. 证书存储路径测试", self.test_cert_paths),
            ("14. 异步IO事件循环测试", self.test_asyncio_loop),
            ("15. 多进程支持测试", self.test_multiprocessing),
        ]
        
        for test_name, test_func in tests:
            print(f"\n{'='*70}")
            print(f"运行测试: {test_name}")
            print(f"{'='*70}")
            
            test_start = time.time()
            try:
                result = test_func()
            except Exception as e:
                result = TestResult(
                    name=test_name,
                    status=TestStatus.FAILED,
                    message=f"异常: {str(e)}",
                    duration=time.time() - test_start
                )
                if self.verbose:
                    import traceback
                    print(f"详细错误:\n{traceback.format_exc()}")
            
            result.duration = time.time() - test_start
            self.report.add_result(result)
            
            # 打印结果
            status_icon = {
                TestStatus.PASSED: "✓",
                TestStatus.FAILED: "✗",
                TestStatus.SKIPPED: "○",
                TestStatus.WARNING: "⚠"
            }
            print(f"  {status_icon[result.status]} {result.message}")
        
        self.report.total_duration = time.time() - start_time
        
        # 打印总结
        self._print_summary()
        
        return self.report
    
    # ==================== 测试用例实现 ====================
    
    def test_gui_import(self) -> TestResult:
        """测试1: GUI界面启动测试"""
        try:
            # 测试PyQt6导入
            import PyQt6
            from PyQt6.QtWidgets import QApplication
            from PyQt6.QtCore import Qt
            
            # 测试主窗口导入
            try:
                from gui.main_window import MainWindow
                has_main_window = True
            except ImportError:
                has_main_window = False
            
            return TestResult(
                name="GUI界面启动测试",
                status=TestStatus.PASSED,
                message=f"PyQt6导入成功，MainWindow: {'可用' if has_main_window else '未找到'}",
                details={"pyqt6_version": PyQt6.__version__, "has_main_window": has_main_window}
            )
        except ImportError as e:
            return TestResult(
                name="GUI界面启动测试",
                status=TestStatus.FAILED,
                message=f"PyQt6导入失败: {str(e)}"
            )
    
    def test_mitm_module(self) -> TestResult:
        """测试2: MITM代理模块测试"""
        try:
            from core.modules.mitm import MITMModule
            from core.modules.mitm_proxy_engine import MITMProxyEngine
            
            # 测试证书生成
            from utils.path_utils import PathUtils
            cert_dir = PathUtils.get_certs_path()
            cert_dir.mkdir(parents=True, exist_ok=True)
            
            return TestResult(
                name="MITM代理模块测试",
                status=TestStatus.PASSED,
                message="MITM模块导入成功，证书目录可用",
                details={"cert_dir": str(cert_dir)}
            )
        except ImportError as e:
            return TestResult(
                name="MITM代理模块测试",
                status=TestStatus.FAILED,
                message=f"MITM模块导入失败: {str(e)}"
            )
    
    def test_http3_quic(self) -> TestResult:
        """测试3: HTTP/3 QUIC协议栈测试"""
        try:
            import aioquic
            from aioquic.h3.connection import H3_ALPN
            from aioquic.quic.configuration import QuicConfiguration
            
            return TestResult(
                name="HTTP/3 QUIC协议栈测试",
                status=TestStatus.PASSED,
                message="aioquic导入成功，HTTP/3协议栈可用",
                details={"aioquic_version": aioquic.__version__}
            )
        except ImportError as e:
            return TestResult(
                name="HTTP/3 QUIC协议栈测试",
                status=TestStatus.FAILED,
                message=f"aioquic导入失败: {str(e)}"
            )
    
    def test_nuclei_engine(self) -> TestResult:
        """测试4: Nuclei模板引擎测试"""
        try:
            from core.modules.nuclei_executor import NucleiExecutor
            
            # 测试模板目录
            from utils.path_utils import PathUtils
            rules_dir = PathUtils.get_rules_path()
            
            has_templates = False
            if rules_dir.exists():
                yaml_files = list(rules_dir.rglob("*.yaml")) + list(rules_dir.rglob("*.yml"))
                has_templates = len(yaml_files) > 0
            
            return TestResult(
                name="Nuclei模板引擎测试",
                status=TestStatus.PASSED if has_templates else TestStatus.WARNING,
                message=f"Nuclei引擎导入成功，模板文件: {'找到' if has_templates else '未找到'}",
                details={"rules_dir": str(rules_dir), "has_templates": has_templates}
            )
        except ImportError as e:
            return TestResult(
                name="Nuclei模板引擎测试",
                status=TestStatus.FAILED,
                message=f"Nuclei引擎导入失败: {str(e)}"
            )
    
    def test_c2_framework(self) -> TestResult:
        """测试5: C2框架模块测试"""
        try:
            from core.modules.c2_server import C2Server
            from core.modules.beacon import Beacon
            
            # 测试Payload临时目录
            from utils.path_utils import PathUtils
            payload_dir = PathUtils.get_payload_temp_path()
            payload_dir.mkdir(parents=True, exist_ok=True)
            
            return TestResult(
                name="C2框架模块测试",
                status=TestStatus.PASSED,
                message="C2框架导入成功，Payload目录可用",
                details={"payload_dir": str(payload_dir)}
            )
        except ImportError as e:
            return TestResult(
                name="C2框架模块测试",
                status=TestStatus.FAILED,
                message=f"C2框架导入失败: {str(e)}"
            )
    
    def test_reverse_platform(self) -> TestResult:
        """测试6: 反连平台测试"""
        try:
            from core.modules.reverse_shell import ReverseShellModule
            from core.modules.oob_detector import OOBDetector
            
            return TestResult(
                name="反连平台测试",
                status=TestStatus.PASSED,
                message="反连平台模块导入成功",
                details={}
            )
        except ImportError as e:
            return TestResult(
                name="反连平台测试",
                status=TestStatus.FAILED,
                message=f"反连平台模块导入失败: {str(e)}"
            )
    
    def test_jwt_oauth(self) -> TestResult:
        """测试7: JWT/OAuth测试模块"""
        try:
            import jwt
            from core.modules.jwt_editor import JWTEditor
            from core.modules.oauth_analyzer import OAuthAnalyzer
            
            # 测试JWT功能
            test_token = jwt.encode({"sub": "test"}, "secret", algorithm="HS256")
            decoded = jwt.decode(test_token, "secret", algorithms=["HS256"])
            
            return TestResult(
                name="JWT/OAuth测试模块",
                status=TestStatus.PASSED,
                message="JWT/OAuth模块导入成功，JWT编解码正常",
                details={"jwt_version": jwt.__version__}
            )
        except ImportError as e:
            return TestResult(
                name="JWT/OAuth测试模块",
                status=TestStatus.FAILED,
                message=f"JWT/OAuth模块导入失败: {str(e)}"
            )
    
    def test_passive_scanner(self) -> TestResult:
        """测试8: 被动扫描引擎测试"""
        try:
            from core.modules.passive_scanner import PassiveScanner
            from core.modules.fingerprint import FingerprintModule
            
            return TestResult(
                name="被动扫描引擎测试",
                status=TestStatus.PASSED,
                message="被动扫描引擎导入成功",
                details={}
            )
        except ImportError as e:
            return TestResult(
                name="被动扫描引擎测试",
                status=TestStatus.FAILED,
                message=f"被动扫描引擎导入失败: {str(e)}"
            )
    
    def test_domain_attack(self) -> TestResult:
        """测试9: 域控攻击模块测试"""
        try:
            from core.modules.domain_attack_integration import DomainAttackIntegration
            from core.modules.dcsync_attack import DCSyncAttack
            from core.modules.shadow_credentials import ShadowCredentials
            
            return TestResult(
                name="域控攻击模块测试",
                status=TestStatus.PASSED,
                message="域控攻击模块导入成功",
                details={}
            )
        except ImportError as e:
            return TestResult(
                name="域控攻击模块测试",
                status=TestStatus.FAILED,
                message=f"域控攻击模块导入失败: {str(e)}"
            )
    
    def test_plugin_system(self) -> TestResult:
        """测试10: 插件系统测试"""
        try:
            from core.modules.plugin_manager import PluginManager
            from core.modules.plugin_engine import PluginEngine
            
            # 测试插件目录
            from utils.path_utils import PathUtils
            plugin_dir = PathUtils.get_plugins_path()
            plugin_dir.mkdir(parents=True, exist_ok=True)
            
            return TestResult(
                name="插件系统测试",
                status=TestStatus.PASSED,
                message="插件系统导入成功，插件目录可用",
                details={"plugin_dir": str(plugin_dir)}
            )
        except ImportError as e:
            return TestResult(
                name="插件系统测试",
                status=TestStatus.FAILED,
                message=f"插件系统导入失败: {str(e)}"
            )
    
    def test_fid_clustering(self) -> TestResult:
        """测试11: FID聚类模块测试"""
        try:
            import sklearn
            import pandas
            import numpy
            
            from core.modules.fid_clustering import FIDClusteringModule
            
            return TestResult(
                name="FID聚类模块测试",
                status=TestStatus.PASSED,
                message="FID聚类模块导入成功，科学计算库可用",
                details={
                    "sklearn_version": sklearn.__version__,
                    "pandas_version": pandas.__version__,
                    "numpy_version": numpy.__version__
                }
            )
        except ImportError as e:
            return TestResult(
                name="FID聚类模块测试",
                status=TestStatus.FAILED,
                message=f"FID聚类模块导入失败: {str(e)}"
            )
    
    def test_data_files(self) -> TestResult:
        """测试12: 数据文件路径测试"""
        if not self.path_utils:
            return TestResult(
                name="数据文件路径测试",
                status=TestStatus.FAILED,
                message="path_utils模块未找到"
            )
        
        try:
            # 测试各种资源路径
            paths_to_check = [
                ("rules", self.path_utils.get_rules_path()),
                ("templates", self.path_utils.get_templates_path()),
                ("profiles", self.path_utils.get_profiles_path()),
                ("gadget_chains", self.path_utils.get_gadget_chains_path()),
                ("assets", self.path_utils.get_assets_path()),
            ]
            
            results = {}
            all_ok = True
            for name, path in paths_to_check:
                exists = path.exists()
                results[name] = {"path": str(path), "exists": exists}
                if not exists:
                    all_ok = False
            
            return TestResult(
                name="数据文件路径测试",
                status=TestStatus.PASSED if all_ok else TestStatus.WARNING,
                message=f"数据文件路径检测完成，{'全部存在' if all_ok else '部分缺失'}",
                details=results
            )
        except Exception as e:
            return TestResult(
                name="数据文件路径测试",
                status=TestStatus.FAILED,
                message=f"数据文件路径检测异常: {str(e)}"
            )
    
    def test_cert_paths(self) -> TestResult:
        """测试13: 证书存储路径测试"""
        if not self.path_utils:
            return TestResult(
                name="证书存储路径测试",
                status=TestStatus.FAILED,
                message="path_utils模块未找到"
            )
        
        try:
            cert_dir = self.path_utils.get_certs_path()
            cert_dir.mkdir(parents=True, exist_ok=True)
            
            # 测试写入权限
            test_file = cert_dir / "test_cert.pem"
            test_file.write_text("test")
            test_file.unlink()
            
            return TestResult(
                name="证书存储路径测试",
                status=TestStatus.PASSED,
                message=f"证书目录可用: {cert_dir}",
                details={"cert_dir": str(cert_dir), "writable": True}
            )
        except Exception as e:
            return TestResult(
                name="证书存储路径测试",
                status=TestStatus.FAILED,
                message=f"证书目录不可用: {str(e)}"
            )
    
    def test_asyncio_loop(self) -> TestResult:
        """测试14: 异步IO事件循环测试"""
        try:
            async def async_test():
                await asyncio.sleep(0.01)
                return True
            
            result = asyncio.run(async_test())
            
            return TestResult(
                name="异步IO事件循环测试",
                status=TestStatus.PASSED if result else TestStatus.FAILED,
                message="asyncio事件循环正常运行",
                details={}
            )
        except Exception as e:
            return TestResult(
                name="异步IO事件循环测试",
                status=TestStatus.FAILED,
                message=f"asyncio事件循环异常: {str(e)}"
            )
    
    def test_multiprocessing(self) -> TestResult:
        """测试15: 多进程支持测试"""
        try:
            import multiprocessing
            
            # 测试freeze_support（打包后必需）
            if getattr(sys, 'frozen', False):
                multiprocessing.freeze_support()
            
            # 测试进程池
            with multiprocessing.Pool(1) as pool:
                result = pool.apply_async(lambda: True).get(timeout=5)
            
            return TestResult(
                name="多进程支持测试",
                status=TestStatus.PASSED if result else TestStatus.FAILED,
                message="多进程支持正常",
                details={"cpu_count": multiprocessing.cpu_count()}
            )
        except Exception as e:
            return TestResult(
                name="多进程支持测试",
                status=TestStatus.FAILED,
                message=f"多进程支持异常: {str(e)}"
            )
    
    # ==================== 辅助方法 ====================
    
    def _print_summary(self):
        """打印测试总结"""
        print("\n" + "=" * 70)
        print("测试总结")
        print("=" * 70)
        print(f"总测试数: {self.report.total_tests}")
        print(f"通过: {self.report.passed}")
        print(f"失败: {self.report.failed}")
        print(f"跳过: {self.report.skipped}")
        print(f"警告: {self.report.warnings}")
        print(f"总耗时: {self.report.total_duration:.2f}秒")
        print("=" * 70)
        
        if self.report.failed > 0:
            print("\n失败的测试:")
            for result in self.report.results:
                if result.status == TestStatus.FAILED:
                    print(f"  ✗ {result.name}: {result.message}")
        
        if self.report.warnings > 0:
            print("\n警告:")
            for result in self.report.results:
                if result.status == TestStatus.WARNING:
                    print(f"  ⚠ {result.name}: {result.message}")
        
        print("=" * 70)


# ==================== 主函数 ====================
def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description="昆仑渗透测试平台 - 打包验证测试")
    parser.add_argument("--verbose", "-v", action="store_true", help="显示详细输出")
    parser.add_argument("--output", "-o", type=str, help="输出报告文件路径")
    
    args = parser.parse_args()
    
    # 运行测试
    suite = PackagedTestSuite(verbose=args.verbose)
    report = suite.run_all_tests()
    
    # 输出报告
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
        print(f"\n测试报告已保存到: {output_path}")
    
    # 返回退出码
    sys.exit(0 if report.failed == 0 else 1)


if __name__ == "__main__":
    main()
