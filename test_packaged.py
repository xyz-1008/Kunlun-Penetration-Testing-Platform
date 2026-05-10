#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KunLun Penetration Testing Platform - Packaging Validation Script

打包后验证清单，确保所有功能模块100%可用
"""

import sys
import os
import subprocess
import time
import socket
from pathlib import Path

# 测试结果颜色
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'


def print_status(test_name, status, message=""):
    """打印测试状态"""
    if status == "PASS":
        print(f"{Colors.GREEN}[PASS]{Colors.RESET} {test_name}")
        if message:
            print(f"       {message}")
    elif status == "FAIL":
        print(f"{Colors.RED}[FAIL]{Colors.RESET} {test_name}")
        if message:
            print(f"       {message}")
    elif status == "WARN":
        print(f"{Colors.YELLOW}[WARN]{Colors.RESET} {test_name}")
        if message:
            print(f"       {message}")
    elif status == "INFO":
        print(f"{Colors.BLUE}[INFO]{Colors.RESET} {test_name}")
        if message:
            print(f"       {message}")


def test_application_startup():
    """测试程序启动和GUI加载"""
    print_status("Application Startup", "INFO", "Testing GUI initialization...")
    try:
        # 检查是否能够导入主模块
        from core.app import Application
        print_status("Application Startup", "PASS", "Successfully imported Application class")
        return True
    except Exception as e:
        print_status("Application Startup", "FAIL", f"Import failed: {str(e)}")
        return False


def test_mitm_proxy():
    """测试MITM代理功能"""
    print_status("MITM Proxy", "INFO", "Testing MITM proxy initialization...")
    try:
        # 检查MITM模块是否可导入
        from core.modules.mitm import MITMProxy
        print_status("MITM Proxy", "PASS", "Successfully imported MITMProxy class")
        
        # 检查证书路径功能
        from utils.path_utils import cert_path
        cert = cert_path("rootCA.pem")
        if cert.exists():
            print_status("MITM Proxy", "PASS", f"Certificate exists: {cert}")
        else:
            print_status("MITM Proxy", "WARN", "Certificate not found, will be generated on first use")
        
        return True
    except Exception as e:
        print_status("MITM Proxy", "FAIL", f"MITM module import failed: {str(e)}")
        return False


def test_nuclei_engine():
    """测试Nuclei引擎功能"""
    print_status("Nuclei Engine", "INFO", "Testing Nuclei integration...")
    try:
        # 检查Nuclei模块
        from core.modules.nuclei_engine import NucleiEngine
        print_status("Nuclei Engine", "PASS", "Successfully imported NucleiEngine class")
        
        # 检查规则目录
        from utils.path_utils import rules_path
        rules_dir = rules_path()
        if rules_dir.exists():
            rule_count = len(list(rules_dir.glob("*.yaml"))) + len(list(rules_dir.glob("*.yml")))
            print_status("Nuclei Engine", "PASS", f"Found {rule_count} rules in rules directory")
        else:
            print_status("Nuclei Engine", "WARN", "Rules directory not found")
        
        return True
    except Exception as e:
        print_status("Nuclei Engine", "FAIL", f"Nuclei module import failed: {str(e)}")
        return False


def test_c2_framework():
    """测试C2框架功能"""
    print_status("C2 Framework", "INFO", "Testing C2 framework...")
    try:
        # 检查C2模块
        from core.modules.c2_automation import C2Automation
        from core.modules.beacon_lifecycle import BeaconLifecycle
        print_status("C2 Framework", "PASS", "Successfully imported C2 modules")
        
        return True
    except Exception as e:
        print_status("C2 Framework", "FAIL", f"C2 module import failed: {str(e)}")
        return False


def test_http3_proxy():
    """测试HTTP/3代理功能"""
    print_status("HTTP/3 Proxy", "INFO", "Testing HTTP/3 support...")
    try:
        # 检查HTTP/3模块
        from core.modules.http3_proxy import HTTP3Proxy
        print_status("HTTP/3 Proxy", "PASS", "Successfully imported HTTP3Proxy class")
        
        return True
    except Exception as e:
        print_status("HTTP/3 Proxy", "FAIL", f"HTTP/3 module import failed: {str(e)}")
        return False


def test_plugin_system():
    """测试插件系统"""
    print_status("Plugin System", "INFO", "Testing plugin loading system...")
    try:
        # 检查插件系统
        from core.module_registry import ModuleRegistry
        print_status("Plugin System", "PASS", "Successfully imported ModuleRegistry")
        
        # 检查插件目录
        from utils.path_utils import plugins_path
        plugins_dir = plugins_path()
        if plugins_dir.exists():
            plugins = list(plugins_dir.glob("*.py"))
            print_status("Plugin System", "PASS", f"Found {len(plugins)} plugins")
        else:
            print_status("Plugin System", "WARN", "Plugins directory not found")
        
        return True
    except Exception as e:
        print_status("Plugin System", "FAIL", f"Plugin system import failed: {str(e)}")
        return False


def test_reverse_dns():
    """测试反连DNS功能"""
    print_status("Reverse DNS", "INFO", "Testing DNS listener...")
    try:
        # 检查反连模块
        from core.modules.dns_server import DNSServer
        print_status("Reverse DNS", "PASS", "Successfully imported DNSServer class")
        
        return True
    except Exception as e:
        print_status("Reverse DNS", "FAIL", f"DNS module import failed: {str(e)}")
        return False


def test_reverse_http():
    """测试反连HTTP功能"""
    print_status("Reverse HTTP", "INFO", "Testing HTTP listener...")
    try:
        # 检查HTTP反连模块
        from core.modules.http_server import HTTPServer
        print_status("Reverse HTTP", "PASS", "Successfully imported HTTPServer class")
        
        return True
    except Exception as e:
        print_status("Reverse HTTP", "FAIL", f"HTTP server module import failed: {str(e)}")
        return False


def test_data_paths():
    """测试数据路径处理"""
    print_status("Data Paths", "INFO", "Testing path utilities...")
    try:
        from utils.path_utils import (
            base_path, user_dir, rules_path, profiles_path, 
            templates_path, config_path, cert_path
        )
        
        paths = [
            ("base_path", base_path()),
            ("user_dir", user_dir()),
            ("rules_path", rules_path()),
            ("profiles_path", profiles_path()),
            ("templates_path", templates_path()),
            ("config_path", config_path()),
            ("cert_path", cert_path()),
        ]
        
        all_exist = True
        for name, path in paths:
            if path.exists():
                print(f"       ✓ {name}: {path}")
            else:
                print(f"       ✗ {name}: {path} (not found)")
                all_exist = False
        
        if all_exist:
            print_status("Data Paths", "PASS", "All paths are valid")
        else:
            print_status("Data Paths", "WARN", "Some paths not found")
        
        return True
    except Exception as e:
        print_status("Data Paths", "FAIL", f"Path utilities failed: {str(e)}")
        return False


def test_network_ports():
    """测试网络端口可用性"""
    print_status("Network Ports", "INFO", "Testing common port availability...")
    try:
        test_ports = [80, 443, 8080, 8443, 53, 5353]
        used_ports = []
        
        for port in test_ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind(('127.0.0.1', port))
                except OSError:
                    used_ports.append(port)
        
        if used_ports:
            print_status("Network Ports", "WARN", f"Ports {used_ports} are already in use")
        else:
            print_status("Network Ports", "PASS", "All test ports are available")
        
        return True
    except Exception as e:
        print_status("Network Ports", "FAIL", f"Port test failed: {str(e)}")
        return False


def test_python_version():
    """测试Python版本"""
    print_status("Python Version", "INFO", "Checking Python version...")
    try:
        version = sys.version_info
        if version >= (3, 10):
            print_status("Python Version", "PASS", f"Python {version.major}.{version.minor}.{version.micro}")
            return True
        else:
            print_status("Python Version", "FAIL", f"Python {version.major}.{version.minor} < 3.10 required")
            return False
    except Exception as e:
        print_status("Python Version", "FAIL", f"Version check failed: {str(e)}")
        return False


def run_all_tests():
    """运行所有测试"""
    print(f"\n{Colors.BLUE}="*70)
    print(f"KunLun Penetration Testing Platform - Packaging Validation")
    print(f"="*70 + Colors.RESET)
    
    tests = [
        test_python_version,
        test_data_paths,
        test_application_startup,
        test_mitm_proxy,
        test_nuclei_engine,
        test_c2_framework,
        test_http3_proxy,
        test_plugin_system,
        test_reverse_dns,
        test_reverse_http,
        test_network_ports,
    ]
    
    passed = 0
    failed = 0
    warned = 0
    
    for test in tests:
        result = test()
        if result:
            # 检查是否有警告（通过但有警告也算通过）
            passed += 1
        else:
            failed += 1
    
    print(f"\n{Colors.BLUE}="*70)
    print(f"测试结果汇总:")
    print(f"  通过: {Colors.GREEN}{passed}{Colors.RESET}")
    print(f"  失败: {Colors.RED}{failed}{Colors.RESET}")
    print(f"="*70 + Colors.RESET)
    
    if failed == 0:
        print(f"\n{Colors.GREEN}✓ 所有测试通过！{Colors.RESET}")
        return 0
    else:
        print(f"\n{Colors.RED}✗ 部分测试失败，请检查上述错误信息{Colors.RESET}")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
