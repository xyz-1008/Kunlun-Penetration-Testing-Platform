"""
PoC验证管理器
整合加载、匹配、执行、结果标准化
"""

import os
import sys
import logging
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import concurrent.futures

from .poc_engine import PoCLoader, PoCMetadata, PoCType, PoCResult, RiskLevel
from .fingerprint_matcher import FingerprintMatcher, AssetFingerprint, MatchResult
from .sandbox_executor import SandboxExecutor, SandboxConfig, SandboxResult
from .oob_detector import OOBManager, OOBRequest
from .result_models import (
    PoCVerificationResult, AssetVulnerabilityReport, 
    ConfidenceLevel, SeverityLevel, PoCStatus,
    create_poc_result, create_asset_report
)

logger = logging.getLogger(__name__)


@dataclass
class PoCExecutionConfig:
    """PoC执行配置"""
    timeout: int = 30
    max_memory_mb: int = 256
    max_concurrent: int = 5
    enable_oob: bool = True
    dns_port: int = 15353
    http_port: int = 18080
    ldap_port: int = 13890
    network_isolation: bool = False


class PoCVerificationManager:
    """PoC验证管理器"""
    
    def __init__(self, poc_dir: str, config: PoCExecutionConfig = None):
        self.poc_dir = poc_dir
        self.config = config or PoCExecutionConfig()
        
        self.poc_loader = PoCLoader(poc_dir)
        self.fingerprint_matcher = FingerprintMatcher()
        self.sandbox_executor = SandboxExecutor(
            SandboxConfig(
                timeout=self.config.timeout,
                max_memory_mb=self.config.max_memory_mb,
                network_isolation=self.config.network_isolation
            )
        )
        self.oob_manager = OOBManager(
            dns_port=self.config.dns_port,
            http_port=self.config.http_port,
            ldap_port=self.config.ldap_port
        )
        
        self._execution_history: List[PoCVerificationResult] = []
    
    def initialize(self):
        """初始化"""
        self.poc_loader.load_all_pocs()
        if self.config.enable_oob:
            self.oob_manager.start_all()
        logger.info("PoC验证管理器初始化完成")
    
    def shutdown(self):
        """关闭"""
        self.sandbox_executor.terminate_all()
        if self.config.enable_oob:
            self.oob_manager.stop_all()
        logger.info("PoC验证管理器已关闭")
    
    def load_pocs(self, poc_dir: str = None) -> int:
        """加载PoC"""
        if poc_dir:
            self.poc_loader = PoCLoader(poc_dir)
        return len(self.poc_loader.load_all_pocs())
    
    def get_available_pocs(self) -> Dict[str, Dict[str, Any]]:
        """获取可用PoC列表"""
        return self.poc_loader.get_all_pocs()
    
    def get_poc_ids(self) -> List[str]:
        """获取所有PoC ID"""
        return self.poc_loader.get_poc_ids()
    
    def match_pocs_for_asset(self, asset: AssetFingerprint) -> List[str]:
        """为资产匹配PoC"""
        pocs = self.poc_loader.get_all_pocs()
        return self.fingerprint_matcher.filter_pocs_for_asset(asset, pocs)
    
    def execute_single_poc(self, poc_id: str, target: str) -> PoCVerificationResult:
        """执行单个PoC"""
        poc_data = self.poc_loader.get_poc(poc_id)
        if not poc_data:
            return create_poc_result(
                poc_id=poc_id,
                poc_name="Unknown",
                target=target,
                status=PoCStatus.ERROR,
                error=f"PoC不存在: {poc_id}"
            )
        
        metadata = poc_data.get("metadata", {})
        poc_type = poc_data.get("type")
        
        if poc_type == PoCType.PYTHON:
            return self._execute_python_poc(poc_id, poc_data, target)
        elif poc_type == PoCType.YAML:
            return self._execute_yaml_poc(poc_id, poc_data, target)
        else:
            return create_poc_result(
                poc_id=poc_id,
                poc_name=metadata.get("name", poc_id),
                target=target,
                status=PoCStatus.ERROR,
                error=f"不支持的PoC类型: {poc_type}"
            )
    
    def _execute_python_poc(self, poc_id: str, poc_data: Dict, target: str) -> PoCVerificationResult:
        """执行Python PoC"""
        metadata = poc_data.get("metadata", {})
        module = poc_data.get("module")
        
        if not module or not hasattr(module, "verify"):
            return create_poc_result(
                poc_id=poc_id,
                poc_name=metadata.get("name", poc_id),
                target=target,
                status=PoCStatus.ERROR,
                error="PoC模块缺少verify函数"
            )
        
        sandbox_result = self.sandbox_executor.execute_poc(poc_id, module, target)
        
        if sandbox_result.success:
            vulnerable = "vuln" in sandbox_result.output.lower() or "true" in sandbox_result.output.lower()
            return create_poc_result(
                poc_id=poc_id,
                poc_name=metadata.get("name", poc_id),
                target=target,
                status=PoCStatus.SUCCESS,
                vulnerable=vulnerable,
                confidence=ConfidenceLevel.CONFIRMED if vulnerable else ConfidenceLevel.UNCONFIRMED,
                severity=SeverityLevel(metadata.get("risk_level", "info")),
                cve=metadata.get("cve", ""),
                evidence=sandbox_result.output,
                execution_time=sandbox_result.cpu_time_used,
                memory_used_mb=sandbox_result.memory_used_mb
            )
        else:
            return create_poc_result(
                poc_id=poc_id,
                poc_name=metadata.get("name", poc_id),
                target=target,
                status=PoCStatus.TIMEOUT if sandbox_result.timeout else PoCStatus.ERROR,
                error=sandbox_result.error,
                execution_time=sandbox_result.cpu_time_used
            )
    
    def _execute_yaml_poc(self, poc_id: str, poc_data: Dict, target: str) -> PoCVerificationResult:
        """执行YAML PoC"""
        metadata = poc_data.get("metadata", {})
        yaml_data = poc_data.get("yaml_data", {})
        
        requests = yaml_data.get("requests", [])
        matchers = yaml_data.get("matchers", [])
        
        try:
            import requests as http_requests
            
            for req in requests:
                url = req.get("url", "").replace("{{target}}", target)
                method = req.get("method", "GET").upper()
                headers = req.get("headers", {})
                body = req.get("body", "")
                
                response = http_requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=body,
                    timeout=self.config.timeout
                )
                
                for matcher in matchers:
                    if self._match_yaml_response(response, matcher):
                        return create_poc_result(
                            poc_id=poc_id,
                            poc_name=metadata.get("name", poc_id),
                            target=target,
                            status=PoCStatus.SUCCESS,
                            vulnerable=True,
                            confidence=ConfidenceLevel.CONFIRMED,
                            severity=SeverityLevel(metadata.get("risk_level", "info")),
                            cve=metadata.get("cve", ""),
                            evidence=f"匹配条件: {matcher}",
                            response_summary=response.text[:500]
                        )
            
            return create_poc_result(
                poc_id=poc_id,
                poc_name=metadata.get("name", poc_id),
                target=target,
                status=PoCStatus.SUCCESS,
                vulnerable=False,
                confidence=ConfidenceLevel.UNCONFIRMED,
                severity=SeverityLevel.INFO
            )
        except Exception as e:
            return create_poc_result(
                poc_id=poc_id,
                poc_name=metadata.get("name", poc_id),
                target=target,
                status=PoCStatus.ERROR,
                error=str(e)
            )
    
    def _match_yaml_response(self, response, matcher: Dict) -> bool:
        """匹配YAML响应"""
        match_type = matcher.get("type", "word")
        
        if match_type == "status":
            expected_status = matcher.get("status", [])
            return response.status_code in expected_status
        
        elif match_type == "word":
            words = matcher.get("words", [])
            for word in words:
                if word.lower() in response.text.lower():
                    return True
            return False
        
        elif match_type == "regex":
            import re
            patterns = matcher.get("regex", [])
            for pattern in patterns:
                if re.search(pattern, response.text):
                    return True
            return False
        
        return False
    
    def execute_multiple_pocs(self, poc_ids: List[str], target: str, max_concurrent: int = None) -> List[PoCVerificationResult]:
        """并发执行多个PoC"""
        if max_concurrent is None:
            max_concurrent = self.config.max_concurrent
        
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            future_to_poc = {
                executor.submit(self.execute_single_poc, poc_id, target): poc_id
                for poc_id in poc_ids
            }
            
            for future in concurrent.futures.as_completed(future_to_poc):
                poc_id = future_to_poc[future]
                try:
                    result = future.result()
                    results.append(result)
                    self._execution_history.append(result)
                except Exception as e:
                    logger.error(f"执行PoC {poc_id} 异常: {e}")
                    results.append(create_poc_result(
                        poc_id=poc_id,
                        poc_name=poc_id,
                        target=target,
                        status=PoCStatus.ERROR,
                        error=str(e)
                    ))
        
        return results
    
    def verify_asset(self, asset: AssetFingerprint) -> AssetVulnerabilityReport:
        """验证资产"""
        matched_poc_ids = self.match_pocs_for_asset(asset)
        
        if not matched_poc_ids:
            return create_asset_report(
                asset_id=asset.product,
                target=asset.product,
                product=asset.product,
                version=asset.version,
                results=[]
            )
        
        results = self.execute_multiple_pocs(matched_poc_ids, asset.product)
        
        return create_asset_report(
            asset_id=asset.product,
            target=asset.product,
            product=asset.product,
            version=asset.version,
            results=results
        )
    
    def get_execution_history(self, limit: int = 100) -> List[PoCVerificationResult]:
        """获取执行历史"""
        return self._execution_history[-limit:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        total = len(self._execution_history)
        vulnerable = sum(1 for r in self._execution_history if r.vulnerable)
        errors = sum(1 for r in self._execution_history if r.status == PoCStatus.ERROR)
        timeouts = sum(1 for r in self._execution_history if r.status == PoCStatus.TIMEOUT)
        
        return {
            "total_executions": total,
            "vulnerabilities_found": vulnerable,
            "errors": errors,
            "timeouts": timeouts,
            "success_rate": (total - errors - timeouts) / total if total > 0 else 0,
            "vulnerability_rate": vulnerable / total if total > 0 else 0
        }
    
    def clear_history(self):
        """清除历史"""
        self._execution_history.clear()
