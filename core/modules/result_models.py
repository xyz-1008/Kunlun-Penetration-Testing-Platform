"""
结果标准化模块
使用Pydantic模型保证数据格式一致
"""

from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class ConfidenceLevel(str, Enum):
    """置信度级别"""
    CONFIRMED = "确定存在"
    SUSPECTED = "疑似存在"
    UNCONFIRMED = "无法确认"


class SeverityLevel(str, Enum):
    """严重程度"""
    CRITICAL = "严重"
    HIGH = "高危"
    MEDIUM = "中危"
    LOW = "低危"
    INFO = "信息"


class PoCStatus(str, Enum):
    """PoC状态"""
    SUCCESS = "成功"
    FAILED = "失败"
    TIMEOUT = "超时"
    ERROR = "错误"


class OOBChannelType(str, Enum):
    """OOB信道类型"""
    DNS = "dns"
    HTTP = "http"
    LDAP = "ldap"


class OOBRequestModel(BaseModel):
    """OOB请求模型"""
    request_id: str
    timestamp: datetime
    channel: OOBChannelType
    source_ip: str
    data: Dict[str, Any] = Field(default_factory=dict)


class PoCVerificationResult(BaseModel):
    """PoC验证结果模型"""
    poc_id: str
    poc_name: str
    target: str
    status: PoCStatus
    vulnerable: bool = False
    confidence: ConfidenceLevel = ConfidenceLevel.UNCONFIRMED
    severity: SeverityLevel = SeverityLevel.INFO
    cve: str = ""
    evidence: str = ""
    payload: str = ""
    response_summary: str = ""
    oob_requests: List[OOBRequestModel] = Field(default_factory=list)
    execution_time: float = 0.0
    memory_used_mb: float = 0.0
    error: str = ""
    timestamp: datetime = Field(default_factory=datetime.now)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AssetVulnerabilityReport(BaseModel):
    """资产漏洞报告模型"""
    asset_id: str
    target: str
    product: str = ""
    version: str = ""
    total_pocs_executed: int = 0
    vulnerabilities_found: int = 0
    results: List[PoCVerificationResult] = Field(default_factory=list)
    scan_start_time: datetime = Field(default_factory=datetime.now)
    scan_end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    summary: str = ""


class PluginExecutionResult(BaseModel):
    """插件执行结果模型"""
    plugin_id: str
    plugin_name: str
    status: PoCStatus
    output: Dict[str, Any] = Field(default_factory=dict)
    error: str = ""
    execution_time: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.now)


class WorkflowExecutionResult(BaseModel):
    """工作流执行结果模型"""
    workflow_id: str
    workflow_name: str
    status: PoCStatus
    steps: List[PluginExecutionResult] = Field(default_factory=list)
    total_duration: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.now)


class StandardizedResponse(BaseModel):
    """标准化响应模型"""
    success: bool
    message: str = ""
    data: Optional[Any] = None
    error_code: str = ""
    timestamp: datetime = Field(default_factory=datetime.now)


def create_poc_result(
    poc_id: str,
    poc_name: str,
    target: str,
    status: PoCStatus,
    vulnerable: bool = False,
    confidence: ConfidenceLevel = ConfidenceLevel.UNCONFIRMED,
    severity: SeverityLevel = SeverityLevel.INFO,
    cve: str = "",
    evidence: str = "",
    payload: str = "",
    response_summary: str = "",
    execution_time: float = 0.0,
    memory_used_mb: float = 0.0,
    error: str = ""
) -> PoCVerificationResult:
    """创建PoC验证结果"""
    return PoCVerificationResult(
        poc_id=poc_id,
        poc_name=poc_name,
        target=target,
        status=status,
        vulnerable=vulnerable,
        confidence=confidence,
        severity=severity,
        cve=cve,
        evidence=evidence,
        payload=payload,
        response_summary=response_summary,
        execution_time=execution_time,
        memory_used_mb=memory_used_mb,
        error=error
    )


def create_asset_report(
    asset_id: str,
    target: str,
    product: str = "",
    version: str = "",
    results: List[PoCVerificationResult] = None
) -> AssetVulnerabilityReport:
    """创建资产漏洞报告"""
    if results is None:
        results = []
    
    vuln_count = sum(1 for r in results if r.vulnerable)
    
    return AssetVulnerabilityReport(
        asset_id=asset_id,
        target=target,
        product=product,
        version=version,
        total_pocs_executed=len(results),
        vulnerabilities_found=vuln_count,
        results=results
    )
