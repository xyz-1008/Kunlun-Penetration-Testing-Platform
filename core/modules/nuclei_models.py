"""
Nuclei模板数据模型
严格遵循Nuclei YAML模板规范v2.x，使用Pydantic进行数据校验

支持协议: HTTP / DNS / TCP / TLS / SSL / HEADLESS / FILE / WORKFLOW / WEBSOCKET / WHOIS / JAVASCRIPT / CODE / NETWORK
"""

from typing import Dict, List, Optional, Any, Union, Literal
from enum import Enum
from pydantic import BaseModel, Field, field_validator, model_validator
import re


class NucleiSeverity(str, Enum):
    """Nuclei严重级别"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class NucleiProtocol(str, Enum):
    """Nuclei协议类型"""
    HTTP = "http"
    DNS = "dns"
    TCP = "tcp"
    TLS = "tls"
    HEADLESS = "headless"
    FILE = "file"
    WORKFLOW = "workflow"
    SSL = "ssl"
    WEBSOCKET = "websocket"
    WHOIS = "whois"
    JAVASCRIPT = "javascript"
    CODE = "code"
    NETWORK = "network"


class MatcherType(str, Enum):
    """匹配器类型"""
    WORD = "word"
    REGEX = "regex"
    STATUS = "status"
    SIZE = "size"
    DSL = "dsl"
    BINARY = "binary"
    X509 = "x509"


class MatcherPart(str, Enum):
    """匹配位置"""
    HEADER = "header"
    BODY = "body"
    FIRSTLINE = "firstline"
    ALL = "all"
    RAW = "raw"
    STATUS_CODE = "status_code"


class MatcherCondition(str, Enum):
    """匹配条件"""
    AND = "and"
    OR = "or"


class SizeOperator(str, Enum):
    """大小比较运算符"""
    GT = ">"
    LT = "<"
    EQ = "=="
    GTE = ">="
    LTE = "<="


class ExtractorType(str, Enum):
    """提取器类型"""
    REGEX = "regex"
    JSON = "json"
    XPATH = "xpath"
    KVAL = "kval"
    DSL = "dsl"
    QUALITY = "quality"
    BODY = "body"
    HEADER = "header"
    STATUS = "status"


class AttackType(str, Enum):
    """攻击类型"""
    BATTERINGRAM = "batteringram"
    PITCHFORK = "pitchfork"
    CLUSTERBOMB = "clusterbomb"


class HTTPMethod(str, Enum):
    """HTTP方法"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"
    CONNECT = "CONNECT"
    TRACE = "TRACE"


class TemplateClassification(BaseModel):
    """模板分类信息"""
    cve_id: List[str] = Field(default_factory=list, alias="cve-id")
    cwe_id: List[str] = Field(default_factory=list, alias="cwe-id")
    cvss_score: Optional[float] = Field(default=None, alias="cvss-score")
    cvss_metrics: Optional[str] = Field(default=None, alias="cvss-metrics")
    epss_score: Optional[float] = Field(default=None, alias="epss-score")
    epss_percentile: Optional[float] = Field(default=None, alias="epss-percentile")
    cpe: Optional[str] = None

    class Config:
        populate_by_name = True


class TemplateInfo(BaseModel):
    """模板信息"""
    name: str
    author: List[str] = Field(default_factory=list)
    severity: NucleiSeverity = NucleiSeverity.INFO
    description: str = ""
    reference: List[str] = Field(default_factory=list)
    tags: str = ""
    classification: Optional[TemplateClassification] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    remediation: str = ""

    class Config:
        populate_by_name = True


class Matcher(BaseModel):
    """匹配器定义

    支持 AND/OR 逻辑组合，word/regex/status/size/dsl/binary 六种匹配类型，
    可指定匹配位置 (header/body/firstline/all/status_code)，
    支持 negative 反向匹配和 case-insensitive 大小写不敏感。
    支持多层嵌套 matchers（递归AND/OR组合）。
    """
    type: MatcherType
    name: Optional[str] = None
    part: MatcherPart = MatcherPart.BODY
    condition: MatcherCondition = MatcherCondition.OR
    words: List[str] = Field(default_factory=list)
    regex: List[str] = Field(default_factory=list)
    status: List[int] = Field(default_factory=list)
    dsl: List[str] = Field(default_factory=list)
    binary: List[str] = Field(default_factory=list)
    size: Optional[int] = None
    size_operator: SizeOperator = Field(default=SizeOperator.EQ, alias="size-operator")
    negative: bool = False
    case_insensitive: bool = Field(default=False, alias="case-insensitive")
    encoding: str = ""
    match_all: bool = Field(default=False, alias="match-all")
    matchers: List['Matcher'] = Field(default_factory=list)
    matchers_condition: MatcherCondition = Field(default=MatcherCondition.OR, alias="matchers-condition")

    class Config:
        populate_by_name = True


class Extractor(BaseModel):
    """提取器定义

    支持 regex/json/xpath/kval/dsl/body/header/status 七种提取类型，
    提取结果存储为内部变量供后续请求引用。
    """
    type: ExtractorType
    name: Optional[str] = None
    part: MatcherPart = MatcherPart.BODY
    regex: List[str] = Field(default_factory=list)
    json_path: List[str] = Field(default_factory=list, alias="json")
    xpath: List[str] = Field(default_factory=list)
    kval: List[str] = Field(default_factory=list)
    dsl: List[str] = Field(default_factory=list)
    attribute: str = ""
    group: int = 1
    internal: bool = False
    case_insensitive: bool = Field(default=False, alias="case-insensitive")

    class Config:
        populate_by_name = True


class PayloadDefinition(BaseModel):
    """Payload定义"""
    name: str
    type: str = "wordlist"
    file_path: Optional[str] = None
    values: List[str] = Field(default_factory=list)


class RawHTTPRequest(BaseModel):
    """Raw HTTP请求"""
    raw: List[str] = Field(default_factory=list)
    name: Optional[str] = None


class HTTPRequest(BaseModel):
    """HTTP请求定义

    完整支持Nuclei HTTP DSL:
    - method: GET/POST/PUT/DELETE/PATCH/OPTIONS/HEAD/CONNECT/TRACE
    - path: 支持 {{BaseURL}} 等内置变量替换
    - headers: Key-Value格式，支持动态变量和函数调用
    - body: 原始文本、表单数据、JSON、XML、multipart文件上传
    - cookie-reuse: 同一模板内后续请求自动复用前面Set-Cookie
    - redirects: 可配置是否跟随及最大跳数
    - attack: 集群炸弹 (batteringram/pitchfork/clusterbomb)
    - Raw模式: 直接传入完整HTTP请求报文
    - Unsafe模式: 不对特殊字符进行转义
    - Pipeline模式: 同一连接复用发送多个请求
    - Race模式: 同时发送多个请求触发竞态条件
    """
    method: HTTPMethod = HTTPMethod.GET
    path: List[str] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    body: str = ""
    raw: List[str] = Field(default_factory=list)
    name: Optional[str] = None
    attack: Optional[AttackType] = None
    payloads: Dict[str, Any] = Field(default_factory=dict)
    matchers: List[Matcher] = Field(default_factory=list)
    matchers_condition: MatcherCondition = Field(default=MatcherCondition.OR, alias="matchers-condition")
    extractors: List[Extractor] = Field(default_factory=list)
    cookie_reuse: bool = Field(default=False, alias="cookie-reuse")
    redirects: bool = False
    max_redirects: int = Field(default=3, alias="max-redirects")
    max_size: int = Field(default=0, alias="max-size")
    read_all: bool = Field(default=False, alias="read-all")
    unsafe: bool = False
    pipeline: bool = False
    pipeline_concurrent_connections: int = Field(default=40, alias="pipeline-concurrent-connections")
    pipeline_max_requests_per_connection: int = Field(default=100, alias="pipeline-max-requests-per-connection")
    req_condition: bool = Field(default=True, alias="req-condition")
    stop_at_first_match: bool = Field(default=False, alias="stop-at-first-match")
    race_count: int = Field(default=1, alias="race-count")
    threads: int = 1
    iterate_all: bool = Field(default=False, alias="iterate-all")
    skip_variables_check: bool = Field(default=False, alias="skip-variables-check")
    host_redirects: bool = Field(default=False, alias="host-redirects")
    disable_cookie: bool = Field(default=False, alias="disable-cookie")

    class Config:
        populate_by_name = True

    @field_validator("path", mode="before")
    @classmethod
    def ensure_path_list(cls, v: Any) -> List[str]:
        if isinstance(v, str):
            return [v]
        if isinstance(v, list):
            return v
        return ["{{BaseURL}}"]

    @field_validator("method", mode="before")
    @classmethod
    def normalize_method(cls, v: Any) -> HTTPMethod:
        if isinstance(v, str):
            return HTTPMethod(v.upper())
        return v


class NucleiTemplate(BaseModel):
    """Nuclei模板完整定义

    遵循Nuclei YAML模板规范v2.x，包含:
    - id: 模板唯一标识
    - info: 模板元信息 (名称/作者/严重级别/描述/标签/分类)
    - requests: HTTP请求列表
    - dns/tcp/tls/file/headless: 其他协议请求
    - workflow: 工作流定义
    - variables: 模板级变量
    - self_contained: 是否自包含
    """
    id: str
    info: TemplateInfo
    requests: List[HTTPRequest] = Field(default_factory=list, alias="http")
    dns: List[Dict[str, Any]] = Field(default_factory=list)
    tcp: List[Dict[str, Any]] = Field(default_factory=list)
    tls: List[Dict[str, Any]] = Field(default_factory=list)
    file: List[Dict[str, Any]] = Field(default_factory=list)
    headless: List[Dict[str, Any]] = Field(default_factory=list)
    workflow: Optional[str] = None
    variables: Dict[str, Any] = Field(default_factory=dict)
    self_contained: bool = Field(default=False, alias="self-contained")
    source_path: str = ""
    source_type: str = "local"

    class Config:
        populate_by_name = True

    @model_validator(mode="before")
    @classmethod
    def normalize_requests(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        if "http" in data and "requests" not in data:
            data["requests"] = data.pop("http")
        return data

    def get_all_matchers(self) -> List[Matcher]:
        """获取所有匹配器"""
        all_matchers: List[Matcher] = []
        for req in self.requests:
            all_matchers.extend(req.matchers)
        return all_matchers

    def get_all_extractors(self) -> List[Extractor]:
        """获取所有提取器"""
        all_extractors: List[Extractor] = []
        for req in self.requests:
            all_extractors.extend(req.extractors)
        return all_extractors

    def get_fingerprint_conditions(self) -> Dict[str, Any]:
        """提取指纹匹配条件

        从模板的matchers中自动提取指纹特征:
        - word匹配器 → 产品关键词
        - regex匹配器 → 版本正则模式
        - 分类信息 → CPE/CVE编号

        Returns:
            指纹条件字典，包含 template_id/name/tags/severity/products/cpe/words/regex_patterns
        """
        conditions: Dict[str, Any] = {
            "template_id": self.id,
            "name": self.info.name,
            "tags": [t.strip() for t in self.info.tags.split(",") if t.strip()] if self.info.tags else [],
            "severity": self.info.severity.value,
            "products": [],
            "cpe": [],
            "words": [],
            "regex_patterns": [],
        }

        if self.info.classification:
            if self.info.classification.cpe:
                conditions["cpe"].append(self.info.classification.cpe)
            if self.info.classification.cve_id:
                conditions["cve"] = self.info.classification.cve_id

        for matcher in self.get_all_matchers():
            if matcher.type == MatcherType.WORD and matcher.words:
                conditions["words"].extend(matcher.words)
            if matcher.type == MatcherType.REGEX and matcher.regex:
                conditions["regex_patterns"].extend(matcher.regex)

        return conditions


class NucleiVerifyResult(BaseModel):
    """Nuclei验证结果

    统一的验证结果对象，包含:
    - 模板信息: template_id/template_name/severity/author/tags/cve
    - 验证状态: vulnerable/matched/extracted
    - 证据: evidence/request_hex/response_hex
    - 提取数据: extracted_values
    - 性能: response_time
    """
    template_id: str
    template_name: str
    target: str
    vulnerable: bool = False
    matched: bool = False
    extracted: bool = False
    evidence: str = ""
    request_hex: str = ""
    response_hex: str = ""
    extracted_values: Dict[str, Any] = Field(default_factory=dict)
    matcher_name: str = ""
    extractor_name: str = ""
    severity: str = ""
    author: str = ""
    description: str = ""
    tags: List[str] = Field(default_factory=list)
    cve: List[str] = Field(default_factory=list)
    curl_command: str = ""
    response_time: float = 0.0
    error: str = ""
    timestamp: str = ""


class NucleiTemplateStats(BaseModel):
    """模板统计信息

    包含:
    - 数量统计: total/loaded/failed
    - 分类统计: by_severity/by_protocol/by_tags
    - 性能: load_time
    """
    total_templates: int = 0
    loaded_templates: int = 0
    failed_templates: int = 0
    by_severity: Dict[str, int] = Field(default_factory=dict)
    by_protocol: Dict[str, int] = Field(default_factory=dict)
    by_tags: Dict[str, int] = Field(default_factory=dict)
    load_time: float = 0.0
    last_update: str = ""


class FingerprintRule(BaseModel):
    """指纹规则 - 从Nuclei模板matchers自动提取"""
    rule_id: str
    template_id: str
    protocol: str = "http"
    product: str = ""
    words: List[str] = Field(default_factory=list)
    regex_patterns: List[str] = Field(default_factory=list)
    cpe: str = ""
    severity: str = "info"
    confidence: float = 0.5
