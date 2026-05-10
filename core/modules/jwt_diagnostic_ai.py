"""
JWT Diagnostic AI Module - Automatic vulnerability inference,
fix suggestion generation, and community knowledge base integration.

This module provides:
    1. Automatic vulnerability cause analysis from attack results
    2. JWT library identification and CVE matching
    3. Code fix suggestion generation for multiple languages
    4. Configuration-level fix recommendations
    5. Community knowledge base synchronization

Integration points:
    - JWT Parser Exploits module
    - JWT Info Leak module
    - OAuth Cross Client module
    - Report generation engine
    - Knowledge base module

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class DiagnosticType(str, Enum):
    """Diagnostic result types."""

    LIBRARY_IDENTIFICATION = "library_identification"
    CVE_MATCHING = "cve_matching"
    ROOT_CAUSE_ANALYSIS = "root_cause_analysis"
    FIX_SUGGESTION = "fix_suggestion"
    CONFIG_RECOMMENDATION = "config_recommendation"


class Language(str, Enum):
    """Programming languages for fix suggestions."""

    PYTHON = "python"
    NODEJS = "nodejs"
    JAVA = "java"
    GO = "go"
    RUST = "rust"
    NGINX = "nginx"


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
class JWTLibraryInfo:
    """JWT library information.

    Attributes:
        name: Library name
        language: Programming language
        version: Library version
        known_vulnerabilities: List of known CVEs
        config_issues: List of common configuration issues
    """

    name: str = ""
    language: Language = Language.PYTHON
    version: str = ""
    known_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    config_issues: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "name": self.name,
            "language": self.language.value,
            "version": self.version,
            "known_vulnerabilities": self.known_vulnerabilities,
            "config_issues": self.config_issues,
        }


@dataclass
class CVEInfo:
    """CVE information for JWT libraries.

    Attributes:
        cve_id: CVE identifier
        library: Affected library
        affected_versions: Affected version range
        severity: CVE severity
        description: CVE description
        fix_version: Version that fixes the vulnerability
        references: List of reference URLs
    """

    cve_id: str = ""
    library: str = ""
    affected_versions: str = ""
    severity: Severity = Severity.INFO
    description: str = ""
    fix_version: str = ""
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "cve_id": self.cve_id,
            "library": self.library,
            "affected_versions": self.affected_versions,
            "severity": self.severity.value,
            "description": self.description,
            "fix_version": self.fix_version,
            "references": self.references,
        }


@dataclass
class FixSuggestion:
    """Code fix suggestion.

    Attributes:
        language: Target programming language
        title: Fix suggestion title
        description: Fix description
        vulnerable_code: Original vulnerable code
        fixed_code: Fixed code example
        explanation: Explanation of the fix
        references: List of reference URLs
    """

    language: Language = Language.PYTHON
    title: str = ""
    description: str = ""
    vulnerable_code: str = ""
    fixed_code: str = ""
    explanation: str = ""
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "language": self.language.value,
            "title": self.title,
            "description": self.description,
            "vulnerable_code": self.vulnerable_code,
            "fixed_code": self.fixed_code,
            "explanation": self.explanation,
            "references": self.references,
        }


@dataclass
class DiagnosticResult:
    """Complete diagnostic result.

    Attributes:
        diagnostic_type: Type of diagnostic
        severity: Result severity
        title: Diagnostic title
        description: Detailed description
        library_info: Identified library information
        matched_cves: List of matched CVEs
        fix_suggestions: List of fix suggestions
        config_recommendations: List of configuration recommendations
        evidence: Supporting evidence
        timestamp: Result timestamp
    """

    diagnostic_type: DiagnosticType = DiagnosticType.ROOT_CAUSE_ANALYSIS
    severity: Severity = Severity.INFO
    title: str = ""
    description: str = ""
    library_info: Optional[JWTLibraryInfo] = None
    matched_cves: List[CVEInfo] = field(default_factory=list)
    fix_suggestions: List[FixSuggestion] = field(default_factory=list)
    config_recommendations: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "diagnostic_type": self.diagnostic_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "library_info": self.library_info.to_dict() if self.library_info else None,
            "matched_cves": [c.to_dict() for c in self.matched_cves],
            "fix_suggestions": [f.to_dict() for f in self.fix_suggestions],
            "config_recommendations": self.config_recommendations,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
        }


@dataclass
class KnowledgeBaseEntry:
    """Community knowledge base entry.

    Attributes:
        entry_id: Unique entry identifier
        vulnerability_type: Type of vulnerability
        target_framework: Target framework/library
        target_version: Target version
        success_rate: Exploit success rate
        description: Entry description
        exploitation_steps: Steps to reproduce
        fix_suggestions: Community fix suggestions
        anonymized: Whether entry is anonymized
        created_at: Entry creation timestamp
        contributor: Contributor identifier (anonymized)
    """

    entry_id: str = ""
    vulnerability_type: str = ""
    target_framework: str = ""
    target_version: str = ""
    success_rate: float = 0.0
    description: str = ""
    exploitation_steps: List[str] = field(default_factory=list)
    fix_suggestions: List[str] = field(default_factory=list)
    anonymized: bool = True
    created_at: float = 0.0
    contributor: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "entry_id": self.entry_id,
            "vulnerability_type": self.vulnerability_type,
            "target_framework": self.target_framework,
            "target_version": self.target_version,
            "success_rate": self.success_rate,
            "description": self.description,
            "exploitation_steps": self.exploitation_steps,
            "fix_suggestions": self.fix_suggestions,
            "anonymized": self.anonymized,
            "created_at": self.created_at,
            "contributor": self.contributor,
        }


# =============================================================================
# JWT Library Vulnerability Database
# =============================================================================

class JWTLibraryVulnDB:
    """Known JWT library vulnerability database.

    Contains CVEs and known vulnerabilities for popular JWT libraries.
    """

    KNOWN_VULNERABILITIES: Dict[str, List[CVEInfo]] = {
        "python-jwt": [
            CVEInfo(
                cve_id="CVE-2022-39228",
                library="python-jwt",
                affected_versions="< 4.0.0",
                severity=Severity.CRITICAL,
                description=(
                    "python-jwt 4.0.0 之前版本存在算法混淆漏洞，"
                    "攻击者可通过修改 JWT Header 中的 alg 字段绕过签名验证。"
                ),
                fix_version="4.0.0",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2022-39228"],
            ),
        ],
        "node-jsonwebtoken": [
            CVEInfo(
                cve_id="CVE-2022-23529",
                library="node-jsonwebtoken",
                affected_versions="< 9.0.0",
                severity=Severity.CRITICAL,
                description=(
                    "jsonwebtoken 9.0.0 之前版本存在密钥注入漏洞，"
                    "攻击者可通过构造特殊的 JWK 密钥绕过签名验证。"
                ),
                fix_version="9.0.0",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2022-23529"],
            ),
            CVEInfo(
                cve_id="CVE-2022-23539",
                library="node-jsonwebtoken",
                affected_versions="< 9.0.0",
                severity=Severity.HIGH,
                description=(
                    "jsonwebtoken 存在不安全的密钥分配问题，"
                    "攻击者可通过指定算法参数进行算法混淆攻击。"
                ),
                fix_version="9.0.0",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2022-23539"],
            ),
            CVEInfo(
                cve_id="CVE-2022-23540",
                library="node-jsonwebtoken",
                affected_versions="< 9.0.0",
                severity=Severity.HIGH,
                description=(
                    "jsonwebtoken 存在密钥混淆漏洞，"
                    "当同时支持 RS256 和 HS256 时，攻击者可使用公钥作为 HMAC 密钥。"
                ),
                fix_version="9.0.0",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2022-23540"],
            ),
            CVEInfo(
                cve_id="CVE-2022-23541",
                library="node-jsonwebtoken",
                affected_versions="< 9.0.0",
                severity=Severity.CRITICAL,
                description=(
                    "jsonwebtoken 存在不安全的 JWK 处理问题，"
                    "攻击者可通过提供恶意 JWK 密钥绕过签名验证。"
                ),
                fix_version="9.0.0",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2022-23541"],
            ),
        ],
        "jjwt": [
            CVEInfo(
                cve_id="CVE-2022-21449",
                library="jjwt",
                affected_versions="< 0.10.0",
                severity=Severity.CRITICAL,
                description=(
                    "Java JWT (jjwt) 存在 ECDSA 签名验证绕过漏洞，"
                    "攻击者可构造无效签名通过验证。"
                ),
                fix_version="0.10.0",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2022-21449"],
            ),
        ],
        "pyjwt": [
            CVEInfo(
                cve_id="CVE-2022-29217",
                library="pyjwt",
                affected_versions="< 2.4.0",
                severity=Severity.CRITICAL,
                description=(
                    "PyJWT 2.4.0 之前版本存在密钥混淆漏洞，"
                    "当同时支持 RS256 和 HS256 时，攻击者可使用公钥作为 HMAC 密钥。"
                ),
                fix_version="2.4.0",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2022-29217"],
            ),
        ],
        "golang-jwt": [
            CVEInfo(
                cve_id="CVE-2022-29155",
                library="golang-jwt",
                affected_versions="< 4.4.2",
                severity=Severity.HIGH,
                description=(
                    "golang-jwt/jwt 存在解析绕过漏洞，"
                    "攻击者可通过构造特殊 JWT 绕过验证。"
                ),
                fix_version="4.4.2",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2022-29155"],
            ),
        ],
    }

    @classmethod
    def get_vulnerabilities(cls, library_name: str) -> List[CVEInfo]:
        """Get known vulnerabilities for a library.

        Args:
            library_name: Library name.

        Returns:
            List of CVEInfo.
        """
        return cls.KNOWN_VULNERABILITIES.get(library_name, [])

    @classmethod
    def get_all_libraries(cls) -> List[str]:
        """Get all known library names.

        Returns:
            List of library names.
        """
        return list(cls.KNOWN_VULNERABILITIES.keys())


# =============================================================================
# Error Message Fingerprint Analyzer
# =============================================================================

class ErrorMessageFingerprintAnalyzer:
    """Analyzes error messages to identify JWT library and version.

    Uses error message patterns to fingerprint the JWT implementation.
    """

    ERROR_PATTERNS: Dict[str, Dict[str, List[str]]] = {
        "python-jwt": {
            "patterns": [
                r"jwt\.exceptions\.",
                r"InvalidTokenError",
                r"ExpiredSignatureError",
                r"DecodeError",
            ],
            "version_patterns": [
                r"python-jwt[=<>!]+\s*([\d.]+)",
            ],
        },
        "node-jsonwebtoken": {
            "patterns": [
                r"JsonWebTokenError",
                r"TokenExpiredError",
                r"NotBeforeError",
                r"invalid signature",
                r"jwt malformed",
            ],
            "version_patterns": [
                r"jsonwebtoken[=<>!]+\s*([\d.]+)",
            ],
        },
        "jjwt": {
            "patterns": [
                r"io\.jsonwebtoken\.",
                r"JwtException",
                r"ExpiredJwtException",
                r"MalformedJwtException",
                r"SignatureException",
            ],
            "version_patterns": [
                r"jjwt[=<>!]+\s*([\d.]+)",
            ],
        },
        "pyjwt": {
            "patterns": [
                r"jwt\.exceptions\.",
                r"InvalidAlgorithmError",
                r"InvalidKeyError",
                r"ImmatureSignatureError",
                r"AudienceError",
            ],
            "version_patterns": [
                r"PyJWT[=<>!]+\s*([\d.]+)",
                r"pyjwt[=<>!]+\s*([\d.]+)",
            ],
        },
        "golang-jwt": {
            "patterns": [
                r"token is malformed",
                r"token is unverifiable",
                r"token is expired",
                r"token is not valid yet",
                r"invalid signing method",
            ],
            "version_patterns": [
                r"golang-jwt/jwt[=<>!]+\s*v?([\d.]+)",
            ],
        },
    }

    @classmethod
    def identify_library(cls, error_message: str) -> Optional[str]:
        """Identify JWT library from error message.

        Args:
            error_message: Error message to analyze.

        Returns:
            Library name if identified.
        """
        for library, patterns in cls.ERROR_PATTERNS.items():
            for pattern in patterns["patterns"]:
                if re.search(pattern, error_message, re.IGNORECASE):
                    return library
        return None

    @classmethod
    def extract_version(cls, error_message: str, library: str) -> Optional[str]:
        """Extract library version from error message.

        Args:
            error_message: Error message to analyze.
            library: Identified library name.

        Returns:
            Version string if found.
        """
        patterns = cls.ERROR_PATTERNS.get(library, {})
        version_patterns = patterns.get("version_patterns", [])

        for pattern in version_patterns:
            match = re.search(pattern, error_message, re.IGNORECASE)
            if match:
                return match.group(1)

        return None


# =============================================================================
# Root Cause Analyzer
# =============================================================================

class RootCauseAnalyzer:
    """Analyzes attack results to determine root cause of vulnerabilities.

    Provides automated analysis of why an attack succeeded.
    """

    VULNERABILITY_PATTERNS: Dict[str, Dict[str, Any]] = {
        "none_algorithm_accepted": {
            "title": "接受 none 算法",
            "description": (
                "服务器接受 alg=none 的 JWT，表示签名验证被完全绕过。"
                "这通常是因为 JWT 库配置错误或使用了不安全的默认设置。"
            ),
            "root_cause": "JWT 库未限制允许的算法列表，或显式允许了 none 算法。",
            "severity": Severity.CRITICAL,
        },
        "rs256_to_hs256_accepted": {
            "title": "RS256 降级为 HS256 被接受",
            "description": (
                "服务器接受将 RS256 降级为 HS256 的 JWT，"
                "表示存在算法混淆漏洞。"
            ),
            "root_cause": (
                "JWT 验证代码未固定算法类型，"
                "允许攻击者将非对称算法降级为对称算法。"
            ),
            "severity": Severity.CRITICAL,
        },
        "kid_injection_successful": {
            "title": "kid 参数注入成功",
            "description": (
                "JWT Header 中的 kid 参数未进行适当验证，"
                "允许路径遍历或 SQL 注入。"
            ),
            "root_cause": (
                "kid 参数直接用于文件系统路径或数据库查询，"
                "未进行白名单验证或参数化查询。"
            ),
            "severity": Severity.HIGH,
        },
        "claim_tampering_accepted": {
            "title": "JWT 声明篡改被接受",
            "description": (
                "服务器接受篡改过的 JWT Payload，"
                "表示签名验证未正确实施。"
            ),
            "root_cause": (
                "JWT 签名验证被跳过或实现错误，"
                "导致任何修改的 Payload 都被接受。"
            ),
            "severity": Severity.CRITICAL,
        },
        "expired_token_accepted": {
            "title": "过期令牌被接受",
            "description": (
                "服务器接受已过期的 JWT，"
                "表示过期时间验证被跳过。"
            ),
            "root_cause": (
                "JWT 验证代码未检查 exp 声明，"
                "或忽略了过期验证配置。"
            ),
            "severity": Severity.HIGH,
        },
        "missing_state_oauth": {
            "title": "OAuth 缺少 state 参数",
            "description": (
                "OAuth 授权请求未使用 state 参数，"
                "存在 CSRF 攻击风险。"
            ),
            "root_cause": (
                "OAuth 客户端实现未生成和验证 state 参数，"
                "或授权服务器未强制要求。"
            ),
            "severity": Severity.HIGH,
        },
    }

    @classmethod
    def analyze(
        cls,
        attack_type: str,
        evidence: Dict[str, Any],
    ) -> DiagnosticResult:
        """Analyze attack results for root cause.

        Args:
            attack_type: Type of attack performed.
            evidence: Evidence from the attack.

        Returns:
            DiagnosticResult with analysis.
        """
        pattern = cls.VULNERABILITY_PATTERNS.get(attack_type, {})

        if not pattern:
            return DiagnosticResult(
                diagnostic_type=DiagnosticType.ROOT_CAUSE_ANALYSIS,
                severity=Severity.INFO,
                title="未知攻击类型",
                description="无法识别的攻击类型。",
                evidence=evidence,
                timestamp=time.time(),
            )

        return DiagnosticResult(
            diagnostic_type=DiagnosticType.ROOT_CAUSE_ANALYSIS,
            severity=pattern.get("severity", Severity.INFO),
            title=pattern.get("title", ""),
            description=pattern.get("description", ""),
            evidence=evidence,
            timestamp=time.time(),
        )


# =============================================================================
# Fix Suggestion Generator
# =============================================================================

class FixSuggestionGenerator:
    """Generates code fix suggestions for JWT/OAuth vulnerabilities.

    Provides fixes for multiple languages and frameworks.
    """

    FIX_TEMPLATES: Dict[str, Dict[Language, FixSuggestion]] = {
        "none_algorithm_accepted": {
            Language.PYTHON: FixSuggestion(
                language=Language.PYTHON,
                title="修复 none 算法绕过",
                description="在 JWT 验证中明确指定允许的算法列表。",
                vulnerable_code=(
                    "# 不安全：未限制算法\n"
                    "payload = jwt.decode(token, secret, algorithms=None)"
                ),
                fixed_code=(
                    "# 安全：明确指定允许的算法\n"
                    "payload = jwt.decode(\n"
                    "    token,\n"
                    "    secret,\n"
                    "    algorithms=['RS256', 'ES256']\n"
                    ")"
                ),
                explanation=(
                    "始终明确指定 algorithms 参数，"
                    "禁止使用 None 或空列表。"
                ),
                references=[
                    "https://pyjwt.readthedocs.io/en/stable/algorithms.html",
                ],
            ),
            Language.NODEJS: FixSuggestion(
                language=Language.NODEJS,
                title="修复 none 算法绕过",
                description="在 JWT 验证中明确指定允许的算法。",
                vulnerable_code=(
                    "// 不安全：未限制算法\n"
                    "jwt.verify(token, secret);"
                ),
                fixed_code=(
                    "// 安全：明确指定允许的算法\n"
                    "jwt.verify(token, secret, {\n"
                    "  algorithms: ['RS256', 'ES256']\n"
                    "});"
                ),
                explanation=(
                    "在 jsonwebtoken 的 verify 方法中始终指定 algorithms 选项。"
                ),
                references=[
                    "https://github.com/auth0/node-jsonwebtoken#algorithms",
                ],
            ),
            Language.JAVA: FixSuggestion(
                language=Language.JAVA,
                title="修复 none 算法绕过",
                description="在 JWT 验证中明确指定允许的算法。",
                vulnerable_code=(
                    "// 不安全：未限制算法\n"
                    "Jwts.parser().parseClaimsJws(token);"
                ),
                fixed_code=(
                    "// 安全：明确指定允许的算法\n"
                    "Jwts.parserBuilder()\n"
                    "    .setSigningKey(key)\n"
                    "    .build()\n"
                    "    .parseClaimsJws(token);"
                ),
                explanation=(
                    "使用 JJWT 的 parserBuilder 明确指定签名密钥和算法。"
                ),
                references=[
                    "https://github.com/jwtk/jjwt",
                ],
            ),
        },
        "rs256_to_hs256_accepted": {
            Language.PYTHON: FixSuggestion(
                language=Language.PYTHON,
                title="修复算法混淆漏洞",
                description="使用公钥验证时仅允许非对称算法。",
                vulnerable_code=(
                    "# 不安全：同时允许对称和非对称算法\n"
                    "jwt.decode(token, public_key, algorithms=['RS256', 'HS256'])"
                ),
                fixed_code=(
                    "# 安全：仅允许非对称算法\n"
                    "jwt.decode(token, public_key, algorithms=['RS256'])"
                ),
                explanation=(
                    "当使用公钥验证时，仅允许非对称算法（RS256、ES256等），"
                    "禁止同时允许对称算法（HS256）。"
                ),
                references=[
                    "https://pyjwt.readthedocs.io/en/stable/algorithms.html",
                ],
            ),
            Language.NODEJS: FixSuggestion(
                language=Language.NODEJS,
                title="修复算法混淆漏洞",
                description="使用公钥验证时仅允许非对称算法。",
                vulnerable_code=(
                    "// 不安全：同时允许对称和非对称算法\n"
                    "jwt.verify(token, publicKey, {\n"
                    "  algorithms: ['RS256', 'HS256']\n"
                    "});"
                ),
                fixed_code=(
                    "// 安全：仅允许非对称算法\n"
                    "jwt.verify(token, publicKey, {\n"
                    "  algorithms: ['RS256']\n"
                    "});"
                ),
                explanation=(
                    "当使用公钥验证时，algorithms 选项仅包含非对称算法。"
                ),
                references=[
                    "https://github.com/auth0/node-jsonwebtoken#algorithms",
                ],
            ),
        },
        "kid_injection_successful": {
            Language.PYTHON: FixSuggestion(
                language=Language.PYTHON,
                title="修复 kid 注入漏洞",
                description="对 kid 参数进行白名单验证。",
                vulnerable_code=(
                    "# 不安全：直接使用 kid 作为文件路径\n"
                    "key = open(f'keys/{kid}.pem').read()"
                ),
                fixed_code=(
                    "# 安全：使用白名单验证 kid\n"
                    "ALLOWED_KIDS = {'key1', 'key2', 'key3'}\n"
                    "if kid not in ALLOWED_KIDS:\n"
                    "    raise ValueError('Invalid kid')\n"
                    "key = get_key_from_secure_store(kid)"
                ),
                explanation=(
                    "kid 参数应使用白名单验证，禁止直接用于"
                    "文件系统路径或数据库查询。"
                ),
                references=[],
            ),
        },
        "claim_tampering_accepted": {
            Language.PYTHON: FixSuggestion(
                language=Language.PYTHON,
                title="修复 JWT 声明篡改",
                description="确保 JWT 签名被正确验证。",
                vulnerable_code=(
                    "# 不安全：跳过签名验证\n"
                    "payload = jwt.decode(token, options={'verify_signature': False})"
                ),
                fixed_code=(
                    "# 安全：强制验证签名\n"
                    "payload = jwt.decode(\n"
                    "    token,\n"
                    "    secret,\n"
                    "    algorithms=['RS256'],\n"
                    "    options={'verify_signature': True}\n"
                    ")"
                ),
                explanation=(
                    "永远不要禁用签名验证。"
                    "始终验证 JWT 签名以确保完整性。"
                ),
                references=[],
            ),
        },
    }

    @classmethod
    def generate_fixes(
        cls,
        vulnerability_type: str,
        languages: Optional[List[Language]] = None,
    ) -> List[FixSuggestion]:
        """Generate fix suggestions for a vulnerability.

        Args:
            vulnerability_type: Type of vulnerability.
            languages: Target languages for fixes.

        Returns:
            List of FixSuggestion.
        """
        templates = cls.FIX_TEMPLATES.get(vulnerability_type, {})

        if languages:
            return [
                templates[lang]
                for lang in languages
                if lang in templates
            ]

        return list(templates.values())

    @classmethod
    def generate_config_recommendations(
        cls,
        vulnerability_type: str,
    ) -> List[str]:
        """Generate configuration-level recommendations.

        Args:
            vulnerability_type: Type of vulnerability.

        Returns:
            List of recommendation strings.
        """
        recommendations: Dict[str, List[str]] = {
            "none_algorithm_accepted": [
                "在 Nginx 反向代理层统一验证 JWT，禁止将未验证的请求转发到后端。",
                "配置 WAF 规则，拦截 alg=none 的 JWT 请求。",
                "在 API 网关层实施 JWT 验证，确保所有请求都经过验证。",
            ],
            "rs256_to_hs256_accepted": [
                "在负载均衡器或 API 网关层固定 JWT 算法，禁止客户端指定算法。",
                "使用专用的 JWT 验证中间件，统一管理算法策略。",
                "在 CI/CD 流程中添加安全测试，检测算法混淆漏洞。",
            ],
            "kid_injection_successful": [
                "使用密钥管理服务（如 AWS KMS、HashiCorp Vault）管理 JWT 密钥。",
                "禁止在 JWT Header 中暴露 kid 参数，使用内部密钥映射。",
                "在 WAF 中配置路径遍历和 SQL 注入规则。",
            ],
            "claim_tampering_accepted": [
                "在所有 API 端点统一实施 JWT 验证中间件。",
                "使用服务网格（如 Istio）在网格层验证 JWT。",
                "在 API 网关层配置 JWT 验证策略。",
            ],
            "expired_token_accepted": [
                "配置 JWT 验证中间件强制检查 exp 声明。",
                "在 Nginx 中使用 lua-resty-jwt 模块验证令牌过期时间。",
                "设置合理的令牌过期时间（建议不超过 1 小时）。",
            ],
            "missing_state_oauth": [
                "在 OAuth 客户端中强制生成和验证 state 参数。",
                "使用 PKCE 替代 state 参数提供额外保护。",
                "在 API 网关层检查 OAuth 请求中的 state 参数。",
            ],
        }

        return recommendations.get(vulnerability_type, [
            "审查 JWT 验证配置，确保所有安全选项都已启用。",
            "使用最新的 JWT 库版本，修复已知漏洞。",
            "定期进行安全审计和渗透测试。",
        ])


# =============================================================================
# Community Knowledge Base
# =============================================================================

class CommunityKnowledgeBase:
    """Community knowledge base for JWT/OAuth vulnerability cases.

    Provides:
    - Upload anonymized exploitation cases
    - Search for similar cases
    - Success rate statistics
    - Framework-specific recommendations
    """

    def __init__(self) -> None:
        """Initialize the community knowledge base."""
        self.entries: List[KnowledgeBaseEntry] = []
        self.entry_counter = 0

    def _next_entry_id(self) -> str:
        """Generate next entry ID.

        Returns:
            Entry ID string.
        """
        self.entry_counter += 1
        return f"KB-{self.entry_counter:04d}"

    def add_entry(
        self,
        vulnerability_type: str,
        target_framework: str,
        target_version: str,
        description: str,
        exploitation_steps: List[str],
        fix_suggestions: List[str],
        success_rate: float = 0.0,
        anonymized: bool = True,
        contributor: str = "",
    ) -> KnowledgeBaseEntry:
        """Add a knowledge base entry.

        Args:
            vulnerability_type: Type of vulnerability.
            target_framework: Target framework/library.
            target_version: Target version.
            description: Entry description.
            exploitation_steps: Steps to reproduce.
            fix_suggestions: Community fix suggestions.
            success_rate: Exploit success rate.
            anonymized: Whether entry is anonymized.
            contributor: Contributor identifier.

        Returns:
            Created KnowledgeBaseEntry.
        """
        entry = KnowledgeBaseEntry(
            entry_id=self._next_entry_id(),
            vulnerability_type=vulnerability_type,
            target_framework=target_framework,
            target_version=target_version,
            success_rate=success_rate,
            description=description,
            exploitation_steps=exploitation_steps,
            fix_suggestions=fix_suggestions,
            anonymized=anonymized,
            created_at=time.time(),
            contributor=contributor or "anonymous",
        )

        self.entries.append(entry)
        logger.info(f"Knowledge base entry added: {entry.entry_id}")

        return entry

    def search_similar_cases(
        self,
        vulnerability_type: str,
        target_framework: str = "",
        target_version: str = "",
    ) -> List[KnowledgeBaseEntry]:
        """Search for similar cases in knowledge base.

        Args:
            vulnerability_type: Type of vulnerability.
            target_framework: Target framework/library.
            target_version: Target version.

        Returns:
            List of matching KnowledgeBaseEntry.
        """
        results: List[KnowledgeBaseEntry] = []

        for entry in self.entries:
            if entry.vulnerability_type != vulnerability_type:
                continue

            if target_framework and entry.target_framework != target_framework:
                continue

            if target_version and entry.target_version != target_version:
                continue

            results.append(entry)

        return results

    def get_success_rate(
        self,
        vulnerability_type: str,
        target_framework: str = "",
    ) -> float:
        """Get average success rate for a vulnerability type.

        Args:
            vulnerability_type: Type of vulnerability.
            target_framework: Target framework/library.

        Returns:
            Average success rate (0.0 to 1.0).
        """
        matching_entries = [
            e for e in self.entries
            if e.vulnerability_type == vulnerability_type
            and (not target_framework or e.target_framework == target_framework)
        ]

        if not matching_entries:
            return 0.0

        return sum(e.success_rate for e in matching_entries) / len(matching_entries)

    def get_framework_recommendations(
        self,
        framework: str,
    ) -> List[str]:
        """Get recommendations for a specific framework.

        Args:
            framework: Framework/library name.

        Returns:
            List of recommendation strings.
        """
        recommendations: Set[str] = set()

        for entry in self.entries:
            if entry.target_framework == framework:
                recommendations.update(entry.fix_suggestions)

        return list(recommendations)


# =============================================================================
# Main Diagnostic AI Manager
# =============================================================================

class JWTDiagnosticAIManager:
    """Main JWT diagnostic AI coordination engine.

    Integrates library identification, CVE matching, root cause analysis,
    fix suggestion generation, and community knowledge base.

    Attributes:
        vuln_db: JWT library vulnerability database
        knowledge_base: Community knowledge base
    """

    def __init__(self) -> None:
        """Initialize the JWT diagnostic AI manager."""
        self.vuln_db = JWTLibraryVulnDB()
        self.knowledge_base = CommunityKnowledgeBase()

    def analyze_error_message(
        self,
        error_message: str,
    ) -> DiagnosticResult:
        """Analyze error message to identify JWT library and version.

        Args:
            error_message: Error message to analyze.

        Returns:
            DiagnosticResult with analysis.
        """
        library = ErrorMessageFingerprintAnalyzer.identify_library(
            error_message
        )

        if not library:
            return DiagnosticResult(
                diagnostic_type=DiagnosticType.LIBRARY_IDENTIFICATION,
                severity=Severity.INFO,
                title="无法识别 JWT 库",
                description="无法从错误消息中识别 JWT 库。",
                evidence={"error_message": error_message},
                timestamp=time.time(),
            )

        version = ErrorMessageFingerprintAnalyzer.extract_version(
            error_message, library
        )

        library_info = JWTLibraryInfo(
            name=library,
            version=version or "unknown",
            known_vulnerabilities=[
                cve.to_dict()
                for cve in self.vuln_db.get_vulnerabilities(library)
            ],
        )

        matched_cves = self.vuln_db.get_vulnerabilities(library)

        return DiagnosticResult(
            diagnostic_type=DiagnosticType.LIBRARY_IDENTIFICATION,
            severity=Severity.HIGH,
            title=f"识别到 JWT 库: {library}",
            description=f"从错误消息中识别到 {library} (版本: {version or 'unknown'})。",
            library_info=library_info,
            matched_cves=matched_cves,
            evidence={"error_message": error_message},
            timestamp=time.time(),
        )

    def analyze_attack_result(
        self,
        attack_type: str,
        evidence: Dict[str, Any],
    ) -> DiagnosticResult:
        """Analyze attack result for root cause.

        Args:
            attack_type: Type of attack performed.
            evidence: Evidence from the attack.

        Returns:
            DiagnosticResult with analysis.
        """
        root_cause = RootCauseAnalyzer.analyze(attack_type, evidence)

        fix_suggestions = FixSuggestionGenerator.generate_fixes(attack_type)
        config_recommendations = FixSuggestionGenerator.generate_config_recommendations(
            attack_type
        )

        root_cause.fix_suggestions = fix_suggestions
        root_cause.config_recommendations = config_recommendations

        similar_cases = self.knowledge_base.search_similar_cases(attack_type)

        if similar_cases:
            root_cause.evidence["similar_cases"] = [
                c.to_dict() for c in similar_cases
            ]
            root_cause.evidence["community_success_rate"] = (
                self.knowledge_base.get_success_rate(attack_type)
            )

        return root_cause

    def generate_fix_report(
        self,
        vulnerability_type: str,
        languages: Optional[List[Language]] = None,
    ) -> Dict[str, Any]:
        """Generate comprehensive fix report.

        Args:
            vulnerability_type: Type of vulnerability.
            languages: Target languages for fixes.

        Returns:
            Dictionary with fix report.
        """
        fix_suggestions = FixSuggestionGenerator.generate_fixes(
            vulnerability_type, languages
        )

        config_recommendations = FixSuggestionGenerator.generate_config_recommendations(
            vulnerability_type
        )

        matched_cves = []
        for lib_name in self.vuln_db.get_all_libraries():
            for cve in self.vuln_db.get_vulnerabilities(lib_name):
                if vulnerability_type.lower() in cve.description.lower():
                    matched_cves.append(cve)

        similar_cases = self.knowledge_base.search_similar_cases(
            vulnerability_type
        )

        return {
            "vulnerability_type": vulnerability_type,
            "fix_suggestions": [f.to_dict() for f in fix_suggestions],
            "config_recommendations": config_recommendations,
            "matched_cves": [c.to_dict() for c in matched_cves],
            "similar_community_cases": [c.to_dict() for c in similar_cases],
            "community_success_rate": self.knowledge_base.get_success_rate(
                vulnerability_type
            ),
        }

    def add_community_case(
        self,
        vulnerability_type: str,
        target_framework: str,
        target_version: str,
        description: str,
        exploitation_steps: List[str],
        fix_suggestions: List[str],
        success_rate: float = 0.0,
        contributor: str = "",
    ) -> KnowledgeBaseEntry:
        """Add a community knowledge base case.

        Args:
            vulnerability_type: Type of vulnerability.
            target_framework: Target framework/library.
            target_version: Target version.
            description: Case description.
            exploitation_steps: Steps to reproduce.
            fix_suggestions: Community fix suggestions.
            success_rate: Exploit success rate.
            contributor: Contributor identifier.

        Returns:
            Created KnowledgeBaseEntry.
        """
        return self.knowledge_base.add_entry(
            vulnerability_type=vulnerability_type,
            target_framework=target_framework,
            target_version=target_version,
            description=description,
            exploitation_steps=exploitation_steps,
            fix_suggestions=fix_suggestions,
            success_rate=success_rate,
            contributor=contributor,
        )
