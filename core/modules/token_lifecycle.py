"""
Token Lifecycle Module - Token logout invalidation, refresh token abuse, token chain integrity.

This module provides:
    1. Token logout invalidation testing
    2. Refresh token abuse detection
    3. Token chain integrity verification
    4. Token lifecycle tracking and analysis

Integration points:
    - MITM proxy traffic capture
    - JWT Editor module
    - OAuth Analyzer module
    - Passive scanning engine

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class TokenStatus(str, Enum):
    """Token lifecycle status."""

    ACTIVE = "active"
    LOGGED_OUT = "logged_out"
    EXPIRED = "expired"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


class LifecycleTestType(str, Enum):
    """Lifecycle test types."""

    LOGOUT_INVALIDATION = "logout_invalidation"
    REFRESH_REUSE = "refresh_reuse"
    REFRESH_CLIENT_BINDING = "refresh_client_binding"
    REFRESH_EXPIRATION = "refresh_expiration"
    CHAIN_SKIP = "chain_skip"
    CHAIN_REPLAY = "chain_replay"


class TokenChainIntegrity(str, Enum):
    """Token chain integrity levels."""

    SECURE = "secure"
    WEAK = "weak"
    BROKEN = "broken"
    UNKNOWN = "unknown"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class TokenRecord:
    """Token lifecycle record.

    Attributes:
        token_hash: Hashed token value (for security)
        token_type: Token type (JWT, access_token, refresh_token)
        status: Current token status
        created_at: Token creation timestamp
        logged_out_at: Logout timestamp (if applicable)
        last_used_at: Last usage timestamp
        usage_count: Number of times used
        associated_user: Associated user identifier
        associated_client: Associated client identifier
    """

    token_hash: str = ""
    token_type: str = ""
    status: TokenStatus = TokenStatus.UNKNOWN
    created_at: float = 0.0
    logged_out_at: float = 0.0
    last_used_at: float = 0.0
    usage_count: int = 0
    associated_user: str = ""
    associated_client: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "token_hash": self.token_hash,
            "token_type": self.token_type,
            "status": self.status.value,
            "created_at": self.created_at,
            "logged_out_at": self.logged_out_at,
            "last_used_at": self.last_used_at,
            "usage_count": self.usage_count,
            "associated_user": self.associated_user,
            "associated_client": self.associated_client,
        }


@dataclass
class LogoutTestResult:
    """Token logout invalidation test result.

    Attributes:
        test_id: Unique test ID
        token_record: Tested token record
        still_valid_after_logout: Whether token still works after logout
        test_duration: Duration token remained valid after logout
        attempts_made: Number of test attempts
        severity: Finding severity
        description: Test description
        recommendation: Remediation recommendation
    """

    test_id: str = ""
    token_record: Optional[TokenRecord] = None
    still_valid_after_logout: bool = False
    test_duration: float = 0.0
    attempts_made: int = 0
    severity: str = "low"
    description: str = ""
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "test_id": self.test_id,
            "token_record": self.token_record.to_dict() if self.token_record else {},
            "still_valid_after_logout": self.still_valid_after_logout,
            "test_duration": self.test_duration,
            "attempts_made": self.attempts_made,
            "severity": self.severity,
            "description": self.description,
            "recommendation": self.recommendation,
        }


@dataclass
class RefreshTokenFinding:
    """Refresh token abuse finding.

    Attributes:
        finding_id: Unique finding ID
        test_type: Test type performed
        refresh_token_hash: Hashed refresh token
        reuse_detected: Whether reuse was detected
        client_binding_missing: Whether client binding is missing
        excessive_lifetime: Whether lifetime is excessive
        lifetime_hours: Token lifetime in hours
        severity: Finding severity
        description: Finding description
        recommendation: Remediation recommendation
    """

    finding_id: str = ""
    test_type: LifecycleTestType = LifecycleTestType.REFRESH_REUSE
    refresh_token_hash: str = ""
    reuse_detected: bool = False
    client_binding_missing: bool = False
    excessive_lifetime: bool = False
    lifetime_hours: float = 0.0
    severity: str = "low"
    description: str = ""
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "finding_id": self.finding_id,
            "test_type": self.test_type.value,
            "refresh_token_hash": self.refresh_token_hash,
            "reuse_detected": self.reuse_detected,
            "client_binding_missing": self.client_binding_missing,
            "excessive_lifetime": self.excessive_lifetime,
            "lifetime_hours": self.lifetime_hours,
            "severity": self.severity,
            "description": self.description,
            "recommendation": self.recommendation,
        }


@dataclass
class TokenChainIntegrityResult:
    """Token chain integrity test result.

    Attributes:
        chain_id: Unique chain ID
        integrity_level: Chain integrity level
        total_steps: Total steps in chain
        weak_steps: Number of weak steps
        skippable_steps: Steps that can be skipped
        replayable_steps: Steps that can be replayed
        vulnerabilities: Detected vulnerabilities
        attack_graph: Attack graph representation
    """

    chain_id: str = ""
    integrity_level: TokenChainIntegrity = TokenChainIntegrity.UNKNOWN
    total_steps: int = 0
    weak_steps: int = 0
    skippable_steps: int = 0
    replayable_steps: int = 0
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    attack_graph: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "chain_id": self.chain_id,
            "integrity_level": self.integrity_level.value,
            "total_steps": self.total_steps,
            "weak_steps": self.weak_steps,
            "skippable_steps": self.skippable_steps,
            "replayable_steps": self.replayable_steps,
            "vulnerabilities": self.vulnerabilities,
            "attack_graph": self.attack_graph,
        }


# =============================================================================
# Token Logout Invalidation Tester
# =============================================================================

class TokenLogoutTester:
    """Tests whether tokens are properly invalidated after logout.

    Monitors logout events and tests whether previously used
    tokens can still access protected resources.

    Attributes:
        _token_records: Tracked token records
        _test_results: Test results
        _test_counter: Test counter
    """

    def __init__(self) -> None:
        """Initialize the TokenLogoutTester."""
        self._token_records: Dict[str, TokenRecord] = {}
        self._test_results: List[LogoutTestResult] = []
        self._test_counter = 0

    def track_token(self, token: str, token_type: str = "jwt", user: str = "", client: str = "") -> str:
        """Track a token for logout testing.

        Args:
            token: Token value to track.
            token_type: Type of token.
            user: Associated user identifier.
            client: Associated client identifier.

        Returns:
            Token hash identifier.
        """
        token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]

        record = TokenRecord(
            token_hash=token_hash,
            token_type=token_type,
            status=TokenStatus.ACTIVE,
            created_at=time.time(),
            last_used_at=time.time(),
            usage_count=1,
            associated_user=user,
            associated_client=client,
        )

        self._token_records[token_hash] = record
        return token_hash

    def mark_token_logged_out(self, token_hash: str) -> None:
        """Mark a token as logged out.

        Args:
            token_hash: Token hash to mark.
        """
        if token_hash in self._token_records:
            self._token_records[token_hash].status = TokenStatus.LOGGED_OUT
            self._token_records[token_hash].logged_out_at = time.time()

    async def test_logout_invalidation(
        self,
        token: str,
        protected_urls: List[str],
        headers_template: Optional[Dict[str, str]] = None,
        test_interval: float = 5.0,
        max_duration: float = 300.0,
    ) -> LogoutTestResult:
        """Test if a token is properly invalidated after logout.

        Args:
            token: Token to test.
            protected_urls: URLs to test access against.
            headers_template: Base headers template.
            test_interval: Seconds between test attempts.
            max_duration: Maximum test duration in seconds.

        Returns:
            LogoutTestResult with findings.
        """
        self._test_counter += 1
        token_hash = self.track_token(token)
        self.mark_token_logged_out(token_hash)

        result = LogoutTestResult(
            test_id=f"LOGOUT-TEST-{self._test_counter:04d}",
            token_record=self._token_records.get(token_hash),
        )

        start_time = time.time()
        attempts = 0
        still_valid = False

        while time.time() - start_time < max_duration:
            attempts += 1
            valid = await self._test_token_access(
                token=token,
                urls=protected_urls,
                headers=headers_template,
            )

            if valid:
                still_valid = True
                result.attempts_made = attempts
                result.test_duration = time.time() - start_time
                break

            await asyncio.sleep(test_interval)

        result.still_valid_after_logout = still_valid
        result.attempts_made = attempts
        result.test_duration = time.time() - start_time

        if still_valid:
            result.severity = "critical"
            result.description = (
                f"令牌在登出后{result.test_duration:.1f}秒内仍然有效，"
                f"经过{attempts}次测试仍可访问受保护资源。"
            )
            result.recommendation = (
                "实现令牌黑名单机制，登出时立即使令牌失效。"
                "使用短期令牌配合刷新令牌，减少令牌泄露窗口。"
            )
        else:
            result.severity = "low"
            result.description = "令牌在登出后正确失效，无法访问受保护资源。"
            result.recommendation = ""

        self._test_results.append(result)
        return result

    async def _test_token_access(
        self,
        token: str,
        urls: List[str],
        headers: Optional[Dict[str, str]] = None,
    ) -> bool:
        """Test if a token can access protected resources.

        Args:
            token: Token to test.
            urls: URLs to test.
            headers: Base headers.

        Returns:
            True if token can access resources.
        """
        try:
            import aiohttp

            request_headers = headers.copy() if headers else {}
            request_headers["Authorization"] = f"Bearer {token}"

            async with aiohttp.ClientSession() as session:
                for url in urls:
                    async with session.get(
                        url,
                        headers=request_headers,
                        timeout=aiohttp.ClientTimeout(total=5),
                    ) as resp:
                        if resp.status == 200:
                            return True

            return False
        except Exception as e:
            logger.error(f"Token access test failed: {e}")
            return False

    def get_test_results(self) -> List[LogoutTestResult]:
        """Get all logout test results.

        Returns:
            List of LogoutTestResult.
        """
        return self._test_results.copy()


# =============================================================================
# Refresh Token Abuse Tester
# =============================================================================

class RefreshTokenAbuseTester:
    """Tests for refresh token abuse scenarios.

    Detects whether refresh tokens can be reused,
    are properly bound to clients, and have reasonable lifetimes.

    Attributes:
        _findings: Test findings
        _finding_counter: Finding counter
    """

    def __init__(self) -> None:
        """Initialize the RefreshTokenAbuseTester."""
        self._findings: List[RefreshTokenFinding] = []
        self._finding_counter = 0

    async def test_refresh_token_reuse(
        self,
        refresh_token: str,
        token_endpoint: str,
        client_id: str = "",
        client_secret: str = "",
        max_attempts: int = 5,
    ) -> RefreshTokenFinding:
        """Test if a refresh token can be reused multiple times.

        Args:
            refresh_token: Refresh token to test.
            token_endpoint: Token endpoint URL.
            client_id: OAuth client ID.
            client_secret: OAuth client secret.
            max_attempts: Maximum reuse attempts.

        Returns:
            RefreshTokenFinding with test results.
        """
        self._finding_counter += 1
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()[:16]

        finding = RefreshTokenFinding(
            finding_id=f"REFRESH-REUSE-{self._finding_counter:04d}",
            test_type=LifecycleTestType.REFRESH_REUSE,
            refresh_token_hash=token_hash,
        )

        reuse_count = 0

        for attempt in range(max_attempts):
            success = await self._attempt_refresh(
                refresh_token=refresh_token,
                token_endpoint=token_endpoint,
                client_id=client_id,
                client_secret=client_secret,
            )

            if success:
                reuse_count += 1

        finding.reuse_detected = reuse_count > 1

        if finding.reuse_detected:
            finding.severity = "critical"
            finding.description = (
                f"Refresh Token可重复使用{reuse_count}次，"
                f"存在令牌滥用风险。每次刷新后旧令牌应立即失效。"
            )
            finding.recommendation = (
                "实现Refresh Token轮换机制，每次刷新后使旧令牌失效。"
                "实施Refresh Token一次性使用策略。"
            )
        else:
            finding.severity = "low"
            finding.description = "Refresh Token在首次使用后正确失效。"
            finding.recommendation = ""

        self._findings.append(finding)
        return finding

    async def test_refresh_token_client_binding(
        self,
        refresh_token: str,
        token_endpoint: str,
        original_client_id: str,
        test_client_ids: Optional[List[str]] = None,
    ) -> RefreshTokenFinding:
        """Test if a refresh token is bound to a specific client.

        Args:
            refresh_token: Refresh token to test.
            token_endpoint: Token endpoint URL.
            original_client_id: Original client ID.
            test_client_ids: Client IDs to test against.

        Returns:
            RefreshTokenFinding with test results.
        """
        self._finding_counter += 1
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()[:16]

        finding = RefreshTokenFinding(
            finding_id=f"REFRESH-BINDING-{self._finding_counter:04d}",
            test_type=LifecycleTestType.REFRESH_CLIENT_BINDING,
            refresh_token_hash=token_hash,
        )

        if not test_client_ids:
            test_client_ids = ["test_client_1", "test_client_2", "admin_client"]

        cross_client_success = False

        for client_id in test_client_ids:
            if client_id == original_client_id:
                continue

            success = await self._attempt_refresh(
                refresh_token=refresh_token,
                token_endpoint=token_endpoint,
                client_id=client_id,
            )

            if success:
                cross_client_success = True
                break

        finding.client_binding_missing = cross_client_success

        if finding.client_binding_missing:
            finding.severity = "high"
            finding.description = (
                "Refresh Token未绑定特定客户端，"
                "可被其他客户端使用进行令牌刷新。"
            )
            finding.recommendation = (
                "将Refresh Token与客户端ID绑定，"
                "确保只有原始客户端可以使用该令牌刷新。"
            )
        else:
            finding.severity = "low"
            finding.description = "Refresh Token正确绑定到原始客户端。"
            finding.recommendation = ""

        self._findings.append(finding)
        return finding

    async def test_refresh_token_lifetime(
        self,
        refresh_token: str,
        token_endpoint: str,
        client_id: str = "",
        client_secret: str = "",
        max_lifetime_hours: float = 720.0,
    ) -> RefreshTokenFinding:
        """Test if a refresh token has an excessive lifetime.

        Args:
            refresh_token: Refresh token to test.
            token_endpoint: Token endpoint URL.
            client_id: OAuth client ID.
            client_secret: OAuth client secret.
            max_lifetime_hours: Maximum acceptable lifetime in hours.

        Returns:
            RefreshTokenFinding with test results.
        """
        self._finding_counter += 1
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()[:16]

        finding = RefreshTokenFinding(
            finding_id=f"REFRESH-LIFETIME-{self._finding_counter:04d}",
            test_type=LifecycleTestType.REFRESH_EXPIRATION,
            refresh_token_hash=token_hash,
        )

        lifetime_hours = await self._measure_token_lifetime(
            refresh_token=refresh_token,
            token_endpoint=token_endpoint,
            client_id=client_id,
            client_secret=client_secret,
        )

        finding.lifetime_hours = lifetime_hours
        finding.excessive_lifetime = lifetime_hours > max_lifetime_hours

        if finding.excessive_lifetime:
            finding.severity = "medium"
            finding.description = (
                f"Refresh Token生命周期为{lifetime_hours:.1f}小时，"
                f"超过建议的{max_lifetime_hours}小时上限。"
            )
            finding.recommendation = (
                "限制Refresh Token的生命周期，建议不超过30天。"
                "实施定期令牌轮换策略。"
            )
        elif lifetime_hours == 0:
            finding.severity = "high"
            finding.description = "Refresh Token永不过期，存在严重安全风险。"
            finding.recommendation = (
                "所有令牌都必须设置合理的过期时间，禁止使用永不过期的令牌。"
            )
        else:
            finding.severity = "low"
            finding.description = f"Refresh Token生命周期合理（{lifetime_hours:.1f}小时）。"
            finding.recommendation = ""

        self._findings.append(finding)
        return finding

    async def _attempt_refresh(
        self,
        refresh_token: str,
        token_endpoint: str,
        client_id: str = "",
        client_secret: str = "",
    ) -> bool:
        """Attempt to refresh a token.

        Args:
            refresh_token: Refresh token to use.
            token_endpoint: Token endpoint URL.
            client_id: Client ID.
            client_secret: Client secret.

        Returns:
            True if refresh was successful.
        """
        try:
            import aiohttp

            payload = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            }

            if client_id:
                payload["client_id"] = client_id
            if client_secret:
                payload["client_secret"] = client_secret

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    token_endpoint,
                    data=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    return resp.status == 200
        except Exception as e:
            logger.error(f"Refresh attempt failed: {e}")
            return False

    async def _measure_token_lifetime(
        self,
        refresh_token: str,
        token_endpoint: str,
        client_id: str = "",
        client_secret: str = "",
    ) -> float:
        """Measure the lifetime of a refresh token.

        Args:
            refresh_token: Refresh token to measure.
            token_endpoint: Token endpoint URL.
            client_id: Client ID.
            client_secret: Client secret.

        Returns:
            Lifetime in hours, 0 if infinite.
        """
        try:
            import aiohttp

            payload = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            }

            if client_id:
                payload["client_id"] = client_id
            if client_secret:
                payload["client_secret"] = client_secret

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    token_endpoint,
                    data=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        body = await resp.json()
                        expires_in = body.get("expires_in", 0)
                        if expires_in:
                            return expires_in / 3600.0
                        return 0.0
                    return 0.0
        except Exception as e:
            logger.error(f"Failed to measure token lifetime: {e}")
            return 0.0

    def get_findings(self) -> List[RefreshTokenFinding]:
        """Get all refresh token findings.

        Returns:
            List of RefreshTokenFinding.
        """
        return self._findings.copy()


# =============================================================================
# Token Chain Integrity Tester
# =============================================================================

class TokenChainIntegrityTester:
    """Tests the integrity of complete token chains.

    Verifies that each step in the token lifecycle
    (authorization code -> access token -> refresh token -> new access token)
    is properly secured and cannot be bypassed or replayed.

    Attributes:
        _results: Chain integrity results
        _result_counter: Result counter
    """

    def __init__(self) -> None:
        """Initialize the TokenChainIntegrityTester."""
        self._results: List[TokenChainIntegrityResult] = []
        self._result_counter = 0

    async def test_chain_integrity(
        self,
        auth_code: str,
        token_endpoint: str,
        client_id: str = "",
        client_secret: str = "",
        redirect_uri: str = "",
    ) -> TokenChainIntegrityResult:
        """Test the integrity of a complete token chain.

        Args:
            auth_code: Authorization code.
            token_endpoint: Token endpoint URL.
            client_id: OAuth client ID.
            client_secret: OAuth client secret.
            redirect_uri: Redirect URI used in authorization.

        Returns:
            TokenChainIntegrityResult with findings.
        """
        self._result_counter += 1
        result = TokenChainIntegrityResult(
            chain_id=f"CHAIN-INTEGRITY-{self._result_counter:04d}",
        )

        chain_steps = [
            ("authorization_code", auth_code),
        ]

        access_token = await self._exchange_code_for_token(
            auth_code=auth_code,
            token_endpoint=token_endpoint,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
        )

        if access_token:
            chain_steps.append(("access_token", access_token))

        refresh_token = await self._extract_refresh_token(
            auth_code=auth_code,
            token_endpoint=token_endpoint,
            client_id=client_id,
            client_secret=client_secret,
        )

        if refresh_token:
            chain_steps.append(("refresh_token", refresh_token))

        result.total_steps = len(chain_steps)

        vulnerabilities: List[Dict[str, Any]] = []

        code_replay = await self._test_code_replay(
            auth_code=auth_code,
            token_endpoint=token_endpoint,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
        )

        if code_replay:
            vulnerabilities.append({
                "step": "authorization_code",
                "type": "code_replay",
                "severity": "critical",
                "description": "授权码可被重复使用，应一次性失效",
            })
            result.replayable_steps += 1

        if refresh_token:
            refresh_reuse = await self._test_refresh_reuse(
                refresh_token=refresh_token,
                token_endpoint=token_endpoint,
                client_id=client_id,
                client_secret=client_secret,
            )

            if refresh_reuse:
                vulnerabilities.append({
                    "step": "refresh_token",
                    "type": "refresh_reuse",
                    "severity": "high",
                    "description": "Refresh Token可重复使用，应实施轮换机制",
                })
                result.replayable_steps += 1

        result.vulnerabilities = vulnerabilities

        if not vulnerabilities:
            result.integrity_level = TokenChainIntegrity.SECURE
        elif len(vulnerabilities) <= 1:
            result.integrity_level = TokenChainIntegrity.WEAK
        else:
            result.integrity_level = TokenChainIntegrity.BROKEN

        result.attack_graph = {
            "nodes": [{"id": i, "type": step[0]} for i, step in enumerate(chain_steps)],
            "edges": [{"from": i, "to": i + 1} for i in range(len(chain_steps) - 1)],
            "vulnerabilities": vulnerabilities,
        }

        self._results.append(result)
        return result

    async def _exchange_code_for_token(
        self,
        auth_code: str,
        token_endpoint: str,
        client_id: str = "",
        client_secret: str = "",
        redirect_uri: str = "",
    ) -> Optional[str]:
        """Exchange authorization code for access token.

        Args:
            auth_code: Authorization code.
            token_endpoint: Token endpoint URL.
            client_id: Client ID.
            client_secret: Client secret.
            redirect_uri: Redirect URI.

        Returns:
            Access token or None.
        """
        try:
            import aiohttp

            payload = {
                "grant_type": "authorization_code",
                "code": auth_code,
            }

            if client_id:
                payload["client_id"] = client_id
            if client_secret:
                payload["client_secret"] = client_secret
            if redirect_uri:
                payload["redirect_uri"] = redirect_uri

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    token_endpoint,
                    data=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        body = await resp.json()
                        return body.get("access_token", "")
                    return None
        except Exception as e:
            logger.error(f"Code exchange failed: {e}")
            return None

    async def _extract_refresh_token(
        self,
        auth_code: str,
        token_endpoint: str,
        client_id: str = "",
        client_secret: str = "",
    ) -> Optional[str]:
        """Extract refresh token from token exchange.

        Args:
            auth_code: Authorization code.
            token_endpoint: Token endpoint URL.
            client_id: Client ID.
            client_secret: Client secret.

        Returns:
            Refresh token or None.
        """
        try:
            import aiohttp

            payload = {
                "grant_type": "authorization_code",
                "code": auth_code,
            }

            if client_id:
                payload["client_id"] = client_id
            if client_secret:
                payload["client_secret"] = client_secret

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    token_endpoint,
                    data=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        body = await resp.json()
                        return body.get("refresh_token", "")
                    return None
        except Exception as e:
            logger.error(f"Failed to extract refresh token: {e}")
            return None

    async def _test_code_replay(
        self,
        auth_code: str,
        token_endpoint: str,
        client_id: str = "",
        client_secret: str = "",
        redirect_uri: str = "",
    ) -> bool:
        """Test if authorization code can be replayed.

        Args:
            auth_code: Authorization code.
            token_endpoint: Token endpoint URL.
            client_id: Client ID.
            client_secret: Client secret.
            redirect_uri: Redirect URI.

        Returns:
            True if code can be replayed.
        """
        try:
            import aiohttp

            payload = {
                "grant_type": "authorization_code",
                "code": auth_code,
            }

            if client_id:
                payload["client_id"] = client_id
            if client_secret:
                payload["client_secret"] = client_secret
            if redirect_uri:
                payload["redirect_uri"] = redirect_uri

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    token_endpoint,
                    data=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    return resp.status == 200
        except Exception:
            return False

    async def _test_refresh_reuse(
        self,
        refresh_token: str,
        token_endpoint: str,
        client_id: str = "",
        client_secret: str = "",
    ) -> bool:
        """Test if refresh token can be reused.

        Args:
            refresh_token: Refresh token.
            token_endpoint: Token endpoint URL.
            client_id: Client ID.
            client_secret: Client secret.

        Returns:
            True if token can be reused.
        """
        try:
            import aiohttp

            payload = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            }

            if client_id:
                payload["client_id"] = client_id
            if client_secret:
                payload["client_secret"] = client_secret

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    token_endpoint,
                    data=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    return resp.status == 200
        except Exception:
            return False

    def get_results(self) -> List[TokenChainIntegrityResult]:
        """Get all chain integrity results.

        Returns:
            List of TokenChainIntegrityResult.
        """
        return self._results.copy()


# =============================================================================
# Main Token Lifecycle Manager
# =============================================================================

class TokenLifecycleManager:
    """Main token lifecycle coordination engine.

    Integrates logout testing, refresh token abuse testing,
    and chain integrity verification.

    Attributes:
        _logout_tester: Token logout tester
        _refresh_tester: Refresh token abuse tester
        _chain_tester: Token chain integrity tester
    """

    def __init__(self) -> None:
        """Initialize the TokenLifecycleManager."""
        self._logout_tester = TokenLogoutTester()
        self._refresh_tester = RefreshTokenAbuseTester()
        self._chain_tester = TokenChainIntegrityTester()

    @property
    def logout(self) -> TokenLogoutTester:
        """Get token logout tester.

        Returns:
            TokenLogoutTester instance.
        """
        return self._logout_tester

    @property
    def refresh(self) -> RefreshTokenAbuseTester:
        """Get refresh token abuse tester.

        Returns:
            RefreshTokenAbuseTester instance.
        """
        return self._refresh_tester

    @property
    def chain(self) -> TokenChainIntegrityTester:
        """Get token chain integrity tester.

        Returns:
            TokenChainIntegrityTester instance.
        """
        return self._chain_tester

    async def run_full_lifecycle_suite(
        self,
        token: str,
        refresh_token: str = "",
        auth_code: str = "",
        protected_urls: Optional[List[str]] = None,
        token_endpoint: str = "",
        client_id: str = "",
        client_secret: str = "",
    ) -> Dict[str, Any]:
        """Run the full token lifecycle test suite.

        Args:
            token: Token to test.
            refresh_token: Refresh token (optional).
            auth_code: Authorization code (optional).
            protected_urls: URLs to test access against.
            token_endpoint: Token endpoint URL.
            client_id: OAuth client ID.
            client_secret: OAuth client secret.

        Returns:
            Dictionary with all test results.
        """
        results: Dict[str, Any] = {
            "logout_invalidation": {},
            "refresh_abuse": {},
            "chain_integrity": {},
        }

        if protected_urls:
            logout_result = await self._logout_tester.test_logout_invalidation(
                token=token,
                protected_urls=protected_urls,
            )
            results["logout_invalidation"] = logout_result.to_dict()

        if refresh_token and token_endpoint:
            reuse_result = await self._refresh_tester.test_refresh_token_reuse(
                refresh_token=refresh_token,
                token_endpoint=token_endpoint,
                client_id=client_id,
                client_secret=client_secret,
            )
            results["refresh_abuse"]["reuse"] = reuse_result.to_dict()

            binding_result = await self._refresh_tester.test_refresh_token_client_binding(
                refresh_token=refresh_token,
                token_endpoint=token_endpoint,
                original_client_id=client_id,
            )
            results["refresh_abuse"]["binding"] = binding_result.to_dict()

        if auth_code and token_endpoint:
            chain_result = await self._chain_tester.test_chain_integrity(
                auth_code=auth_code,
                token_endpoint=token_endpoint,
                client_id=client_id,
                client_secret=client_secret,
            )
            results["chain_integrity"] = chain_result.to_dict()

        return results
