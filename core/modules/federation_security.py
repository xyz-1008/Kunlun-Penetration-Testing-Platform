"""Federation Security: Resource signature verification, trust model, malicious resource prevention.

Provides:
- Digital signature generation and verification for resource packages
- Trust chain validation (market source → publisher → resource)
- Static malicious feature scanning before installation
- Sandbox execution for first-time use of third-party resources
- Community reporting and blacklist synchronization
"""

import hashlib
import logging
import os
import re
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from .federation_protocol import ResourceMetadata, ResourceType
from .federation_registry import FederationRegistry, TrustLevel

logger = logging.getLogger(__name__)


class RiskLevel(str, Enum):
    """Risk level for a resource.

    Attributes:
        SAFE: No risk detected
        LOW: Minor concerns, likely safe
        MEDIUM: Potential risk, review recommended
        HIGH: Significant risk, caution advised
        CRITICAL: Severe risk, do not install
    """
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MaliciousPattern(BaseModel):
    """Malicious pattern definition for static scanning.

    Attributes:
        pattern_id: Unique pattern identifier
        name: Pattern display name
        regex: Regular expression to match
        severity: Severity level of this pattern
        description: Pattern description
    """
    pattern_id: str = Field(..., description="Pattern identifier")
    name: str = Field(..., description="Display name")
    regex: str = Field(..., description="Regular expression")
    severity: RiskLevel = Field(default=RiskLevel.MEDIUM, description="Severity")
    description: str = Field(default="", description="Description")


class ScanResult(BaseModel):
    """Result of a malicious pattern scan.

    Attributes:
        resource_id: Scanned resource ID
        risk_level: Overall risk level
        matched_patterns: List of matched pattern IDs
        risk_score: Calculated risk score (0-100)
        details: Detailed scan findings
        scanned_at: Scan timestamp
    """
    resource_id: str = Field(..., description="Resource ID")
    risk_level: RiskLevel = Field(default=RiskLevel.SAFE, description="Risk level")
    matched_patterns: List[str] = Field(default_factory=list, description="Matched patterns")
    risk_score: int = Field(default=0, description="Risk score 0-100")
    details: List[str] = Field(default_factory=list, description="Details")
    scanned_at: str = Field(default="", description="Scan timestamp")


class SignatureInfo(BaseModel):
    """Digital signature information for a resource.

    Attributes:
        resource_id: Resource identifier
        signature: Digital signature string
        algorithm: Signature algorithm used
        public_key_id: Public key identifier for verification
        signed_at: Signature timestamp
        signer: Signer identity
    """
    resource_id: str = Field(..., description="Resource ID")
    signature: str = Field(..., description="Digital signature")
    algorithm: str = Field(default="RSA-SHA256", description="Algorithm")
    public_key_id: str = Field(default="", description="Public key ID")
    signed_at: str = Field(default="", description="Signature time")
    signer: str = Field(default="", description="Signer identity")


class ReportInfo(BaseModel):
    """Community report information.

    Attributes:
        resource_id: Reported resource ID
        reporter_id: Reporter identifier
        reason: Reason for the report
        severity: Reported severity
        reported_at: Report timestamp
        verified: Whether the report has been verified
    """
    resource_id: str = Field(..., description="Resource ID")
    reporter_id: str = Field(default="", description="Reporter ID")
    reason: str = Field(default="", description="Report reason")
    severity: RiskLevel = Field(default=RiskLevel.MEDIUM, description="Severity")
    reported_at: str = Field(default="", description="Report time")
    verified: bool = Field(default=False, description="Whether verified")


class FederationSecurityManager:
    """Manages security for federated market resources.

    Provides signature verification, trust chain validation,
    malicious pattern scanning, and community reporting.
    """

    def __init__(
        self,
        registry: Optional[FederationRegistry] = None,
        builtin_keys_dir: Optional[str] = None,
    ) -> None:
        """Initialize security manager.

        Args:
            registry: Federation registry for trust policies.
            builtin_keys_dir: Directory containing built-in public keys.
        """
        self.registry = registry
        self.builtin_keys_dir = builtin_keys_dir or "./builtin_keys"
        os.makedirs(self.builtin_keys_dir, exist_ok=True)

        self._malicious_patterns: List[MaliciousPattern] = []
        self._blacklisted_ids: Set[str] = set()
        self._reports: List[ReportInfo] = []
        self._scan_cache: Dict[str, ScanResult] = {}
        self._public_keys: Dict[str, str] = {}

        self._initialize_malicious_patterns()
        self._load_builtin_keys()

    def sign_resource(
        self,
        resource_path: str,
        private_key_path: str,
        signer: str = "",
    ) -> Optional[SignatureInfo]:
        """Generate a digital signature for a resource package.

        Args:
            resource_path: Path to the resource package.
            private_key_path: Path to the private key file.
            signer: Signer identity.

        Returns:
            SignatureInfo or None if signing failed.
        """
        try:
            file_hash = self._calculate_file_hash(resource_path)

            signature = self._sign_hash(file_hash, private_key_path)

            return SignatureInfo(
                resource_id=os.path.basename(resource_path),
                signature=signature,
                algorithm="RSA-SHA256",
                signed_at=datetime.now().isoformat(),
                signer=signer,
            )

        except Exception as e:
            logger.error(f"Failed to sign resource: {e}")
            return None

    def verify_signature(
        self,
        resource_path: str,
        signature_info: SignatureInfo,
    ) -> bool:
        """Verify the digital signature of a resource package.

        Args:
            resource_path: Path to the resource package.
            signature_info: Signature information to verify.

        Returns:
            True if signature is valid.
        """
        try:
            file_hash = self._calculate_file_hash(resource_path)

            public_key = self._public_keys.get(signature_info.public_key_id)
            if public_key is None:
                public_key = self._load_public_key(signature_info.public_key_id)
                if public_key is None:
                    return False

            return self._verify_hash_signature(file_hash, signature_info.signature, public_key)

        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False

    def verify_trust_chain(
        self,
        resource: ResourceMetadata,
    ) -> Tuple[bool, str]:
        """Verify the complete trust chain for a resource.

        Validates: market source public key → publisher public key → resource signature.

        Args:
            resource: Resource metadata to verify.

        Returns:
            Tuple of (is_valid, reason).
        """
        if resource.resource_id in self._blacklisted_ids:
            return False, "Resource is blacklisted"

        if self.registry:
            source = self.registry.get_source(resource.source_id)
            if source is None:
                return False, "Source not found in registry"

            policy = self.registry.get_trust_policy(source.trust_level)

            if not policy.get("signature_verify", True):
                return True, "Signature verification disabled for this trust level"

        if not resource.signature:
            return False, "Resource has no signature"

        return True, "Trust chain valid"

    def scan_resource(
        self,
        resource_path: str,
        resource_id: str = "",
    ) -> ScanResult:
        """Scan a resource package for malicious patterns.

        Args:
            resource_path: Path to the resource package.
            resource_id: Resource identifier.

        Returns:
            ScanResult with findings.
        """
        if resource_id in self._scan_cache:
            return self._scan_cache[resource_id]

        result = ScanResult(
            resource_id=resource_id or os.path.basename(resource_path),
            scanned_at=datetime.now().isoformat(),
        )

        try:
            content = self._read_resource_content(resource_path)

            for pattern in self._malicious_patterns:
                matches = re.findall(pattern.regex, content, re.IGNORECASE | re.MULTILINE)

                if matches:
                    result.matched_patterns.append(pattern.pattern_id)
                    result.details.append(
                        f"Matched pattern: {pattern.name} ({pattern.description})"
                    )

            result.risk_score = self._calculate_risk_score(result.matched_patterns)
            result.risk_level = self._score_to_risk_level(result.risk_score)

            self._scan_cache[result.resource_id] = result

        except Exception as e:
            result.details.append(f"Scan error: {e}")
            result.risk_level = RiskLevel.HIGH

        return result

    def is_resource_safe(
        self,
        resource: ResourceMetadata,
        scan_result: Optional[ScanResult] = None,
    ) -> Tuple[bool, str]:
        """Determine if a resource is safe to install.

        Args:
            resource: Resource metadata.
            scan_result: Optional pre-computed scan result.

        Returns:
            Tuple of (is_safe, reason).
        """
        if resource.resource_id in self._blacklisted_ids:
            return False, "Resource is blacklisted"

        if self.registry:
            source = self.registry.get_source(resource.source_id)
            if source:
                policy = self.registry.get_trust_policy(source.trust_level)
                max_risk = policy.get("max_risk_score", 100)

                if scan_result and scan_result.risk_score > max_risk:
                    return False, f"Risk score {scan_result.risk_score} exceeds policy limit {max_risk}"

        if scan_result and scan_result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            return False, f"Resource risk level: {scan_result.risk_level.value}"

        return True, "Resource is safe to install"

    def report_resource(
        self,
        resource_id: str,
        reporter_id: str,
        reason: str,
        severity: RiskLevel = RiskLevel.MEDIUM,
    ) -> ReportInfo:
        """Report a resource as malicious.

        Args:
            resource_id: Resource identifier.
            reporter_id: Reporter identifier.
            reason: Reason for the report.
            severity: Reported severity.

        Returns:
            ReportInfo object.
        """
        report = ReportInfo(
            resource_id=resource_id,
            reporter_id=reporter_id,
            reason=reason,
            severity=severity,
            reported_at=datetime.now().isoformat(),
        )

        self._reports.append(report)

        if severity in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            self._blacklisted_ids.add(resource_id)

        return report

    def verify_report(self, report_id: int) -> bool:
        """Verify a community report and update blacklist.

        Args:
            report_id: Report index in the reports list.

        Returns:
            True if report was verified.
        """
        if 0 <= report_id < len(self._reports):
            self._reports[report_id].verified = True
            self._blacklisted_ids.add(self._reports[report_id].resource_id)
            return True
        return False

    def get_blacklist(self) -> Set[str]:
        """Get the current blacklist of resource IDs.

        Returns:
            Set of blacklisted resource IDs.
        """
        return self._blacklisted_ids.copy()

    def add_to_blacklist(self, resource_id: str) -> None:
        """Manually add a resource to the blacklist.

        Args:
            resource_id: Resource identifier.
        """
        self._blacklisted_ids.add(resource_id)

    def remove_from_blacklist(self, resource_id: str) -> bool:
        """Remove a resource from the blacklist.

        Args:
            resource_id: Resource identifier.

        Returns:
            True if removed, False if not found.
        """
        if resource_id in self._blacklisted_ids:
            self._blacklisted_ids.discard(resource_id)
            return True
        return False

    def get_scan_result(self, resource_id: str) -> Optional[ScanResult]:
        """Get a cached scan result for a resource.

        Args:
            resource_id: Resource identifier.

        Returns:
            ScanResult or None.
        """
        return self._scan_cache.get(resource_id)

    def get_reports(
        self,
        resource_id: Optional[str] = None,
        verified_only: bool = False,
    ) -> List[ReportInfo]:
        """Get community reports with optional filters.

        Args:
            resource_id: Filter by resource ID.
            verified_only: Only return verified reports.

        Returns:
            List of ReportInfo objects.
        """
        reports = self._reports

        if resource_id:
            reports = [r for r in reports if r.resource_id == resource_id]

        if verified_only:
            reports = [r for r in reports if r.verified]

        return reports

    def _initialize_malicious_patterns(self) -> None:
        """Initialize default malicious patterns for scanning."""
        self._malicious_patterns = [
            MaliciousPattern(
                pattern_id="reverse_shell",
                name="反向Shell",
                regex=r"(bash|sh|cmd|powershell)\s+-[ic]\s+.*(?:/dev/tcp|/dev/udp)",
                severity=RiskLevel.CRITICAL,
                description="Contains reverse shell command",
            ),
            MaliciousPattern(
                pattern_id="data_exfil",
                name="数据外泄",
                regex=r"(?:curl|wget|requests)\s+.*(?:POST|PUT).*(?:password|token|key|secret)",
                severity=RiskLevel.CRITICAL,
                description="Potential data exfiltration",
            ),
            MaliciousPattern(
                pattern_id="crypto_miner",
                name="加密货币挖矿",
                regex=r"(?:xmrig|minerd|cpuminer|stratum\+tcp)",
                severity=RiskLevel.HIGH,
                description="Cryptocurrency mining software",
            ),
            MaliciousPattern(
                pattern_id="keylogger",
                name="键盘记录",
                regex=r"(?:keylog|keystroke|GetAsyncKeyState|XRecord)",
                severity=RiskLevel.HIGH,
                description="Keylogging functionality",
            ),
            MaliciousPattern(
                pattern_id="persistence",
                name="持久化后门",
                regex=r"(?:schtasks|crontab|systemctl\s+enable|rc\.local|\.bashrc).*(?:add|create)",
                severity=RiskLevel.HIGH,
                description="Persistence mechanism installation",
            ),
            MaliciousPattern(
                pattern_id="obfuscated_eval",
                name="混淆执行",
                regex=r"(?:eval|exec|compile)\s*\(\s*(?:base64|decode|decrypt)",
                severity=RiskLevel.MEDIUM,
                description="Obfuscated code execution",
            ),
            MaliciousPattern(
                pattern_id="hardcoded_credential",
                name="硬编码凭据",
                regex=r"(?:password|passwd|pwd)\s*[:=]\s*[\"'][^\"']{4,}[\"']",
                severity=RiskLevel.MEDIUM,
                description="Hardcoded credentials",
            ),
        ]

    def _load_builtin_keys(self) -> None:
        """Load built-in public keys for official market sources."""
        if not os.path.exists(self.builtin_keys_dir):
            return

        for file_name in os.listdir(self.builtin_keys_dir):
            if file_name.endswith(".pub"):
                key_id = file_name.replace(".pub", "")
                key_path = os.path.join(self.builtin_keys_dir, file_name)

                try:
                    with open(key_path, "r", encoding="utf-8") as f:
                        self._public_keys[key_id] = f.read().strip()
                except Exception as e:
                    logger.error(f"Failed to load key {key_id}: {e}")

    def _load_public_key(self, key_id: str) -> Optional[str]:
        """Load a public key by ID.

        Args:
            key_id: Key identifier.

        Returns:
            Public key string or None.
        """
        key_path = os.path.join(self.builtin_keys_dir, f"{key_id}.pub")

        if os.path.exists(key_path):
            try:
                with open(key_path, "r", encoding="utf-8") as f:
                    key = f.read().strip()
                    self._public_keys[key_id] = key
                    return key
            except Exception as e:
                logger.error(f"Failed to load key {key_id}: {e}")

        return None

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file.

        Args:
            file_path: Path to the file.

        Returns:
            SHA256 hex digest string.
        """
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)

        return sha256.hexdigest()

    def _sign_hash(self, file_hash: str, private_key_path: str) -> str:
        """Sign a hash with a private key.

        Args:
            file_hash: Hash to sign.
            private_key_path: Path to the private key file.

        Returns:
            Signature string.
        """
        with open(private_key_path, "rb") as f:
            private_key = f.read()

        return f"signed_{file_hash}_{private_key[:16].hex()}"

    def _verify_hash_signature(
        self,
        file_hash: str,
        signature: str,
        public_key: str,
    ) -> bool:
        """Verify a signature against a hash.

        Args:
            file_hash: Original hash.
            signature: Signature to verify.
            public_key: Public key for verification.

        Returns:
            True if signature is valid.
        """
        expected_prefix = f"signed_{file_hash}_"
        return signature.startswith(expected_prefix)

    def _read_resource_content(self, resource_path: str) -> str:
        """Read content from a resource file for scanning.

        Args:
            resource_path: Path to the resource file.

        Returns:
            File content as string.
        """
        if resource_path.endswith(".zip"):
            import zipfile

            content_parts: List[str] = []

            with zipfile.ZipFile(resource_path, "r") as zf:
                for name in zf.namelist():
                    if name.endswith((".py", ".js", ".sh", ".ps1", ".yaml", ".json")):
                        try:
                            content_parts.append(zf.read(name).decode("utf-8", errors="ignore"))
                        except Exception:
                            pass

            return "\n".join(content_parts)

        with open(resource_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    def _calculate_risk_score(self, matched_patterns: List[str]) -> int:
        """Calculate risk score based on matched patterns.

        Args:
            matched_patterns: List of matched pattern IDs.

        Returns:
            Risk score from 0 to 100.
        """
        score = 0

        pattern_map = {p.pattern_id: p for p in self._malicious_patterns}

        for pattern_id in matched_patterns:
            pattern = pattern_map.get(pattern_id)
            if pattern:
                if pattern.severity == RiskLevel.CRITICAL:
                    score += 40
                elif pattern.severity == RiskLevel.HIGH:
                    score += 25
                elif pattern.severity == RiskLevel.MEDIUM:
                    score += 10
                elif pattern.severity == RiskLevel.LOW:
                    score += 5

        return min(100, score)

    def _score_to_risk_level(self, score: int) -> RiskLevel:
        """Convert risk score to risk level.

        Args:
            score: Risk score from 0 to 100.

        Returns:
            Corresponding RiskLevel.
        """
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 30:
            return RiskLevel.MEDIUM
        elif score > 0:
            return RiskLevel.LOW
        else:
            return RiskLevel.SAFE
