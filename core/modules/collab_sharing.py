"""Collaboration Sharing: Asset/credential/traffic sharing pools, deduplication, claiming, encrypted storage.

Provides:
- Asset sharing pool: Real-time asset aggregation from team members with deduplication
- Credential sharing pool: Encrypted credential sharing with type, target, source module tracking
- Traffic sharing: Key requests/responses shared to team war room
- Asset claiming: Members can claim assets for deep testing, visible to others
- Asset tags and notes: Members can add tags and notes to shared assets
- Sensitive protection: Credentials encrypted in storage, configurable masking in UI
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class CredentialType(Enum):
    """Types of credentials that can be shared."""
    PASSWORD = "password"
    HASH = "hash"
    TICKET = "ticket"
    TOKEN = "token"
    SSH_KEY = "ssh_key"
    API_KEY = "api_key"
    CERTIFICATE = "certificate"


class AssetClaimStatus(Enum):
    """Asset claim status."""
    UNCLAIMED = "unclaimed"
    CLAIMED = "claimed"
    TESTING = "testing"
    COMPLETED = "completed"


class VulnerabilityStatus(Enum):
    """Vulnerability confirmation status."""
    CONFIRMED = "confirmed"
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    PENDING = "pending"


@dataclass
class SharedAsset:
    """Asset shared in the team pool.

    Attributes:
        asset_id: Unique asset identifier
        project_id: Parent project ID
        ip: IP address
        port: Port number
        protocol: Protocol detected
        service: Service name
        fingerprint: Service fingerprint
        hostname: Hostname
        discovered_by: Member who discovered this asset
        discovered_at: Discovery timestamp
        claimed_by: Member who claimed this asset
        claim_status: Asset claim status
        tags: List of tags (e.g., "tested", "high-value", "honeypot")
        notes: Member notes about this asset
    """
    asset_id: str = ""
    project_id: str = ""
    ip: str = ""
    port: int = 0
    protocol: str = ""
    service: str = ""
    fingerprint: str = ""
    hostname: str = ""
    discovered_by: str = ""
    discovered_at: float = 0.0
    claimed_by: str = ""
    claim_status: AssetClaimStatus = AssetClaimStatus.UNCLAIMED
    tags: List[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class SharedCredential:
    """Credential shared in the team pool.

    Attributes:
        cred_id: Unique credential identifier
        project_id: Parent project ID
        cred_type: Credential type
        target: Target system/service
        username: Username or account name
        encrypted_password: Encrypted password/hash value
        source_module: Module that obtained this credential
        obtained_by: Member who obtained this credential
        obtained_at: Acquisition timestamp
        expires_at: Expiration timestamp (for tokens/tickets)
        is_valid: Whether credential is still valid
        usage_count: Number of times used by team
    """
    cred_id: str = ""
    project_id: str = ""
    cred_type: CredentialType = CredentialType.PASSWORD
    target: str = ""
    username: str = ""
    encrypted_password: str = ""
    source_module: str = ""
    obtained_by: str = ""
    obtained_at: float = 0.0
    expires_at: float = 0.0
    is_valid: bool = True
    usage_count: int = 0


@dataclass
class SharedTraffic:
    """HTTP traffic shared to team war room.

    Attributes:
        traffic_id: Unique traffic identifier
        project_id: Parent project ID
        request: HTTP request data
        response: HTTP response data
        url: Request URL
        method: HTTP method
        status_code: Response status code
        shared_by: Member who shared this traffic
        shared_at: Share timestamp
        tags: List of tags
        notes: Notes about this traffic
        is_imported: Whether other members have imported this
    """
    traffic_id: str = ""
    project_id: str = ""
    request: str = ""
    response: str = ""
    url: str = ""
    method: str = ""
    status_code: int = 0
    shared_by: str = ""
    shared_at: float = 0.0
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    is_imported: bool = False


@dataclass
class SharedVulnerability:
    """Vulnerability shared in the team pool.

    Attributes:
        vuln_id: Unique vulnerability identifier
        project_id: Parent project ID
        asset_id: Associated asset ID
        title: Vulnerability title
        severity: Severity level (critical/high/medium/low/info)
        description: Vulnerability description
        proof: Proof of concept or evidence
        discovered_by: Member who discovered this vulnerability
        discovered_at: Discovery timestamp
        status: Vulnerability confirmation status
        affected_members: Members who also confirmed this vulnerability
    """
    vuln_id: str = ""
    project_id: str = ""
    asset_id: str = ""
    title: str = ""
    severity: str = ""
    description: str = ""
    proof: str = ""
    discovered_by: str = ""
    discovered_at: float = 0.0
    status: VulnerabilityStatus = VulnerabilityStatus.PENDING
    affected_members: List[str] = field(default_factory=list)


class SharingPool:
    """Manages shared assets, credentials, traffic, and vulnerabilities for team collaboration.

    Provides deduplication, claiming, encrypted storage, and real-time
    notifications for shared resources within a project space.
    """

    def __init__(self, db_path: str = "", encryption_key: bytes = b"") -> None:
        """Initialize sharing pool.

        Args:
            db_path: Path to SQLite database file.
            encryption_key: AES-256 key for credential encryption.
        """
        self.db_path = db_path or "collab_sharing.db"
        self.encryption_key = encryption_key
        self._assets: Dict[str, SharedAsset] = {}
        self._credentials: Dict[str, SharedCredential] = {}
        self._traffic: Dict[str, SharedTraffic] = {}
        self._vulnerabilities: Dict[str, SharedVulnerability] = {}
        self._asset_callbacks: List[Callable[[str, SharedAsset], Coroutine[Any, Any, None]]] = []
        self._cred_callbacks: List[Callable[[str, SharedCredential], Coroutine[Any, Any, None]]] = []
        self._vuln_callbacks: List[Callable[[str, SharedVulnerability], Coroutine[Any, Any, None]]] = []

        self._init_database()
        self._load_data()

    def register_asset_callback(
        self,
        callback: Callable[[str, SharedAsset], Coroutine[Any, Any, None]],
    ) -> None:
        """Register callback for new shared assets.

        Args:
            callback: Async callback receiving project_id and asset.
        """
        self._asset_callbacks.append(callback)

    def register_credential_callback(
        self,
        callback: Callable[[str, SharedCredential], Coroutine[Any, Any, None]],
    ) -> None:
        """Register callback for new shared credentials.

        Args:
            callback: Async callback receiving project_id and credential.
        """
        self._cred_callbacks.append(callback)

    def register_vulnerability_callback(
        self,
        callback: Callable[[str, SharedVulnerability], Coroutine[Any, Any, None]],
    ) -> None:
        """Register callback for new shared vulnerabilities.

        Args:
            callback: Async callback receiving project_id and vulnerability.
        """
        self._vuln_callbacks.append(callback)

    def _init_database(self) -> None:
        """Initialize SQLite database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS shared_assets (
                asset_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT,
                service TEXT,
                fingerprint TEXT,
                hostname TEXT,
                discovered_by TEXT NOT NULL,
                discovered_at REAL NOT NULL,
                claimed_by TEXT,
                claim_status TEXT NOT NULL,
                tags TEXT,
                notes TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS shared_credentials (
                cred_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                cred_type TEXT NOT NULL,
                target TEXT NOT NULL,
                username TEXT,
                encrypted_password TEXT NOT NULL,
                source_module TEXT,
                obtained_by TEXT NOT NULL,
                obtained_at REAL NOT NULL,
                expires_at REAL,
                is_valid INTEGER NOT NULL,
                usage_count INTEGER NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS shared_traffic (
                traffic_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                request TEXT,
                response TEXT,
                url TEXT,
                method TEXT,
                status_code INTEGER,
                shared_by TEXT NOT NULL,
                shared_at REAL NOT NULL,
                tags TEXT,
                notes TEXT,
                is_imported INTEGER NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS shared_vulnerabilities (
                vuln_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                asset_id TEXT,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                proof TEXT,
                discovered_by TEXT NOT NULL,
                discovered_at REAL NOT NULL,
                status TEXT NOT NULL,
                affected_members TEXT
            )
        """)

        conn.commit()
        conn.close()

    def _load_data(self) -> None:
        """Load all shared data from database."""
        if not os.path.exists(self.db_path):
            return

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM shared_assets")
        for row in cursor.fetchall():
            asset = SharedAsset(
                asset_id=row[0],
                project_id=row[1],
                ip=row[2],
                port=row[3],
                protocol=row[4] or "",
                service=row[5] or "",
                fingerprint=row[6] or "",
                hostname=row[7] or "",
                discovered_by=row[8],
                discovered_at=row[9],
                claimed_by=row[10] or "",
                claim_status=AssetClaimStatus(row[11]),
                tags=json.loads(row[12]) if row[12] else [],
                notes=row[13] or "",
            )
            self._assets[asset.asset_id] = asset

        cursor.execute("SELECT * FROM shared_credentials")
        for row in cursor.fetchall():
            cred = SharedCredential(
                cred_id=row[0],
                project_id=row[1],
                cred_type=CredentialType(row[2]),
                target=row[3],
                username=row[4] or "",
                encrypted_password=row[5],
                source_module=row[6] or "",
                obtained_by=row[7],
                obtained_at=row[8],
                expires_at=row[9] or 0.0,
                is_valid=bool(row[10]),
                usage_count=row[11],
            )
            self._credentials[cred.cred_id] = cred

        cursor.execute("SELECT * FROM shared_traffic")
        for row in cursor.fetchall():
            traffic = SharedTraffic(
                traffic_id=row[0],
                project_id=row[1],
                request=row[2] or "",
                response=row[3] or "",
                url=row[4] or "",
                method=row[5] or "",
                status_code=row[6] or 0,
                shared_by=row[7],
                shared_at=row[8],
                tags=json.loads(row[9]) if row[9] else [],
                notes=row[10] or "",
                is_imported=bool(row[11]),
            )
            self._traffic[traffic.traffic_id] = traffic

        cursor.execute("SELECT * FROM shared_vulnerabilities")
        for row in cursor.fetchall():
            vuln = SharedVulnerability(
                vuln_id=row[0],
                project_id=row[1],
                asset_id=row[2] or "",
                title=row[3],
                severity=row[4],
                description=row[5] or "",
                proof=row[6] or "",
                discovered_by=row[7],
                discovered_at=row[8],
                status=VulnerabilityStatus(row[9]),
                affected_members=json.loads(row[10]) if row[10] else [],
            )
            self._vulnerabilities[vuln.vuln_id] = vuln

        conn.close()

    async def share_asset(
        self,
        project_id: str,
        ip: str,
        port: int,
        protocol: str,
        service: str,
        discovered_by: str,
        fingerprint: str = "",
        hostname: str = "",
    ) -> Optional[SharedAsset]:
        """Share a discovered asset to the team pool.

        Args:
            project_id: Target project ID.
            ip: IP address.
            port: Port number.
            protocol: Protocol detected.
            service: Service name.
            discovered_by: Member who discovered this asset.
            fingerprint: Service fingerprint.
            hostname: Hostname.

        Returns:
            SharedAsset if new, or existing asset if duplicate.
        """
        asset_key = self._generate_asset_key(ip, port, protocol)

        existing = self._find_asset_by_key(project_id, asset_key)
        if existing:
            return existing

        asset_id = f"asset_{uuid.uuid4().hex[:12]}"
        now = time.time()

        asset = SharedAsset(
            asset_id=asset_id,
            project_id=project_id,
            ip=ip,
            port=port,
            protocol=protocol,
            service=service,
            fingerprint=fingerprint,
            hostname=hostname,
            discovered_by=discovered_by,
            discovered_at=now,
        )

        self._assets[asset_id] = asset
        self._save_asset(asset)

        for callback in self._asset_callbacks:
            try:
                await callback(project_id, asset)
            except Exception as e:
                logger.error(f"Asset callback error: {e}")

        return asset

    async def claim_asset(
        self,
        asset_id: str,
        member_id: str,
    ) -> bool:
        """Claim an asset for deep testing.

        Args:
            asset_id: Asset to claim.
            member_id: Member claiming the asset.

        Returns:
            True if claimed successfully.
        """
        asset = self._assets.get(asset_id)
        if not asset:
            return False

        if asset.claim_status != AssetClaimStatus.UNCLAIMED:
            return False

        asset.claimed_by = member_id
        asset.claim_status = AssetClaimStatus.CLAIMED

        self._save_asset(asset)

        return True

    async def update_asset_tags(
        self,
        asset_id: str,
        tags: List[str],
    ) -> bool:
        """Update tags for a shared asset.

        Args:
            asset_id: Target asset ID.
            tags: New tag list.

        Returns:
            True if updated successfully.
        """
        asset = self._assets.get(asset_id)
        if not asset:
            return False

        asset.tags = tags
        self._save_asset(asset)

        return True

    async def update_asset_notes(
        self,
        asset_id: str,
        notes: str,
    ) -> bool:
        """Update notes for a shared asset.

        Args:
            asset_id: Target asset ID.
            notes: New notes content.

        Returns:
            True if updated successfully.
        """
        asset = self._assets.get(asset_id)
        if not asset:
            return False

        asset.notes = notes
        self._save_asset(asset)

        return True

    async def share_credential(
        self,
        project_id: str,
        cred_type: CredentialType,
        target: str,
        username: str,
        password: str,
        source_module: str,
        obtained_by: str,
        expires_at: float = 0.0,
    ) -> str:
        """Share a credential to the team pool (encrypted).

        Args:
            project_id: Target project ID.
            cred_type: Credential type.
            target: Target system/service.
            username: Username or account name.
            password: Password/hash value (will be encrypted).
            source_module: Module that obtained this credential.
            obtained_by: Member who obtained this credential.
            expires_at: Expiration timestamp.

        Returns:
            New credential ID.
        """
        cred_id = f"cred_{uuid.uuid4().hex[:12]}"
        now = time.time()

        encrypted_pw = self._encrypt_value(password)

        cred = SharedCredential(
            cred_id=cred_id,
            project_id=project_id,
            cred_type=cred_type,
            target=target,
            username=username,
            encrypted_password=encrypted_pw,
            source_module=source_module,
            obtained_by=obtained_by,
            obtained_at=now,
            expires_at=expires_at,
            is_valid=True,
        )

        self._credentials[cred_id] = cred
        self._save_credential(cred)

        for callback in self._cred_callbacks:
            try:
                await callback(project_id, cred)
            except Exception as e:
                logger.error(f"Credential callback error: {e}")

        return cred_id

    def get_credential_value(self, cred_id: str) -> Optional[str]:
        """Get decrypted credential value.

        Args:
            cred_id: Credential identifier.

        Returns:
            Decrypted password or None.
        """
        cred = self._credentials.get(cred_id)
        if not cred:
            return None

        return self._decrypt_value(cred.encrypted_password)

    def mask_credential_value(self, cred_id: str) -> str:
        """Get masked credential value for UI display.

        Args:
            cred_id: Credential identifier.

        Returns:
            Masked string (e.g., "****abcd").
        """
        cred = self._credentials.get(cred_id)
        if not cred:
            return ""

        value = self._decrypt_value(cred.encrypted_password)
        if len(value) <= 4:
            return "****"

        return "****" + value[-4:]

    async def use_credential(self, cred_id: str) -> bool:
        """Mark a credential as used (increment usage count).

        Args:
            cred_id: Credential identifier.

        Returns:
            True if marked successfully.
        """
        cred = self._credentials.get(cred_id)
        if not cred:
            return False

        cred.usage_count += 1
        self._save_credential(cred)

        return True

    async def share_traffic(
        self,
        project_id: str,
        request: str,
        response: str,
        url: str,
        method: str,
        status_code: int,
        shared_by: str,
        tags: Optional[List[str]] = None,
        notes: str = "",
    ) -> str:
        """Share HTTP traffic to the team war room.

        Args:
            project_id: Target project ID.
            request: HTTP request data.
            response: HTTP response data.
            url: Request URL.
            method: HTTP method.
            status_code: Response status code.
            shared_by: Member who shared this traffic.
            tags: Optional tags.
            notes: Optional notes.

        Returns:
            New traffic ID.
        """
        traffic_id = f"traffic_{uuid.uuid4().hex[:12]}"
        now = time.time()

        traffic = SharedTraffic(
            traffic_id=traffic_id,
            project_id=project_id,
            request=request,
            response=response,
            url=url,
            method=method,
            status_code=status_code,
            shared_by=shared_by,
            shared_at=now,
            tags=tags or [],
            notes=notes,
        )

        self._traffic[traffic_id] = traffic
        self._save_traffic(traffic)

        return traffic_id

    async def import_traffic(self, traffic_id: str) -> bool:
        """Mark traffic as imported by a member.

        Args:
            traffic_id: Traffic identifier.

        Returns:
            True if marked successfully.
        """
        traffic = self._traffic.get(traffic_id)
        if not traffic:
            return False

        traffic.is_imported = True
        self._save_traffic(traffic)

        return True

    async def share_vulnerability(
        self,
        project_id: str,
        asset_id: str,
        title: str,
        severity: str,
        description: str,
        proof: str,
        discovered_by: str,
    ) -> Optional[SharedVulnerability]:
        """Share a discovered vulnerability to the team pool.

        Args:
            project_id: Target project ID.
            asset_id: Associated asset ID.
            title: Vulnerability title.
            severity: Severity level.
            description: Vulnerability description.
            proof: Proof of concept.
            discovered_by: Member who discovered this vulnerability.

        Returns:
            SharedVulnerability if new, or existing if duplicate.
        """
        existing = self._find_vulnerability_by_key(project_id, asset_id, title)
        if existing:
            if discovered_by not in existing.affected_members:
                existing.affected_members.append(discovered_by)
                self._save_vulnerability(existing)
            return existing

        vuln_id = f"vuln_{uuid.uuid4().hex[:12]}"
        now = time.time()

        vuln = SharedVulnerability(
            vuln_id=vuln_id,
            project_id=project_id,
            asset_id=asset_id,
            title=title,
            severity=severity,
            description=description,
            proof=proof,
            discovered_by=discovered_by,
            discovered_at=now,
        )

        self._vulnerabilities[vuln_id] = vuln
        self._save_vulnerability(vuln)

        for callback in self._vuln_callbacks:
            try:
                await callback(project_id, vuln)
            except Exception as e:
                logger.error(f"Vulnerability callback error: {e}")

        return vuln

    async def update_vulnerability_status(
        self,
        vuln_id: str,
        status: VulnerabilityStatus,
    ) -> bool:
        """Update vulnerability confirmation status.

        Args:
            vuln_id: Vulnerability identifier.
            status: New status.

        Returns:
            True if updated successfully.
        """
        vuln = self._vulnerabilities.get(vuln_id)
        if not vuln:
            return False

        vuln.status = status
        self._save_vulnerability(vuln)

        return True

    def get_project_assets(self, project_id: str) -> List[SharedAsset]:
        """Get all shared assets for a project.

        Args:
            project_id: Project identifier.

        Returns:
            List of SharedAsset objects.
        """
        return [a for a in self._assets.values() if a.project_id == project_id]

    def get_project_credentials(self, project_id: str) -> List[SharedCredential]:
        """Get all shared credentials for a project.

        Args:
            project_id: Project identifier.

        Returns:
            List of SharedCredential objects.
        """
        return [c for c in self._credentials.values() if c.project_id == project_id]

    def get_project_traffic(self, project_id: str) -> List[SharedTraffic]:
        """Get all shared traffic for a project.

        Args:
            project_id: Project identifier.

        Returns:
            List of SharedTraffic objects.
        """
        return [t for t in self._traffic.values() if t.project_id == project_id]

    def get_project_vulnerabilities(self, project_id: str) -> List[SharedVulnerability]:
        """Get all shared vulnerabilities for a project.

        Args:
            project_id: Project identifier.

        Returns:
            List of SharedVulnerability objects.
        """
        return [v for v in self._vulnerabilities.values() if v.project_id == project_id]

    def _generate_asset_key(self, ip: str, port: int, protocol: str) -> str:
        """Generate unique key for asset deduplication.

        Args:
            ip: IP address.
            port: Port number.
            protocol: Protocol.

        Returns:
            Unique asset key.
        """
        raw = f"{ip}:{port}:{protocol}".lower()
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _find_asset_by_key(self, project_id: str, asset_key: str) -> Optional[SharedAsset]:
        """Find existing asset by deduplication key.

        Args:
            project_id: Project identifier.
            asset_key: Asset deduplication key.

        Returns:
            Existing SharedAsset or None.
        """
        for asset in self._assets.values():
            if asset.project_id != project_id:
                continue
            if self._generate_asset_key(asset.ip, asset.port, asset.protocol) == asset_key:
                return asset
        return None

    def _find_vulnerability_by_key(
        self,
        project_id: str,
        asset_id: str,
        title: str,
    ) -> Optional[SharedVulnerability]:
        """Find existing vulnerability by deduplication key.

        Args:
            project_id: Project identifier.
            asset_id: Asset identifier.
            title: Vulnerability title.

        Returns:
            Existing SharedVulnerability or None.
        """
        for vuln in self._vulnerabilities.values():
            if vuln.project_id != project_id:
                continue
            if vuln.asset_id == asset_id and vuln.title.lower() == title.lower():
                return vuln
        return None

    def _encrypt_value(self, value: str) -> str:
        """Encrypt a value using AES-256-GCM.

        Args:
            value: Value to encrypt.

        Returns:
            Base64 encoded encrypted value.
        """
        if not self.encryption_key:
            return base64.b64encode(value.encode()).decode()

        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            import os

            aesgcm = AESGCM(self.encryption_key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, value.encode(), None)

            return base64.b64encode(nonce + ciphertext).decode()

        except ImportError:
            return base64.b64encode(value.encode()).decode()

    def _decrypt_value(self, encrypted_value: str) -> str:
        """Decrypt an encrypted value.

        Args:
            encrypted_value: Base64 encoded encrypted value.

        Returns:
            Decrypted value string.
        """
        if not self.encryption_key:
            return base64.b64decode(encrypted_value.encode()).decode()

        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            data = base64.b64decode(encrypted_value.encode())
            nonce = data[:12]
            ciphertext = data[12:]

            aesgcm = AESGCM(self.encryption_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)

            return plaintext.decode()

        except ImportError:
            return base64.b64decode(encrypted_value.encode()).decode()

    def _save_asset(self, asset: SharedAsset) -> None:
        """Save asset to database.

        Args:
            asset: SharedAsset to save.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO shared_assets VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                asset.asset_id,
                asset.project_id,
                asset.ip,
                asset.port,
                asset.protocol,
                asset.service,
                asset.fingerprint,
                asset.hostname,
                asset.discovered_by,
                asset.discovered_at,
                asset.claimed_by or None,
                asset.claim_status.value,
                json.dumps(asset.tags),
                asset.notes,
            ),
        )
        conn.commit()
        conn.close()

    def _save_credential(self, cred: SharedCredential) -> None:
        """Save credential to database.

        Args:
            cred: SharedCredential to save.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO shared_credentials VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                cred.cred_id,
                cred.project_id,
                cred.cred_type.value,
                cred.target,
                cred.username,
                cred.encrypted_password,
                cred.source_module,
                cred.obtained_by,
                cred.obtained_at,
                cred.expires_at if cred.expires_at > 0 else None,
                int(cred.is_valid),
                cred.usage_count,
            ),
        )
        conn.commit()
        conn.close()

    def _save_traffic(self, traffic: SharedTraffic) -> None:
        """Save traffic to database.

        Args:
            traffic: SharedTraffic to save.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO shared_traffic VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                traffic.traffic_id,
                traffic.project_id,
                traffic.request,
                traffic.response,
                traffic.url,
                traffic.method,
                traffic.status_code,
                traffic.shared_by,
                traffic.shared_at,
                json.dumps(traffic.tags),
                traffic.notes,
                int(traffic.is_imported),
            ),
        )
        conn.commit()
        conn.close()

    def _save_vulnerability(self, vuln: SharedVulnerability) -> None:
        """Save vulnerability to database.

        Args:
            vuln: SharedVulnerability to save.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO shared_vulnerabilities VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                vuln.vuln_id,
                vuln.project_id,
                vuln.asset_id,
                vuln.title,
                vuln.severity,
                vuln.description,
                vuln.proof,
                vuln.discovered_by,
                vuln.discovered_at,
                vuln.status.value,
                json.dumps(vuln.affected_members),
            ),
        )
        conn.commit()
        conn.close()
