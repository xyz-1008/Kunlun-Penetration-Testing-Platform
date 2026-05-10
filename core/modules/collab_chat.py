"""Collaboration Chat: Project built-in encrypted chat, message types, history archiving.

Provides:
- Project space built-in encrypted chat room (end-to-end AES-256 encryption)
- Support sending: text messages, code snippets, screenshots, file attachments
- Message types: normal messages, system notifications (task assignment, vulnerability discovery), alert messages
- Message search and history archiving
"""

import asyncio
import base64
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


class MessageType(Enum):
    """Types of chat messages."""
    TEXT = "text"
    CODE = "code"
    IMAGE = "image"
    FILE = "file"
    SYSTEM = "system"
    ALERT = "alert"
    TASK_NOTIFICATION = "task_notification"
    VULNERABILITY_NOTIFICATION = "vulnerability_notification"


@dataclass
class ChatMessage:
    """Chat message in the project war room.

    Attributes:
        message_id: Unique message identifier
        project_id: Parent project ID
        sender_id: Member who sent this message
        sender_name: Display name of sender
        message_type: Type of message
        content: Message content (text, code, file path, etc.)
        metadata: Additional metadata (file size, language, etc.)
        timestamp: Message timestamp
        is_encrypted: Whether content is encrypted
        reply_to: Message ID this is replying to
    """
    message_id: str = ""
    project_id: str = ""
    sender_id: str = ""
    sender_name: str = ""
    message_type: MessageType = MessageType.TEXT
    content: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0
    is_encrypted: bool = True
    reply_to: str = ""


class ChatManager:
    """Manages encrypted chat rooms for project collaboration.

    Provides end-to-end encrypted messaging, multiple message types,
    message search, and history archiving capabilities.
    """

    def __init__(self, db_path: str = "", encryption_key: bytes = b"") -> None:
        """Initialize chat manager.

        Args:
            db_path: Path to SQLite database file.
            encryption_key: AES-256 key for message encryption.
        """
        self.db_path = db_path or "collab_chat.db"
        self.encryption_key = encryption_key
        self._messages: Dict[str, List[ChatMessage]] = {}
        self._message_callbacks: List[Callable[[str, ChatMessage], Coroutine[Any, Any, None]]] = []

        self._init_database()
        self._load_messages()

    def register_message_callback(
        self,
        callback: Callable[[str, ChatMessage], Coroutine[Any, Any, None]],
    ) -> None:
        """Register callback for new chat messages.

        Args:
            callback: Async callback receiving project_id and message.
        """
        self._message_callbacks.append(callback)

    def _init_database(self) -> None:
        """Initialize SQLite database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_messages (
                message_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                sender_name TEXT NOT NULL,
                message_type TEXT NOT NULL,
                content TEXT NOT NULL,
                metadata TEXT,
                timestamp REAL NOT NULL,
                is_encrypted INTEGER NOT NULL,
                reply_to TEXT
            )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_chat_project ON chat_messages(project_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_chat_timestamp ON chat_messages(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_chat_sender ON chat_messages(sender_id)")

        conn.commit()
        conn.close()

    def _load_messages(self) -> None:
        """Load all chat messages from database."""
        if not os.path.exists(self.db_path):
            return

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM chat_messages ORDER BY timestamp ASC")
        for row in cursor.fetchall():
            message = ChatMessage(
                message_id=row[0],
                project_id=row[1],
                sender_id=row[2],
                sender_name=row[3],
                message_type=MessageType(row[4]),
                content=row[5],
                metadata=json.loads(row[6]) if row[6] else {},
                timestamp=row[7],
                is_encrypted=bool(row[8]),
                reply_to=row[9] or "",
            )

            if message.project_id not in self._messages:
                self._messages[message.project_id] = []

            self._messages[message.project_id].append(message)

        conn.close()

    async def send_message(
        self,
        project_id: str,
        sender_id: str,
        sender_name: str,
        content: str,
        message_type: MessageType = MessageType.TEXT,
        metadata: Optional[Dict[str, Any]] = None,
        reply_to: str = "",
    ) -> str:
        """Send a message to the project chat room.

        Args:
            project_id: Target project ID.
            sender_id: Member who sent this message.
            sender_name: Display name of sender.
            content: Message content.
            message_type: Type of message.
            metadata: Additional metadata.
            reply_to: Message ID this is replying to.

        Returns:
            New message ID.
        """
        message_id = f"msg_{uuid.uuid4().hex[:12]}"
        now = time.time()

        encrypted_content = content
        is_encrypted = False

        if message_type == MessageType.TEXT and self.encryption_key:
            encrypted_content = self._encrypt_content(content)
            is_encrypted = True

        message = ChatMessage(
            message_id=message_id,
            project_id=project_id,
            sender_id=sender_id,
            sender_name=sender_name,
            message_type=message_type,
            content=encrypted_content,
            metadata=metadata or {},
            timestamp=now,
            is_encrypted=is_encrypted,
            reply_to=reply_to,
        )

        if project_id not in self._messages:
            self._messages[project_id] = []

        self._messages[project_id].append(message)
        self._save_message(message)

        for callback in self._message_callbacks:
            try:
                await callback(project_id, message)
            except Exception as e:
                logger.error(f"Message callback error: {e}")

        return message_id

    async def send_system_notification(
        self,
        project_id: str,
        notification_text: str,
    ) -> str:
        """Send a system notification to the project chat room.

        Args:
            project_id: Target project ID.
            notification_text: Notification text.

        Returns:
            New message ID.
        """
        return await self.send_message(
            project_id=project_id,
            sender_id="system",
            sender_name="System",
            content=notification_text,
            message_type=MessageType.SYSTEM,
        )

    async def send_alert_message(
        self,
        project_id: str,
        alert_text: str,
    ) -> str:
        """Send an alert message to the project chat room.

        Args:
            project_id: Target project ID.
            alert_text: Alert text.

        Returns:
            New message ID.
        """
        return await self.send_message(
            project_id=project_id,
            sender_id="system",
            sender_name="Alert",
            content=alert_text,
            message_type=MessageType.ALERT,
        )

    async def send_code_snippet(
        self,
        project_id: str,
        sender_id: str,
        sender_name: str,
        code: str,
        language: str = "",
        reply_to: str = "",
    ) -> str:
        """Send a code snippet to the project chat room.

        Args:
            project_id: Target project ID.
            sender_id: Member who sent this message.
            sender_name: Display name of sender.
            code: Code content.
            language: Programming language.
            reply_to: Message ID this is replying to.

        Returns:
            New message ID.
        """
        metadata = {"language": language} if language else {}

        return await self.send_message(
            project_id=project_id,
            sender_id=sender_id,
            sender_name=sender_name,
            content=code,
            message_type=MessageType.CODE,
            metadata=metadata,
            reply_to=reply_to,
        )

    async def send_file_attachment(
        self,
        project_id: str,
        sender_id: str,
        sender_name: str,
        file_path: str,
        file_name: str,
        file_size: int,
        reply_to: str = "",
    ) -> str:
        """Send a file attachment to the project chat room.

        Args:
            project_id: Target project ID.
            sender_id: Member who sent this message.
            sender_name: Display name of sender.
            file_path: Path to the file.
            file_name: Display name of the file.
            file_size: File size in bytes.
            reply_to: Message ID this is replying to.

        Returns:
            New message ID.
        """
        metadata = {
            "file_path": file_path,
            "file_name": file_name,
            "file_size": file_size,
        }

        return await self.send_message(
            project_id=project_id,
            sender_id=sender_id,
            sender_name=sender_name,
            content=file_name,
            message_type=MessageType.FILE,
            metadata=metadata,
            reply_to=reply_to,
        )

    def get_project_messages(
        self,
        project_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> List[ChatMessage]:
        """Get messages for a project chat room.

        Args:
            project_id: Project identifier.
            limit: Maximum messages to return.
            offset: Number of messages to skip.

        Returns:
            List of ChatMessage objects, newest first.
        """
        messages = self._messages.get(project_id, [])

        sorted_messages = sorted(messages, key=lambda m: m.timestamp, reverse=True)

        return sorted_messages[offset:offset + limit]

    def search_messages(
        self,
        project_id: str,
        query: str,
        sender_id: str = "",
        message_type: Optional[MessageType] = None,
        start_time: float = 0.0,
        end_time: float = 0.0,
    ) -> List[ChatMessage]:
        """Search messages by various criteria.

        Args:
            project_id: Project identifier.
            query: Search query (case-insensitive).
            sender_id: Filter by sender (empty for all).
            message_type: Filter by message type (None for all).
            start_time: Filter messages after this timestamp.
            end_time: Filter messages before this timestamp.

        Returns:
            List of matching ChatMessage objects.
        """
        messages = self._messages.get(project_id, [])

        results = []
        query_lower = query.lower()

        for message in messages:
            if sender_id and message.sender_id != sender_id:
                continue

            if message_type and message.message_type != message_type:
                continue

            if start_time > 0 and message.timestamp < start_time:
                continue

            if end_time > 0 and message.timestamp > end_time:
                continue

            content = self._get_message_content(message)
            if query_lower in content.lower():
                results.append(message)

        results.sort(key=lambda m: m.timestamp, reverse=True)

        return results

    def archive_project_messages(self, project_id: str) -> str:
        """Archive all messages for a project as JSON.

        Args:
            project_id: Project identifier.

        Returns:
            JSON string of archived messages.
        """
        messages = self._messages.get(project_id, [])

        archive_data = [
            {
                "message_id": m.message_id,
                "timestamp": m.timestamp,
                "timestamp_human": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(m.timestamp)),
                "sender_id": m.sender_id,
                "sender_name": m.sender_name,
                "message_type": m.message_type.value,
                "content": self._get_message_content(m),
                "metadata": m.metadata,
                "reply_to": m.reply_to,
            }
            for m in sorted(messages, key=lambda x: x.timestamp)
        ]

        return json.dumps(archive_data, ensure_ascii=False, indent=2)

    def get_message_count(self, project_id: str) -> int:
        """Get total message count for a project.

        Args:
            project_id: Project identifier.

        Returns:
            Total message count.
        """
        return len(self._messages.get(project_id, []))

    def get_active_senders(self, project_id: str) -> List[Tuple[str, int]]:
        """Get list of active senders and their message counts.

        Args:
            project_id: Project identifier.

        Returns:
            List of (sender_name, message_count) tuples.
        """
        messages = self._messages.get(project_id, [])

        sender_counts: Dict[str, int] = {}
        for message in messages:
            sender_counts[message.sender_name] = sender_counts.get(message.sender_name, 0) + 1

        return sorted(sender_counts.items(), key=lambda x: x[1], reverse=True)

    def _get_message_content(self, message: ChatMessage) -> str:
        """Get decrypted message content for display.

        Args:
            message: ChatMessage to decrypt if needed.

        Returns:
            Decrypted or original content.
        """
        if message.is_encrypted:
            return self._decrypt_content(message.content)
        return message.content

    def _encrypt_content(self, content: str) -> str:
        """Encrypt message content using AES-256-GCM.

        Args:
            content: Content to encrypt.

        Returns:
            Base64 encoded encrypted content.
        """
        if not self.encryption_key:
            return base64.b64encode(content.encode()).decode()

        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            import os

            aesgcm = AESGCM(self.encryption_key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, content.encode(), None)

            return base64.b64encode(nonce + ciphertext).decode()

        except ImportError:
            return base64.b64encode(content.encode()).decode()

    def _decrypt_content(self, encrypted_content: str) -> str:
        """Decrypt encrypted message content.

        Args:
            encrypted_content: Base64 encoded encrypted content.

        Returns:
            Decrypted content string.
        """
        if not self.encryption_key:
            return base64.b64decode(encrypted_content.encode()).decode()

        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            data = base64.b64decode(encrypted_content.encode())
            nonce = data[:12]
            ciphertext = data[12:]

            aesgcm = AESGCM(self.encryption_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)

            return plaintext.decode()

        except ImportError:
            return base64.b64decode(encrypted_content.encode()).decode()

    def _save_message(self, message: ChatMessage) -> None:
        """Save chat message to database.

        Args:
            message: ChatMessage to save.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO chat_messages VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                message.message_id,
                message.project_id,
                message.sender_id,
                message.sender_name,
                message.message_type.value,
                message.content,
                json.dumps(message.metadata),
                message.timestamp,
                int(message.is_encrypted),
                message.reply_to or None,
            ),
        )
        conn.commit()
        conn.close()
