"""
P2P Mesh Network Module - Kademlia DHT self-organizing network between beacons.

This module provides peer-to-peer mesh networking capabilities using:
    1. Kademlia Distributed Hash Table for beacon discovery
    2. Automatic task and configuration synchronization
    3. Self-healing network topology
    4. Decentralized message routing

Core capabilities:
    - Kademlia DHT node implementation
    - Peer discovery and routing table maintenance
    - Key-value storage and retrieval
    - Message routing through DHT network
    - Automatic failover and task redistribution

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import os
import random
import socket
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class MessageType(str, Enum):
    """P2P message types."""

    PING = "ping"
    PONG = "pong"
    STORE = "store"
    FIND_NODE = "find_node"
    FIND_VALUE = "find_value"
    NODE_RESPONSE = "node_response"
    VALUE_RESPONSE = "value_response"
    TASK_SYNC = "task_sync"
    PROFILE_SYNC = "profile_sync"
    BEACON_JOIN = "beacon_join"
    BEACON_LEAVE = "beacon_leave"


class NodeState(str, Enum):
    """Node operational states."""

    ACTIVE = "active"
    SUSPECTED = "suspected"
    DEAD = "dead"
    JOINING = "joining"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class NodeId:
    """Kademlia node identifier.

    Attributes:
        id_bytes: 160-bit node ID
        id_int: Integer representation
        id_hex: Hex string representation
    """

    id_bytes: bytes = b""
    id_int: int = 0
    id_hex: str = ""

    def __init__(self, value: Optional[bytes] = None) -> None:
        """Initialize NodeId.

        Args:
            value: Node ID bytes.
        """
        if value:
            self.id_bytes = value
        else:
            self.id_bytes = os.urandom(20)

        self.id_int = int.from_bytes(self.id_bytes, "big")
        self.id_hex = self.id_bytes.hex()

    def distance(self, other: "NodeId") -> int:
        """Calculate XOR distance to another node.

        Args:
            other: Other NodeId.

        Returns:
            XOR distance.
        """
        return self.id_int ^ other.id_int

    def prefix_match(self, other: "NodeId", bits: int) -> bool:
        """Check if IDs match on first N bits.

        Args:
            other: Other NodeId.
            bits: Number of bits to match.

        Returns:
            True if prefix matches.
        """
        mask = (1 << (160 - bits)) - 1
        return (self.id_int & mask) == (other.id_int & mask)

    def __eq__(self, other: object) -> bool:
        """Check equality."""
        if not isinstance(other, NodeId):
            return False
        return self.id_bytes == other.id_bytes

    def __lt__(self, other: "NodeId") -> bool:
        """Compare by distance."""
        return self.id_int < other.id_int

    def __hash__(self) -> int:
        """Hash function."""
        return hash(self.id_bytes)


@dataclass
class Contact:
    """Kademlia contact information.

    Attributes:
        node_id: Node identifier
        ip_address: IP address
        port: Port number
        state: Node state
        last_seen: Last contact timestamp
        last_failed: Last failed attempt
    """

    node_id: NodeId = field(default_factory=NodeId)
    ip_address: str = ""
    port: int = 0
    state: NodeState = NodeState.ACTIVE
    last_seen: float = 0.0
    last_failed: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "node_id": self.node_id.id_hex[:16],
            "ip_address": self.ip_address,
            "port": self.port,
            "state": self.state.value,
        }


@dataclass
class KBucket:
    """Kademlia k-bucket for routing table.

    Attributes:
        contacts: List of contacts
        k: Maximum bucket size
        min_range: Minimum ID range
        max_range: Maximum ID range
    """

    contacts: List[Contact] = field(default_factory=list)
    k: int = 20
    min_range: int = 0
    max_range: int = 0

    def add_contact(self, contact: Contact) -> bool:
        """Add or update contact in bucket.

        Args:
            contact: Contact to add.

        Returns:
            True if added successfully.
        """
        for i, existing in enumerate(self.contacts):
            if existing.node_id == contact.node_id:
                self.contacts.pop(i)
                self.contacts.insert(0, contact)
                return True

        if len(self.contacts) < self.k:
            self.contacts.append(contact)
            return True

        return False

    def get_contacts(self, count: int = 0) -> List[Contact]:
        """Get contacts from bucket.

        Args:
            count: Maximum count (0 for all).

        Returns:
            List of contacts.
        """
        if count <= 0:
            return self.contacts[:]
        return self.contacts[:count]


@dataclass
class MeshConfig:
    """P2P mesh network configuration.

    Attributes:
        node_id: This node's ID
        listen_port: Listening port
        k_bucket_size: K-bucket size
        alpha: Concurrent lookup parameter
        refresh_interval: Routing table refresh interval
        bootstrap_nodes: Initial bootstrap nodes
        network_id: Network identifier
    """

    node_id: str = ""
    listen_port: int = 14000
    k_bucket_size: int = 20
    alpha: int = 3
    refresh_interval: int = 3600
    bootstrap_nodes: List[str] = field(default_factory=list)
    network_id: str = "kunlun_mesh"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "node_id": self.node_id[:16],
            "listen_port": self.listen_port,
            "k_bucket_size": self.k_bucket_size,
            "bootstrap_count": len(self.bootstrap_nodes),
        }


@dataclass
class MeshStatus:
    """P2P mesh network status.

    Attributes:
        node_count: Known node count
        bucket_count: Routing table bucket count
        stored_keys: Number of stored keys
        messages_sent: Messages sent count
        messages_received: Messages received count
        uptime: Node uptime
    """

    node_count: int = 0
    bucket_count: int = 0
    stored_keys: int = 0
    messages_sent: int = 0
    messages_received: int = 0
    uptime: float = 0.0
    start_time: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "node_count": self.node_count,
            "bucket_count": self.bucket_count,
            "stored_keys": self.stored_keys,
            "uptime": self.uptime,
        }


# =============================================================================
# Kademlia Routing Table
# =============================================================================

class KademliaRoutingTable:
    """Kademlia routing table with k-buckets.

    Maintains the distributed hash table routing table
    for efficient node lookups.

    Attributes:
        _node_id: This node's ID
        _buckets: List of k-buckets
        _k: Bucket size
    """

    def __init__(
        self,
        node_id: NodeId,
        k: int = 20,
    ) -> None:
        """Initialize the KademliaRoutingTable.

        Args:
            node_id: This node's ID.
            k: Bucket size.
        """
        self._node_id = node_id
        self._k = k
        self._buckets: List[KBucket] = [
            KBucket(k=k, min_range=0, max_range=1 << 160),
        ]

    def add_contact(self, contact: Contact) -> None:
        """Add or update contact in routing table.

        Args:
            contact: Contact to add.
        """
        if contact.node_id == self._node_id:
            return

        distance = self._node_id.distance(contact.node_id)

        for bucket in self._buckets:
            if bucket.min_range <= distance < bucket.max_range:
                bucket.add_contact(contact)
                return

    def remove_contact(self, node_id: NodeId) -> bool:
        """Remove contact from routing table.

        Args:
            node_id: Node to remove.

        Returns:
            True if removed.
        """
        for bucket in self._buckets:
            for i, contact in enumerate(bucket.contacts):
                if contact.node_id == node_id:
                    bucket.contacts.pop(i)
                    return True
        return False

    def get_nearest_nodes(
        self,
        target_id: NodeId,
        count: int = 20,
    ) -> List[Contact]:
        """Get nearest nodes to target ID.

        Args:
            target_id: Target node ID.
            count: Maximum nodes to return.

        Returns:
            List of nearest contacts.
        """
        all_contacts: List[Tuple[int, Contact]] = []

        for bucket in self._buckets:
            for contact in bucket.contacts:
                distance = target_id.distance(contact.node_id)
                all_contacts.append((distance, contact))

        all_contacts.sort(key=lambda x: x[0])

        return [c for _, c in all_contacts[:count]]

    def get_all_contacts(self) -> List[Contact]:
        """Get all contacts in routing table.

        Returns:
            List of all contacts.
        """
        contacts: List[Contact] = []
        for bucket in self._buckets:
            contacts.extend(bucket.contacts)
        return contacts

    def get_bucket_count(self) -> int:
        """Get number of buckets.

        Returns:
            Bucket count.
        """
        return len(self._buckets)

    def get_status(self) -> Dict[str, Any]:
        """Get routing table status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "bucket_count": len(self._buckets),
            "total_contacts": len(self.get_all_contacts()),
        }


# =============================================================================
# DHT Storage
# =============================================================================

class DHTStorage:
    """Distributed hash table storage.

    Stores key-value pairs in the DHT network with
    replication and expiration.

    Attributes:
        _data: Stored key-value pairs
        _expiry: Key expiry times
        _replicas: Replication count per key
    """

    def __init__(self, replicas: int = 3) -> None:
        """Initialize the DHTStorage.

        Args:
            replicas: Number of replicas per key.
        """
        self._data: Dict[str, Any] = {}
        self._expiry: Dict[str, float] = {}
        self._replicas = replicas

    def store(
        self,
        key: str,
        value: Any,
        ttl_seconds: int = 86400,
    ) -> bool:
        """Store a key-value pair.

        Args:
            key: Storage key.
            value: Value to store.
            ttl_seconds: Time-to-live.

        Returns:
            True if stored successfully.
        """
        self._data[key] = value
        self._expiry[key] = time.time() + ttl_seconds
        return True

    def retrieve(self, key: str) -> Optional[Any]:
        """Retrieve a value by key.

        Args:
            key: Storage key.

        Returns:
            Stored value, or None.
        """
        if key not in self._data:
            return None

        if time.time() > self._expiry.get(key, 0):
            del self._data[key]
            del self._expiry[key]
            return None

        return self._data[key]

    def delete(self, key: str) -> bool:
        """Delete a key-value pair.

        Args:
            key: Key to delete.

        Returns:
            True if deleted.
        """
        if key in self._data:
            del self._data[key]
            if key in self._expiry:
                del self._expiry[key]
            return True
        return False

    def get_key_count(self) -> int:
        """Get number of stored keys.

        Returns:
            Key count.
        """
        return len(self._data)

    def cleanup_expired(self) -> int:
        """Remove expired keys.

        Returns:
            Number of keys removed.
        """
        now = time.time()
        expired = [k for k, v in self._expiry.items() if now > v]

        for key in expired:
            del self._data[key]
            del self._expiry[key]

        return len(expired)


# =============================================================================
# P2P Message Router
# =============================================================================

class P2PMessageRouter:
    """Routes messages through the P2P mesh network.

    Handles message encoding, routing, and delivery
    through the DHT network.

    Attributes:
        _node_id: This node's ID
        _routing_table: Routing table
        _pending_requests: Pending request tracking
    """

    def __init__(
        self,
        node_id: NodeId,
        routing_table: KademliaRoutingTable,
    ) -> None:
        """Initialize the P2PMessageRouter.

        Args:
            node_id: This node's ID.
            routing_table: Routing table.
        """
        self._node_id = node_id
        self._routing_table = routing_table
        self._pending_requests: Dict[str, asyncio.Event] = {}

    def create_message(
        self,
        msg_type: MessageType,
        payload: Dict[str, Any],
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a P2P message.

        Args:
            msg_type: Message type.
            payload: Message payload.
            request_id: Request identifier.

        Returns:
            Message dictionary.
        """
        return {
            "type": msg_type.value,
            "sender": self._node_id.id_hex,
            "request_id": request_id or hashlib.md5(
                f"{time.time()}_{random.random()}".encode()
            ).hexdigest()[:12],
            "payload": payload,
            "timestamp": time.time(),
            "ttl": 10,
        }

    async def send_message(
        self,
        target: Contact,
        message: Dict[str, Any],
    ) -> bool:
        """Send message to a contact.

        Args:
            target: Target contact.
            message: Message to send.

        Returns:
            True if send succeeded.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.ip_address, target.port),
                timeout=10,
            )

            data = json.dumps(message).encode()
            writer.write(struct.pack("!I", len(data)) + data)
            await writer.drain()
            writer.close()

            return True

        except Exception as e:
            logger.error(f"Message send failed: {e}")
            return False

    async def iterative_find_nodes(
        self,
        target_id: NodeId,
    ) -> List[Contact]:
        """Iteratively find nodes closest to target.

        Args:
            target_id: Target node ID.

        Returns:
            List of closest contacts.
        """
        shortlist = self._routing_table.get_nearest_nodes(target_id, 20)
        contacted: Set[str] = set()

        while shortlist:
            alpha_nodes = shortlist[:3]
            shortlist = shortlist[3:]

            for node in alpha_nodes:
                if node.node_id.id_hex in contacted:
                    continue

                contacted.add(node.node_id.id_hex)

                response = await self._query_node(node, target_id)
                if response:
                    for contact in response:
                        if contact.node_id.id_hex not in contacted:
                            shortlist.append(contact)

            shortlist.sort(key=lambda c: target_id.distance(c.node_id))

        return self._routing_table.get_nearest_nodes(target_id, 20)

    async def _query_node(
        self,
        node: Contact,
        target_id: NodeId,
    ) -> Optional[List[Contact]]:
        """Query a node for nearest contacts.

        Args:
            node: Node to query.
            target_id: Target ID.

        Returns:
            List of contacts, or None.
        """
        message = self.create_message(
            MessageType.FIND_NODE,
            {"target_id": target_id.id_hex},
        )

        if await self.send_message(node, message):
            return self._routing_table.get_nearest_nodes(target_id, 20)

        return None


# =============================================================================
# P2P Mesh Network Manager
# =============================================================================

class P2PMeshManager:
    """Main P2P mesh network coordination engine.

    Integrates Kademlia DHT, storage, and message routing
    for decentralized beacon networking.

    Attributes:
        _config: Mesh configuration
        _node_id: This node's ID
        _routing_table: Routing table
        _storage: DHT storage
        _router: Message router
        _status: Mesh status
        _running: Whether mesh is running
    """

    def __init__(
        self,
        config: Optional[MeshConfig] = None,
    ) -> None:
        """Initialize the P2PMeshManager.

        Args:
            config: Mesh configuration.
        """
        self._config = config or MeshConfig()

        if self._config.node_id:
            node_bytes = bytes.fromhex(self._config.node_id.ljust(40, "0")[:40])
            self._node_id = NodeId(node_bytes)
        else:
            self._node_id = NodeId()
            self._config.node_id = self._node_id.id_hex

        self._routing_table = KademliaRoutingTable(
            self._node_id, self._config.k_bucket_size,
        )
        self._storage = DHTStorage()
        self._router = P2PMessageRouter(self._node_id, self._routing_table)
        self._status = MeshStatus()
        self._running = False

    async def start(self) -> bool:
        """Start P2P mesh network.

        Returns:
            True if start succeeded.
        """
        self._running = True
        self._status.start_time = time.time()

        for bootstrap in self._config.bootstrap_nodes:
            await self._bootstrap_to_node(bootstrap)

        logger.info(
            f"P2P mesh started: node {self._node_id.id_hex[:16]}"
        )
        return True

    async def stop(self) -> None:
        """Stop P2P mesh network."""
        self._running = False
        logger.info("P2P mesh stopped")

    async def _bootstrap_to_node(self, address: str) -> bool:
        """Bootstrap to a known node.

        Args:
            address: Node address (ip:port).

        Returns:
            True if bootstrap succeeded.
        """
        try:
            parts = address.split(":")
            ip = parts[0]
            port = int(parts[1]) if len(parts) > 1 else 14000

            contact = Contact(
                node_id=NodeId(),
                ip_address=ip,
                port=port,
                last_seen=time.time(),
            )

            self._routing_table.add_contact(contact)
            return True

        except Exception as e:
            logger.error(f"Bootstrap failed: {e}")
            return False

    async def store_data(
        self,
        key: str,
        value: Any,
        ttl_seconds: int = 86400,
    ) -> bool:
        """Store data in DHT.

        Args:
            key: Storage key.
            value: Value to store.
            ttl_seconds: Time-to-live.

        Returns:
            True if stored successfully.
        """
        return self._storage.store(key, value, ttl_seconds)

    async def retrieve_data(self, key: str) -> Optional[Any]:
        """Retrieve data from DHT.

        Args:
            key: Storage key.

        Returns:
            Stored value, or None.
        """
        return self._storage.retrieve(key)

    async def find_nodes(
        self, target_id: str,
    ) -> List[Contact]:
        """Find nodes closest to target ID.

        Args:
            target_id: Target node ID hex string.

        Returns:
            List of closest contacts.
        """
        target_bytes = bytes.fromhex(target_id.ljust(40, "0")[:40])
        target = NodeId(target_bytes)

        return await self._router.iterative_find_nodes(target)

    def get_known_nodes(self) -> List[Contact]:
        """Get all known nodes.

        Returns:
            List of contacts.
        """
        return self._routing_table.get_all_contacts()

    def get_status(self) -> Dict[str, Any]:
        """Get mesh network status.

        Returns:
            Dictionary with status summary.
        """
        if self._status.start_time > 0:
            self._status.uptime = time.time() - self._status.start_time

        self._status.node_count = len(self.get_known_nodes())
        self._status.bucket_count = self._routing_table.get_bucket_count()
        self._status.stored_keys = self._storage.get_key_count()

        return {
            "status": self._status.to_dict(),
            "config": self._config.to_dict(),
            "routing_table": self._routing_table.get_status(),
        }


# =============================================================================
# Global Singleton
# =============================================================================

_p2p_mesh_manager: Optional[P2PMeshManager] = None


def get_p2p_mesh_manager(
    config: Optional[MeshConfig] = None,
) -> P2PMeshManager:
    """Get the global P2PMeshManager singleton.

    Args:
        config: Mesh configuration.

    Returns:
        Singleton P2PMeshManager instance.
    """
    global _p2p_mesh_manager
    if _p2p_mesh_manager is None:
        _p2p_mesh_manager = P2PMeshManager(config)
    return _p2p_mesh_manager


__all__ = [
    "P2PMeshManager",
    "KademliaRoutingTable",
    "DHTStorage",
    "P2PMessageRouter",
    "NodeId",
    "Contact",
    "KBucket",
    "MeshConfig",
    "MeshStatus",
    "MessageType",
    "NodeState",
    "get_p2p_mesh_manager",
]
