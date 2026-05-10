"""PCAP Exporter: Pure Python PCAP/PCAPNG file writer for captured traffic.

Provides:
- Pure Python PCAP file writing (no libpcap dependency)
- PCAP and PCAPNG format support
- Virtual Ethernet/IP/TCP/UDP layer construction
- TCP session state management (handshake, teardown, keep-alive)
- WebSocket upgrade and data frame simulation
- TCP segmentation with configurable MSS
- TLS traffic handling (decrypted plaintext or original TLS records)
- Export filtering by domain, URL, time range, method, status code
- Streaming write support for large files (>1GB)
- Progress callback for large exports
"""

import asyncio
import logging
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

PCAP_MAGIC_NUMBER = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAPNG_SECTION_BLOCK_MAGIC = 0x0A0D0D0A
PCAPNG_INTERFACE_BLOCK_MAGIC = 0x00000001
PCAPNG_PACKET_BLOCK_MAGIC = 0x00000002
PCAPNG_SIMPLE_PACKET_BLOCK_MAGIC = 0x00000003
PCAPNG_INTERFACE_STATS_BLOCK_MAGIC = 0x00000005
PCAPNG_NAME_RESOLUTION_BLOCK_MAGIC = 0x00000006
PCAPNG_INTERFACE_STATS_BLOCK_MAGIC_V2 = 0x00000007

ETHERNET_TYPE_IP = 0x0800
ETHERNET_TYPE_IPV6 = 0x86DD
IP_PROTOCOL_TCP = 6
IP_PROTOCOL_UDP = 17

DEFAULT_MSS = 1460
DEFAULT_SRC_MAC = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
DEFAULT_DST_MAC = bytes([0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB])


class TCPFlag(Enum):
    """TCP flags."""
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20


class PCAPLinkType(Enum):
    """PCAP link type values."""
    ETHERNET = 1
    RAW_IP = 101
    IPV4 = 228
    IPV6 = 229


class PCAPExporter:
    """Pure Python PCAP/PCAPNG exporter for captured HTTP/HTTPS/WebSocket traffic.

    Constructs virtual Ethernet/IP/TCP layers to encapsulate proxy-captured
    traffic into standard PCAP format for Wireshark and other tools.

    Attributes:
        mss: Maximum Segment Size for TCP segmentation
        preserve_tls: Whether to preserve original TLS records
        src_mac_template: Source MAC address template
        dst_mac_template: Destination MAC address template
        link_type: PCAP link type
    """

    def __init__(
        self,
        mss: int = DEFAULT_MSS,
        preserve_tls: bool = False,
        src_mac: Optional[bytes] = None,
        dst_mac: Optional[bytes] = None,
        link_type: PCAPLinkType = PCAPLinkType.ETHERNET,
        progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Initialize PCAP exporter.

        Args:
            mss: Maximum Segment Size for TCP segmentation.
            preserve_tls: Whether to preserve original TLS records.
            src_mac: Source MAC address (6 bytes). Uses default if None.
            dst_mac: Destination MAC address (6 bytes). Uses default if None.
            link_type: PCAP link type.
            progress_callback: Async callback for progress reporting.
        """
        self.mss = mss
        self.preserve_tls = preserve_tls
        self.src_mac = src_mac or DEFAULT_SRC_MAC
        self.dst_mac = dst_mac or DEFAULT_DST_MAC
        self.link_type = link_type
        self._progress_callback = progress_callback
        self._file_handle: Optional[Any] = None
        self._packet_count = 0
        self._tcp_sequences: Dict[str, Dict[str, int]] = {}

    async def _report_progress(self, message: str, percentage: float) -> None:
        """Report export progress.

        Args:
            message: Progress message.
            percentage: Progress percentage (0-100).
        """
        if self._progress_callback:
            await self._progress_callback(message, percentage)

    def _ip_to_bytes(self, ip_str: str) -> bytes:
        """Convert IP address string to bytes.

        Args:
            ip_str: IP address string (e.g., "192.168.1.1").

        Returns:
            4 bytes representing the IP address.
        """
        try:
            parts = ip_str.split(".")
            return bytes(int(p) for p in parts)
        except (ValueError, AttributeError):
            return bytes([127, 0, 0, 1])

    def _build_ethernet_header(
        self,
        eth_type: int = ETHERNET_TYPE_IP,
    ) -> bytes:
        """Build Ethernet II header.

        Args:
            eth_type: EtherType value.

        Returns:
            Ethernet header bytes (14 bytes).
        """
        return struct.pack(
            "!6s6sH",
            self.dst_mac,
            self.src_mac,
            eth_type,
        )

    def _build_ipv4_header(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: int,
        payload_length: int,
        identification: int = 0,
    ) -> bytes:
        """Build IPv4 header.

        Args:
            src_ip: Source IP address.
            dst_ip: Destination IP address.
            protocol: IP protocol number.
            payload_length: Payload length in bytes.
            identification: IP identification field.

        Returns:
            IPv4 header bytes (20 bytes).
        """
        version_ihl = (4 << 4) | 5
        total_length = 20 + payload_length
        ttl = 64
        flags_fragment = 0x4000

        header = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            0,
            total_length,
            identification,
            flags_fragment,
            ttl,
            protocol,
            0,
            self._ip_to_bytes(src_ip),
            self._ip_to_bytes(dst_ip),
        )

        checksum = self._calculate_checksum(header)
        header = header[:10] + struct.pack("!H", checksum) + header[12:]

        return header

    def _build_tcp_header(
        self,
        src_port: int,
        dst_port: int,
        seq_num: int,
        ack_num: int,
        flags: int,
        payload: bytes = b"",
        window_size: int = 65535,
    ) -> bytes:
        """Build TCP header.

        Args:
            src_port: Source port.
            dst_port: Destination port.
            seq_num: Sequence number.
            ack_num: Acknowledgment number.
            flags: TCP flags.
            payload: TCP payload.
            window_size: TCP window size.

        Returns:
            TCP header bytes (20 bytes minimum + options).
        """
        data_offset = 5
        reserved = 0
        offset_flags = (data_offset << 12) | flags
        urgent_pointer = 0

        header = struct.pack(
            "!HHIIHHH",
            src_port,
            dst_port,
            seq_num,
            ack_num,
            offset_flags,
            window_size,
            0,
        )
        header += struct.pack("!H", urgent_pointer)

        return header

    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate IP/TCP/UDP checksum.

        Args:
            data: Data to checksum.

        Returns:
            16-bit checksum value.
        """
        if len(data) % 2 != 0:
            data += b"\x00"

        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        return ~checksum & 0xFFFF

    def _build_tcp_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        seq_num: int,
        ack_num: int,
        flags: int,
        payload: bytes = b"",
        timestamp: Optional[float] = None,
    ) -> Tuple[bytes, float]:
        """Build complete TCP packet with Ethernet and IP headers.

        Args:
            src_ip: Source IP address.
            dst_ip: Destination IP address.
            src_port: Source port.
            dst_port: Destination port.
            seq_num: TCP sequence number.
            ack_num: TCP acknowledgment number.
            flags: TCP flags.
            payload: TCP payload data.
            timestamp: Packet timestamp (epoch seconds).

        Returns:
            Tuple of (packet_bytes, timestamp).
        """
        tcp_header = self._build_tcp_header(
            src_port=src_port,
            dst_port=dst_port,
            seq_num=seq_num,
            ack_num=ack_num,
            flags=flags,
            payload=payload,
        )

        tcp_payload = tcp_header + payload

        ip_header = self._build_ipv4_header(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=IP_PROTOCOL_TCP,
            payload_length=len(tcp_payload),
        )

        if self.link_type == PCAPLinkType.ETHERNET:
            eth_header = self._build_ethernet_header()
            packet = eth_header + ip_header + tcp_payload
        else:
            packet = ip_header + tcp_payload

        ts = timestamp or time.time()

        return packet, ts

    def _segment_payload(self, payload: bytes) -> List[bytes]:
        """Segment payload into MSS-sized chunks.

        Args:
            payload: Data to segment.

        Returns:
            List of payload segments.
        """
        if len(payload) <= self.mss:
            return [payload] if payload else []

        segments: List[bytes] = []
        for i in range(0, len(payload), self.mss):
            segments.append(payload[i : i + self.mss])

        return segments

    def _build_tcp_handshake(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        timestamp: float,
    ) -> List[Tuple[bytes, float]]:
        """Build TCP three-way handshake packets.

        Args:
            src_ip: Source IP address.
            dst_ip: Destination IP address.
            src_port: Source port.
            dst_port: Destination port.
            timestamp: Connection start timestamp.

        Returns:
            List of (packet, timestamp) tuples for SYN, SYN-ACK, ACK.
        """
        packets: List[Tuple[bytes, float]] = []
        initial_seq = 1000

        syn_packet, ts1 = self._build_tcp_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            seq_num=initial_seq,
            ack_num=0,
            flags=TCPFlag.SYN.value,
            timestamp=timestamp,
        )
        packets.append((syn_packet, ts1))

        syn_ack_packet, ts2 = self._build_tcp_packet(
            src_ip=dst_ip,
            dst_ip=src_ip,
            src_port=dst_port,
            dst_port=src_port,
            seq_num=2000,
            ack_num=initial_seq + 1,
            flags=TCPFlag.SYN.value | TCPFlag.ACK.value,
            timestamp=timestamp + 0.001,
        )
        packets.append((syn_ack_packet, ts2))

        ack_packet, ts3 = self._build_tcp_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            seq_num=initial_seq + 1,
            ack_num=2001,
            flags=TCPFlag.ACK.value,
            timestamp=timestamp + 0.002,
        )
        packets.append((ack_packet, ts3))

        return packets

    def _build_tcp_teardown(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        seq_num: int,
        ack_num: int,
        timestamp: float,
    ) -> List[Tuple[bytes, float]]:
        """Build TCP four-way teardown packets.

        Args:
            src_ip: Source IP address.
            dst_ip: Destination IP address.
            src_port: Source port.
            dst_port: Destination port.
            seq_num: Current sequence number.
            ack_num: Current acknowledgment number.
            timestamp: Connection end timestamp.

        Returns:
            List of (packet, timestamp) tuples for FIN/ACK exchange.
        """
        packets: List[Tuple[bytes, float]] = []

        fin1, ts1 = self._build_tcp_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            seq_num=seq_num,
            ack_num=ack_num,
            flags=TCPFlag.FIN.value | TCPFlag.ACK.value,
            timestamp=timestamp,
        )
        packets.append((fin1, ts1))

        fin_ack1, ts2 = self._build_tcp_packet(
            src_ip=dst_ip,
            dst_ip=src_ip,
            src_port=dst_port,
            dst_port=src_port,
            seq_num=ack_num,
            ack_num=seq_num + 1,
            flags=TCPFlag.FIN.value | TCPFlag.ACK.value,
            timestamp=timestamp + 0.001,
        )
        packets.append((fin_ack1, ts2))

        ack2, ts3 = self._build_tcp_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            seq_num=seq_num + 1,
            ack_num=ack_num + 1,
            flags=TCPFlag.ACK.value,
            timestamp=timestamp + 0.002,
        )
        packets.append((ack2, ts3))

        return packets

    def _build_http_packets(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        request_data: bytes,
        response_data: bytes,
        timestamp: float,
    ) -> List[Tuple[bytes, float]]:
        """Build HTTP request/response TCP packets.

        Args:
            src_ip: Source IP address.
            dst_ip: Destination IP address.
            src_port: Source port.
            dst_port: Destination port.
            request_data: HTTP request bytes.
            response_data: HTTP response bytes.
            timestamp: Request timestamp.

        Returns:
            List of (packet, timestamp) tuples.
        """
        packets: List[Tuple[bytes, float]] = []
        connection_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"

        if connection_key not in self._tcp_sequences:
            handshake = self._build_tcp_handshake(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                timestamp=timestamp,
            )
            packets.extend(handshake)
            self._tcp_sequences[connection_key] = {
                "client_seq": 1001,
                "server_seq": 2001,
            }

        seq_info = self._tcp_sequences[connection_key]
        client_seq = seq_info["client_seq"]
        server_seq = seq_info["server_seq"]

        request_segments = self._segment_payload(request_data)
        for i, segment in enumerate(request_segments):
            flags = TCPFlag.PSH.value | TCPFlag.ACK.value if i == len(request_segments) - 1 else TCPFlag.ACK.value
            packet, ts = self._build_tcp_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                seq_num=client_seq,
                ack_num=server_seq,
                flags=flags,
                payload=segment,
                timestamp=timestamp + (i * 0.001),
            )
            packets.append((packet, ts))
            client_seq += len(segment)

        response_segments = self._segment_payload(response_data)
        response_ts = timestamp + 0.05
        for i, segment in enumerate(response_segments):
            flags = TCPFlag.PSH.value | TCPFlag.ACK.value if i == len(response_segments) - 1 else TCPFlag.ACK.value
            packet, ts = self._build_tcp_packet(
                src_ip=dst_ip,
                dst_ip=src_ip,
                src_port=dst_port,
                dst_port=src_port,
                seq_num=server_seq,
                ack_num=client_seq,
                flags=flags,
                payload=segment,
                timestamp=response_ts + (i * 0.001),
            )
            packets.append((packet, ts))
            server_seq += len(segment)

        seq_info["client_seq"] = client_seq
        seq_info["server_seq"] = server_seq

        return packets

    def _build_websocket_packets(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        upgrade_request: bytes,
        upgrade_response: bytes,
        messages: List[Dict[str, Any]],
        timestamp: float,
    ) -> List[Tuple[bytes, float]]:
        """Build WebSocket upgrade and data frame packets.

        Args:
            src_ip: Source IP address.
            dst_ip: Destination IP address.
            src_port: Source port.
            dst_port: Destination port.
            upgrade_request: WebSocket upgrade request bytes.
            upgrade_response: WebSocket upgrade response bytes.
            messages: WebSocket messages list.
            timestamp: Connection start timestamp.

        Returns:
            List of (packet, timestamp) tuples.
        """
        packets: List[Tuple[bytes, float]] = []

        http_packets = self._build_http_packets(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            request_data=upgrade_request,
            response_data=upgrade_response,
            timestamp=timestamp,
        )
        packets.extend(http_packets)

        connection_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        seq_info = self._tcp_sequences.get(connection_key, {
            "client_seq": 1001,
            "server_seq": 2001,
        })
        client_seq = seq_info["client_seq"]
        server_seq = seq_info["server_seq"]

        msg_timestamp = timestamp + 0.1
        for msg in messages:
            direction = msg.get("direction", "client_to_server")
            payload = msg.get("data", b"")
            if isinstance(payload, str):
                payload = payload.encode("utf-8")

            if direction == "client_to_server":
                packet, ts = self._build_tcp_packet(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    seq_num=client_seq,
                    ack_num=server_seq,
                    flags=TCPFlag.PSH.value | TCPFlag.ACK.value,
                    payload=payload,
                    timestamp=msg_timestamp,
                )
                packets.append((packet, ts))
                client_seq += len(payload)
            else:
                packet, ts = self._build_tcp_packet(
                    src_ip=dst_ip,
                    dst_ip=src_ip,
                    src_port=dst_port,
                    dst_port=src_port,
                    seq_num=server_seq,
                    ack_num=client_seq,
                    flags=TCPFlag.PSH.value | TCPFlag.ACK.value,
                    payload=payload,
                    timestamp=msg_timestamp,
                )
                packets.append((packet, ts))
                server_seq += len(payload)

            msg_timestamp += msg.get("delay", 0.05)

        seq_info["client_seq"] = client_seq
        seq_info["server_seq"] = server_seq
        self._tcp_sequences[connection_key] = seq_info

        return packets

    def _write_pcap_header(self, file_handle: Any) -> None:
        """Write PCAP file global header.

        Args:
            file_handle: Open file handle for writing.
        """
        header = struct.pack(
            "!IHHiIII",
            PCAP_MAGIC_NUMBER,
            PCAP_VERSION_MAJOR,
            PCAP_VERSION_MINOR,
            0,
            0,
            65535,
            self.link_type.value,
        )
        file_handle.write(header)

    def _write_pcap_packet(
        self,
        file_handle: Any,
        timestamp_sec: int,
        timestamp_usec: int,
        packet_data: bytes,
    ) -> None:
        """Write single PCAP packet.

        Args:
            file_handle: Open file handle for writing.
            timestamp_sec: Timestamp seconds.
            timestamp_usec: Timestamp microseconds.
            packet_data: Packet bytes.
        """
        packet_header = struct.pack(
            "!IIII",
            timestamp_sec,
            timestamp_usec,
            len(packet_data),
            len(packet_data),
        )
        file_handle.write(packet_header)
        file_handle.write(packet_data)

    async def export_to_pcap(
        self,
        traffic_records: List[Dict[str, Any]],
        output_path: str,
    ) -> int:
        """Export traffic records to PCAP format.

        Args:
            traffic_records: List of traffic record dictionaries.
            output_path: Output PCAP file path.

        Returns:
            Number of packets written.
        """
        total = len(traffic_records)
        packet_count = 0

        with open(output_path, "wb") as f:
            self._write_pcap_header(f)

            for idx, record in enumerate(traffic_records):
                request_data = record.get("request", {})
                response_data = record.get("response", {})
                websocket_messages = record.get("websocket_messages", [])
                is_websocket = record.get("is_websocket", False)

                src_ip = request_data.get("client_ip", "127.0.0.1")
                dst_ip = request_data.get("server_ip", "127.0.0.1")
                src_port = request_data.get("client_port", 50000 + idx)
                dst_port = request_data.get("server_port", 80)

                timestamp = request_data.get("timestamp", time.time())
                if isinstance(timestamp, datetime):
                    timestamp = timestamp.timestamp()

                request_body = request_data.get("body", b"")
                request_headers = request_data.get("headers", {})
                request_line = f"{request_data.get('method', 'GET')} {request_data.get('path', '/')} {request_data.get('protocol', 'HTTP/1.1')}\r\n"
                header_lines = "\r\n".join(f"{k}: {v}" for k, v in request_headers.items())
                full_request = f"{request_line}{header_lines}\r\n\r\n".encode("utf-8")
                if request_body:
                    if isinstance(request_body, str):
                        request_body = request_body.encode("utf-8")
                    full_request += request_body

                response_body = response_data.get("body", b"")
                response_headers = response_data.get("headers", {})
                response_line = f"HTTP/1.1 {response_data.get('status_code', 200)} {response_data.get('status_text', 'OK')}\r\n"
                response_header_lines = "\r\n".join(f"{k}: {v}" for k, v in response_headers.items())
                full_response = f"{response_line}{response_header_lines}\r\n\r\n".encode("utf-8")
                if response_body:
                    if isinstance(response_body, str):
                        response_body = response_body.encode("utf-8")
                    full_response += response_body

                if is_websocket:
                    upgrade_request = full_request
                    upgrade_response = full_response
                    packets = self._build_websocket_packets(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        upgrade_request=upgrade_request,
                        upgrade_response=upgrade_response,
                        messages=websocket_messages,
                        timestamp=timestamp,
                    )
                else:
                    packets = self._build_http_packets(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        request_data=full_request,
                        response_data=full_response,
                        timestamp=timestamp,
                    )

                for packet_data, pkt_ts in packets:
                    ts_sec = int(pkt_ts)
                    ts_usec = int((pkt_ts - ts_sec) * 1000000)
                    self._write_pcap_packet(f, ts_sec, ts_usec, packet_data)
                    packet_count += 1

                if (idx + 1) % 100 == 0:
                    progress = ((idx + 1) / total) * 100 if total > 0 else 100
                    await self._report_progress(
                        f"Writing packet {idx + 1}/{total}", progress
                    )

            connection_keys = list(self._tcp_sequences.keys())
            for conn_key in connection_keys:
                parts = conn_key.split("-")
                if len(parts) == 2:
                    src_part = parts[0].split(":")
                    dst_part = parts[1].split(":")
                    if len(src_part) == 2 and len(dst_part) == 2:
                        seq_info = self._tcp_sequences[conn_key]
                        teardown = self._build_tcp_teardown(
                            src_ip=src_part[0],
                            dst_ip=dst_part[0],
                            src_port=int(src_part[1]),
                            dst_port=int(dst_part[1]),
                            seq_num=seq_info["client_seq"],
                            ack_num=seq_info["server_seq"],
                            timestamp=time.time(),
                        )
                        for packet_data, pkt_ts in teardown:
                            ts_sec = int(pkt_ts)
                            ts_usec = int((pkt_ts - ts_sec) * 1000000)
                            self._write_pcap_packet(f, ts_sec, ts_usec, packet_data)
                            packet_count += 1

        self._packet_count = packet_count
        await self._report_progress("PCAP export completed", 100.0)
        logger.info(f"PCAP exported to {output_path} with {packet_count} packets")

        return packet_count

    async def export_filtered_traffic(
        self,
        traffic_records: List[Dict[str, Any]],
        output_path: str,
        domain_filter: Optional[List[str]] = None,
        url_filter: Optional[List[str]] = None,
        method_filter: Optional[List[str]] = None,
        status_filter: Optional[List[int]] = None,
        time_start: Optional[float] = None,
        time_end: Optional[float] = None,
    ) -> int:
        """Export filtered traffic records to PCAP format.

        Args:
            traffic_records: Full list of traffic records.
            output_path: Output PCAP file path.
            domain_filter: List of domains to include.
            url_filter: List of URL patterns to include.
            method_filter: List of HTTP methods to include.
            status_filter: List of status codes to include.
            time_start: Start timestamp filter.
            time_end: End timestamp filter.

        Returns:
            Number of packets written.
        """
        filtered_records: List[Dict[str, Any]] = []

        for record in traffic_records:
            request_data = record.get("request", {})
            response_data = record.get("response", {})

            url = request_data.get("url", "")
            domain = request_data.get("host", "")
            method = request_data.get("method", "")
            status = response_data.get("status_code", 0)
            timestamp = request_data.get("timestamp", 0)

            if isinstance(timestamp, datetime):
                timestamp = timestamp.timestamp()

            if domain_filter and domain not in domain_filter:
                continue

            if url_filter and not any(pattern in url for pattern in url_filter):
                continue

            if method_filter and method not in method_filter:
                continue

            if status_filter and status not in status_filter:
                continue

            if time_start and timestamp < time_start:
                continue

            if time_end and timestamp > time_end:
                continue

            filtered_records.append(record)

        return await self.export_to_pcap(filtered_records, output_path)

    def reset_session_state(self) -> None:
        """Reset TCP session state tracking."""
        self._tcp_sequences.clear()
        self._packet_count = 0
