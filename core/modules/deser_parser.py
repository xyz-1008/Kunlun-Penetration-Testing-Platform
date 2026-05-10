"""Java serialization data parser for deep analysis.

Provides:
- Pure Python Java serialization format parser
- Automatic traffic identification
- Serialization data comparison and diff analysis
"""

import asyncio
import base64
import gzip
import logging
import re
import secrets
import struct
import time
import zlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class TCType(Enum):
    """Java serialization TC_* type codes."""
    TC_NULL = 0x70
    TC_REFERENCE = 0x71
    TC_CLASSDESC = 0x72
    TC_OBJECT = 0x73
    TC_STRING = 0x74
    TC_ARRAY = 0x75
    TC_CLASS = 0x76
    TC_BLOCKDATA = 0x77
    TC_ENDBLOCKDATA = 0x78
    TC_RESET = 0x79
    TC_BLOCKDATALONG = 0x7A
    TC_EXCEPTION = 0x7B
    TC_LONGSTRING = 0x7C
    TC_PROXYCLASSDESC = 0x7D
    TC_ENUM = 0x7E


@dataclass
class SerializationNode:
    """Serialization tree node.

    Attributes:
        node_type: TC type code
        class_name: Class name if applicable
        field_name: Field name if applicable
        value: Field value
        children: Child nodes
        offset: Data offset
        length: Data length
    """
    node_type: int = 0
    class_name: str = ""
    field_name: str = ""
    value: Any = None
    children: List["SerializationNode"] = field(default_factory=list)
    offset: int = 0
    length: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "node_type": TCType(self.node_type).name if self.node_type else "UNKNOWN",
            "class_name": self.class_name,
            "field_name": self.field_name,
            "value": str(self.value) if self.value is not None else None,
            "children": [child.to_dict() for child in self.children],
            "offset": self.offset,
            "length": self.length,
        }


@dataclass
class ParseResult:
    """Serialization parse result.

    Attributes:
        parse_id: Unique parse identifier
        is_valid: Whether data is valid Java serialization
        magic_header: Magic header bytes
        version: Serialization version
        root_node: Root tree node
        class_names: Extracted class names
        field_values: Extracted field values
        total_nodes: Total node count
        parse_depth: Maximum tree depth
        error_message: Error message if failed
        duration_seconds: Parse duration
        timestamp: Parse timestamp
    """
    parse_id: str = ""
    is_valid: bool = False
    magic_header: bytes = b""
    version: int = 0
    root_node: Optional[SerializationNode] = None
    class_names: List[str] = field(default_factory=list)
    field_values: Dict[str, Any] = field(default_factory=dict)
    total_nodes: int = 0
    parse_depth: int = 0
    error_message: str = ""
    duration_seconds: float = 0.0
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "parse_id": self.parse_id,
            "is_valid": self.is_valid,
            "version": self.version,
            "class_names": self.class_names,
            "field_count": len(self.field_values),
            "total_nodes": self.total_nodes,
            "parse_depth": self.parse_depth,
            "error_message": self.error_message,
            "duration_seconds": self.duration_seconds,
        }


@dataclass
class DiffResult:
    """Serialization diff result.

    Attributes:
        diff_id: Unique diff identifier
        left_parse_id: Left parse ID
        right_parse_id: Right parse ID
        differences: List of differences
        added_nodes: Added nodes count
        removed_nodes: Removed nodes count
        modified_nodes: Modified nodes count
        identical: Whether data is identical
        diff_report: Detailed diff report
        duration_seconds: Diff duration
        timestamp: Diff timestamp
    """
    diff_id: str = ""
    left_parse_id: str = ""
    right_parse_id: str = ""
    differences: List[Dict[str, Any]] = field(default_factory=list)
    added_nodes: int = 0
    removed_nodes: int = 0
    modified_nodes: int = 0
    identical: bool = True
    diff_report: str = ""
    duration_seconds: float = 0.0
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "diff_id": self.diff_id,
            "left_parse_id": self.left_parse_id,
            "right_parse_id": self.right_parse_id,
            "added_nodes": self.added_nodes,
            "removed_nodes": self.removed_nodes,
            "modified_nodes": self.modified_nodes,
            "identical": self.identical,
            "difference_count": len(self.differences),
            "duration_seconds": self.duration_seconds,
        }


class DeserParser:
    """Java serialization data parser.

    Provides pure Python Java serialization format parsing,
    automatic traffic identification, and diff analysis.
    """

    JAVA_SERIALIZATION_MAGIC = b"\xac\xed\x00\x05"

    TC_NAMES: Dict[int, str] = {
        0x70: "TC_NULL",
        0x71: "TC_REFERENCE",
        0x72: "TC_CLASSDESC",
        0x73: "TC_OBJECT",
        0x74: "TC_STRING",
        0x75: "TC_ARRAY",
        0x76: "TC_CLASS",
        0x77: "TC_BLOCKDATA",
        0x78: "TC_ENDBLOCKDATA",
        0x79: "TC_RESET",
        0x7A: "TC_BLOCKDATALONG",
        0x7B: "TC_EXCEPTION",
        0x7C: "TC_LONGSTRING",
        0x7D: "TC_PROXYCLASSDESC",
        0x7E: "TC_ENUM",
    }

    PROTOCOL_SIGNATURES: Dict[str, bytes] = {
        "JRMP": b"\xac\xed",
        "T3": b"t3",
        "IIOP": b"\x49\x4f\x50",
        "AJP": b"\x12\x34",
        "Hessian": b"\x43",
    }

    def __init__(
        self,
        mitm_proxy: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize deserialization parser.

        Args:
            mitm_proxy: MITM proxy instance.
            event_bus: Event bus for broadcasting events.
        """
        self.mitm_proxy = mitm_proxy
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._parse_history: List[ParseResult] = []
        self._diff_history: List[DiffResult] = []

    def set_callbacks(
        self,
        progress_cb: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None,
        log_cb: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Set progress and log callbacks.

        Args:
            progress_cb: Callback for progress updates (message, percentage).
            log_cb: Callback for log messages.
        """
        self._progress_callback = progress_cb
        self._log_callback = log_cb

    async def _report_progress(self, message: str, percentage: float) -> None:
        """Report progress via callback.

        Args:
            message: Progress message.
            percentage: Progress percentage (0-100).
        """
        if self._progress_callback:
            await self._progress_callback(message, percentage)
        logger.info("Deser Parser Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("Deser Parser: %s", message)

    async def parse_serialization(
        self,
        data: bytes,
    ) -> ParseResult:
        """Parse Java serialization data.

        Args:
            data: Serialization data bytes.

        Returns:
            ParseResult.
        """
        start_time = time.time()
        result = ParseResult(
            parse_id=f"parse_{int(time.time())}_{secrets.token_hex(4)}",
            timestamp=time.time(),
        )

        try:
            await self._report_progress("解析序列化数据", 10)

            if not self._is_java_serialization(data):
                result.error_message = "无效的Java序列化数据"
                result.duration_seconds = time.time() - start_time
                return result

            result.is_valid = True
            result.magic_header = data[:4]
            result.version = struct.unpack(">H", data[2:4])[0]

            await self._report_progress("构建对象树", 30)

            root_node = await self._parse_stream(data, 4)
            result.root_node = root_node

            await self._report_progress("提取类名和字段", 70)

            result.class_names = self._extract_class_names(root_node)
            result.field_values = self._extract_field_values(root_node)
            result.total_nodes = self._count_nodes(root_node)
            result.parse_depth = self._calculate_depth(root_node)

            result.duration_seconds = time.time() - start_time
            await self._report_progress("完成", 100)

            self._parse_history.append(result)

        except Exception as e:
            result.error_message = str(e)
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"解析失败: {e}")
            logger.error("Serialization parsing failed: %s", e)

        return result

    def _is_java_serialization(self, data: bytes) -> bool:
        """Check if data is Java serialization.

        Args:
            data: Data bytes.

        Returns:
            True if valid Java serialization.
        """
        if len(data) < 4:
            return False
        return data[:4] == self.JAVA_SERIALIZATION_MAGIC

    async def _parse_stream(
        self,
        data: bytes,
        offset: int,
    ) -> SerializationNode:
        """Parse serialization stream.

        Args:
            data: Data bytes.
            offset: Start offset.

        Returns:
            Root SerializationNode.
        """
        root = SerializationNode(offset=offset)

        try:
            pos = offset
            while pos < len(data):
                tc = data[pos]
                node = await self._parse_tc(data, pos)
                if node:
                    root.children.append(node)
                    pos += node.length
                else:
                    break
        except Exception as e:
            logger.error("Stream parsing error at offset %d: %s", offset, e)

        return root

    async def _parse_tc(
        self,
        data: bytes,
        offset: int,
    ) -> Optional[SerializationNode]:
        """Parse TC_* element.

        Args:
            data: Data bytes.
            offset: Element offset.

        Returns:
            SerializationNode or None.
        """
        if offset >= len(data):
            return None

        tc = data[offset]
        node = SerializationNode(node_type=tc, offset=offset)

        try:
            if tc == TCType.TC_NULL.value:
                node.length = 1
            elif tc == TCType.TC_STRING.value:
                node.length, node.value = await self._parse_string(data, offset + 1)
            elif tc == TCType.TC_CLASSDESC.value:
                node.length, node.class_name = await self._parse_classdesc(data, offset + 1)
            elif tc == TCType.TC_OBJECT.value:
                node.length = await self._parse_object(data, offset + 1, node)
            elif tc == TCType.TC_BLOCKDATA.value:
                node.length, node.value = await self._parse_blockdata(data, offset + 1)
            elif tc == TCType.TC_ARRAY.value:
                node.length = await self._parse_array(data, offset + 1, node)
            else:
                node.length = 1

        except Exception as e:
            logger.error("TC parsing error at offset %d: %s", offset, e)
            node.length = 1

        return node

    async def _parse_string(
        self,
        data: bytes,
        offset: int,
    ) -> Tuple[int, str]:
        """Parse TC_STRING element.

        Args:
            data: Data bytes.
            offset: String offset.

        Returns:
            Tuple of (length, string value).
        """
        if offset + 2 > len(data):
            return 2, ""

        str_len = struct.unpack(">H", data[offset : offset + 2])[0]
        if offset + 2 + str_len > len(data):
            return offset + 2 - offset, ""

        value = data[offset + 2 : offset + 2 + str_len].decode("utf-8", errors="replace")
        return 2 + str_len, value

    async def _parse_classdesc(
        self,
        data: bytes,
        offset: int,
    ) -> Tuple[int, str]:
        """Parse TC_CLASSDESC element.

        Args:
            data: Data bytes.
            offset: Classdesc offset.

        Returns:
            Tuple of (length, class name).
        """
        if offset + 2 > len(data):
            return 2, ""

        str_len = struct.unpack(">H", data[offset : offset + 2])[0]
        if offset + 2 + str_len > len(data):
            return offset + 2 - offset, ""

        class_name = data[offset + 2 : offset + 2 + str_len].decode("utf-8", errors="replace")
        return 2 + str_len + 10, class_name

    async def _parse_object(
        self,
        data: bytes,
        offset: int,
        node: SerializationNode,
    ) -> int:
        """Parse TC_OBJECT element.

        Args:
            data: Data bytes.
            offset: Object offset.
            node: Parent node.

        Returns:
            Element length.
        """
        return 1

    async def _parse_blockdata(
        self,
        data: bytes,
        offset: int,
    ) -> Tuple[int, bytes]:
        """Parse TC_BLOCKDATA element.

        Args:
            data: Data bytes.
            offset: Blockdata offset.

        Returns:
            Tuple of (length, block data).
        """
        if offset >= len(data):
            return 1, b""

        block_len = data[offset]
        if offset + 1 + block_len > len(data):
            return 1, b""

        block_data = data[offset + 1 : offset + 1 + block_len]
        return 1 + block_len, block_data

    async def _parse_array(
        self,
        data: bytes,
        offset: int,
        node: SerializationNode,
    ) -> int:
        """Parse TC_ARRAY element.

        Args:
            data: Data bytes.
            offset: Array offset.
            node: Parent node.

        Returns:
            Element length.
        """
        return 1

    def _extract_class_names(self, node: Optional[SerializationNode]) -> List[str]:
        """Extract class names from parse tree.

        Args:
            node: Root node.

        Returns:
            List of class names.
        """
        names: List[str] = []
        if not node:
            return names

        if node.class_name:
            names.append(node.class_name)

        for child in node.children:
            names.extend(self._extract_class_names(child))

        return list(set(names))

    def _extract_field_values(self, node: Optional[SerializationNode]) -> Dict[str, Any]:
        """Extract field values from parse tree.

        Args:
            node: Root node.

        Returns:
            Dictionary of field values.
        """
        values: Dict[str, Any] = {}
        if not node:
            return values

        if node.field_name and node.value is not None:
            values[node.field_name] = node.value

        for child in node.children:
            values.update(self._extract_field_values(child))

        return values

    def _count_nodes(self, node: Optional[SerializationNode]) -> int:
        """Count total nodes in tree.

        Args:
            node: Root node.

        Returns:
            Node count.
        """
        if not node:
            return 0
        count = 1
        for child in node.children:
            count += self._count_nodes(child)
        return count

    def _calculate_depth(self, node: Optional[SerializationNode]) -> int:
        """Calculate maximum tree depth.

        Args:
            node: Root node.

        Returns:
            Maximum depth.
        """
        if not node or not node.children:
            return 1
        return 1 + max(self._calculate_depth(child) for child in node.children)

    async def identify_traffic(
        self,
        raw_traffic: bytes,
    ) -> Dict[str, Any]:
        """Identify serialization traffic in raw traffic.

        Args:
            raw_traffic: Raw traffic bytes.

        Returns:
            Traffic identification result.
        """
        result: Dict[str, Any] = {
            "is_serialization": False,
            "protocol": "unknown",
            "encoding": "raw",
            "decoded_data": b"",
        }

        try:
            await self._report_progress("识别流量", 10)

            if raw_traffic[:4] == self.JAVA_SERIALIZATION_MAGIC:
                result["is_serialization"] = True
                result["protocol"] = "JRMP"
                result["decoded_data"] = raw_traffic
                await self._report_log("检测到Java序列化数据 (JRMP)")
                return result

            for protocol, signature in self.PROTOCOL_SIGNATURES.items():
                if signature in raw_traffic:
                    result["is_serialization"] = True
                    result["protocol"] = protocol
                    await self._report_log(f"检测到{protocol}协议流量")
                    return result

            try:
                decoded = base64.b64decode(raw_traffic)
                if decoded[:4] == self.JAVA_SERIALIZATION_MAGIC:
                    result["is_serialization"] = True
                    result["encoding"] = "base64"
                    result["decoded_data"] = decoded
                    await self._report_log("检测到Base64编码的序列化数据")
                    return result
            except Exception:
                pass

            try:
                decoded = bytes.fromhex(raw_traffic.decode("utf-8", errors="replace"))
                if decoded[:4] == self.JAVA_SERIALIZATION_MAGIC:
                    result["is_serialization"] = True
                    result["encoding"] = "hex"
                    result["decoded_data"] = decoded
                    await self._report_log("检测到Hex编码的序列化数据")
                    return result
            except Exception:
                pass

            try:
                decompressed = gzip.decompress(raw_traffic)
                if decompressed[:4] == self.JAVA_SERIALIZATION_MAGIC:
                    result["is_serialization"] = True
                    result["encoding"] = "gzip"
                    result["decoded_data"] = decompressed
                    await self._report_log("检测到GZIP压缩的序列化数据")
                    return result
            except Exception:
                pass

            try:
                decompressed = zlib.decompress(raw_traffic)
                if decompressed[:4] == self.JAVA_SERIALIZATION_MAGIC:
                    result["is_serialization"] = True
                    result["encoding"] = "deflate"
                    result["decoded_data"] = decompressed
                    await self._report_log("检测到Deflate压缩的序列化数据")
                    return result
            except Exception:
                pass

            await self._report_log("未检测到序列化流量")

        except Exception as e:
            await self._report_log(f"流量识别失败: {e}")
            logger.error("Traffic identification failed: %s", e)

        return result

    async def compare_serializations(
        self,
        left_data: bytes,
        right_data: bytes,
    ) -> DiffResult:
        """Compare two serialization data sets.

        Args:
            left_data: Left serialization data.
            right_data: Right serialization data.

        Returns:
            DiffResult.
        """
        start_time = time.time()
        result = DiffResult(
            diff_id=f"diff_{int(time.time())}_{secrets.token_hex(4)}",
            timestamp=time.time(),
        )

        try:
            await self._report_progress("解析左侧数据", 20)
            left_parse = await self.parse_serialization(left_data)
            result.left_parse_id = left_parse.parse_id

            await self._report_progress("解析右侧数据", 40)
            right_parse = await self.parse_serialization(right_data)
            result.right_parse_id = right_parse.parse_id

            await self._report_progress("比对差异", 60)

            if left_parse.root_node and right_parse.root_node:
                result.differences = await self._diff_nodes(
                    left_parse.root_node,
                    right_parse.root_node,
                )

            result.added_nodes = sum(1 for d in result.differences if d.get("type") == "added")
            result.removed_nodes = sum(1 for d in result.differences if d.get("type") == "removed")
            result.modified_nodes = sum(1 for d in result.differences if d.get("type") == "modified")
            result.identical = len(result.differences) == 0

            result.diff_report = self._generate_diff_report(result)

            result.duration_seconds = time.time() - start_time
            await self._report_progress("完成", 100)

            self._diff_history.append(result)

        except Exception as e:
            result.diff_report = f"比对失败: {e}"
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"比对失败: {e}")
            logger.error("Serialization comparison failed: %s", e)

        return result

    async def _diff_nodes(
        self,
        left: SerializationNode,
        right: SerializationNode,
        path: str = "",
    ) -> List[Dict[str, Any]]:
        """Diff two serialization nodes.

        Args:
            left: Left node.
            right: Right node.
            path: Current path.

        Returns:
            List of differences.
        """
        differences: List[Dict[str, Any]] = []

        if left.class_name != right.class_name:
            differences.append({
                "type": "modified",
                "path": path or "root",
                "field": "class_name",
                "left_value": left.class_name,
                "right_value": right.class_name,
            })

        if left.value != right.value:
            differences.append({
                "type": "modified",
                "path": path or "root",
                "field": "value",
                "left_value": str(left.value) if left.value is not None else None,
                "right_value": str(right.value) if right.value is not None else None,
            })

        left_children = {c.field_name or str(c.offset): c for c in left.children}
        right_children = {c.field_name or str(c.offset): c for c in right.children}

        for key, left_child in left_children.items():
            if key not in right_children:
                differences.append({
                    "type": "removed",
                    "path": f"{path}/{key}" if path else key,
                    "node_type": TCType(left_child.node_type).name if left_child.node_type else "UNKNOWN",
                })
            else:
                child_diff = await self._diff_nodes(
                    left_child,
                    right_children[key],
                    f"{path}/{key}" if path else key,
                )
                differences.extend(child_diff)

        for key, right_child in right_children.items():
            if key not in left_children:
                differences.append({
                    "type": "added",
                    "path": f"{path}/{key}" if path else key,
                    "node_type": TCType(right_child.node_type).name if right_child.node_type else "UNKNOWN",
                })

        return differences

    def _generate_diff_report(self, diff_result: DiffResult) -> str:
        """Generate detailed diff report.

        Args:
            diff_result: Diff result.

        Returns:
            Detailed report string.
        """
        report_lines: List[str] = [
            f"序列化数据比对报告",
            f"===================",
            f"左侧ID: {diff_result.left_parse_id}",
            f"右侧ID: {diff_result.right_parse_id}",
            f"是否相同: {'是' if diff_result.identical else '否'}",
            f"新增节点: {diff_result.added_nodes}",
            f"删除节点: {diff_result.removed_nodes}",
            f"修改节点: {diff_result.modified_nodes}",
            f"",
            f"差异详情:",
            f"-----------",
        ]

        for diff in diff_result.differences:
            diff_type = diff.get("type", "unknown")
            path = diff.get("path", "")
            field = diff.get("field", "")

            if diff_type == "added":
                report_lines.append(f"  [+] 新增: {path}")
            elif diff_type == "removed":
                report_lines.append(f"  [-] 删除: {path}")
            elif diff_type == "modified":
                report_lines.append(f"  [~] 修改: {path}/{field}")
                report_lines.append(f"      左侧: {diff.get('left_value')}")
                report_lines.append(f"      右侧: {diff.get('right_value')}")

        return "\n".join(report_lines)

    def get_parse_history(self) -> List[ParseResult]:
        """Get parse history.

        Returns:
            List of parse results.
        """
        return self._parse_history

    def get_diff_history(self) -> List[DiffResult]:
        """Get diff history.

        Returns:
            List of diff results.
        """
        return self._diff_history
