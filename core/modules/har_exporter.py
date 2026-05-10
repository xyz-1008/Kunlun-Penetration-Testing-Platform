"""HAR 1.2 Exporter: HTTP Archive format export for captured traffic.

Provides:
- HAR 1.2 spec-compliant export with log/creator/entries/pages structure
- Timing calculation from proxy timing data
- WebSocket message serialization to _messages extension
- HTTP/2 and HTTP/3 normalization to HTTP/1.1 format
- Page aggregation based on Referer and URL path
- Base64 encoding for response bodies
- PostData parsing for form-urlencoded and multipart forms
- Body size threshold with truncation support
- Protocol metadata in _meta extension field
"""

import base64
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger(__name__)

HAR_VERSION = "1.2"
DEFAULT_BODY_SIZE_LIMIT = 10 * 1024 * 1024  # 10MB


@dataclass
class HARTiming:
    """HAR timing information in milliseconds.

    Attributes:
        blocked: Time spent in blocked state
        dns: DNS resolution time
        connect: TCP connection time
        ssl: SSL/TLS handshake time
        send: Request send time
        wait: Time waiting for first byte (TTFB)
        receive: Response receive time
    """
    blocked: float = -1.0
    dns: float = -1.0
    connect: float = -1.0
    ssl: float = -1.0
    send: float = -1.0
    wait: float = -1.0
    receive: float = -1.0

    def to_dict(self) -> Dict[str, float]:
        """Convert to HAR-compliant dictionary.

        Returns:
            Dictionary with timing values.
        """
        return {
            "blocked": self.blocked,
            "dns": self.dns,
            "connect": self.connect,
            "ssl": self.ssl,
            "send": self.send,
            "wait": self.wait,
            "receive": self.receive,
        }


@dataclass
class HARCookie:
    """HAR cookie representation.

    Attributes:
        name: Cookie name
        value: Cookie value
        path: Cookie path
        domain: Cookie domain
        expires: Cookie expiration time
        httpOnly: Whether cookie is HTTP-only
        secure: Whether cookie is secure
    """
    name: str = ""
    value: str = ""
    path: str = ""
    domain: str = ""
    expires: Optional[str] = None
    httpOnly: bool = False
    secure: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to HAR-compliant dictionary.

        Returns:
            Dictionary with cookie data.
        """
        result: Dict[str, Any] = {
            "name": self.name,
            "value": self.value,
        }
        if self.path:
            result["path"] = self.path
        if self.domain:
            result["domain"] = self.domain
        if self.expires:
            result["expires"] = self.expires
        result["httpOnly"] = self.httpOnly
        result["secure"] = self.secure
        return result


@dataclass
class HARHeader:
    """HAR header representation.

    Attributes:
        name: Header name
        value: Header value
    """
    name: str = ""
    value: str = ""

    def to_dict(self) -> Dict[str, str]:
        """Convert to HAR-compliant dictionary.

        Returns:
            Dictionary with header data.
        """
        return {
            "name": self.name,
            "value": self.value,
        }


@dataclass
class HARQueryStringParam:
    """HAR query string parameter.

    Attributes:
        name: Parameter name
        value: Parameter value
    """
    name: str = ""
    value: str = ""

    def to_dict(self) -> Dict[str, str]:
        """Convert to HAR-compliant dictionary.

        Returns:
            Dictionary with parameter data.
        """
        return {
            "name": self.name,
            "value": self.value,
        }


@dataclass
class HARPostDataParam:
    """HAR POST data parameter.

    Attributes:
        name: Parameter name
        value: Parameter value
        fileName: File name (for multipart)
        contentType: Content type (for multipart)
        comment: Additional comment
    """
    name: str = ""
    value: Optional[str] = None
    fileName: Optional[str] = None
    contentType: Optional[str] = None
    comment: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to HAR-compliant dictionary.

        Returns:
            Dictionary with POST parameter data.
        """
        result: Dict[str, Any] = {"name": self.name}
        if self.value is not None:
            result["value"] = self.value
        if self.fileName:
            result["fileName"] = self.fileName
        if self.contentType:
            result["contentType"] = self.contentType
        if self.comment:
            result["comment"] = self.comment
        return result


@dataclass
class HARPostData:
    """HAR POST data representation.

    Attributes:
        mimeType: MIME type of POST data
        params: POST parameters
        text: Raw POST text
        comment: Additional comment
    """
    mimeType: str = ""
    params: List[HARPostDataParam] = field(default_factory=list)
    text: Optional[str] = None
    comment: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to HAR-compliant dictionary.

        Returns:
            Dictionary with POST data.
        """
        result: Dict[str, Any] = {"mimeType": self.mimeType}
        if self.params:
            result["params"] = [p.to_dict() for p in self.params]
        if self.text is not None:
            result["text"] = self.text
        if self.comment:
            result["comment"] = self.comment
        return result


@dataclass
class HARRequest:
    """HAR request representation.

    Attributes:
        method: HTTP method
        url: Request URL
        httpVersion: HTTP version string
        cookies: Request cookies
        headers: Request headers
        queryString: Query string parameters
        postData: POST data (if applicable)
        headersSize: Total request header size in bytes
        bodySize: Request body size in bytes
    """
    method: str = "GET"
    url: str = ""
    httpVersion: str = "HTTP/1.1"
    cookies: List[HARCookie] = field(default_factory=list)
    headers: List[HARHeader] = field(default_factory=list)
    queryString: List[HARQueryStringParam] = field(default_factory=list)
    postData: Optional[HARPostData] = None
    headersSize: int = -1
    bodySize: int = -1

    def to_dict(self) -> Dict[str, Any]:
        """Convert to HAR-compliant dictionary.

        Returns:
            Dictionary with request data.
        """
        result: Dict[str, Any] = {
            "method": self.method,
            "url": self.url,
            "httpVersion": self.httpVersion,
        }
        if self.cookies:
            result["cookies"] = [c.to_dict() for c in self.cookies]
        if self.headers:
            result["headers"] = [h.to_dict() for h in self.headers]
        if self.queryString:
            result["queryString"] = [q.to_dict() for q in self.queryString]
        if self.postData:
            result["postData"] = self.postData.to_dict()
        result["headersSize"] = self.headersSize
        result["bodySize"] = self.bodySize
        return result


@dataclass
class HARContent:
    """HAR response content representation.

    Attributes:
        size: Response body size in bytes
        compression: Compression ratio
        mimeType: MIME type of content
        text: Response body text
        encoding: Encoding used (base64)
        comment: Additional comment
    """
    size: int = 0
    compression: int = -1
    mimeType: str = ""
    text: Optional[str] = None
    encoding: Optional[str] = None
    comment: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to HAR-compliant dictionary.

        Returns:
            Dictionary with content data.
        """
        result: Dict[str, Any] = {
            "size": self.size,
            "mimeType": self.mimeType,
        }
        if self.compression >= 0:
            result["compression"] = self.compression
        if self.text is not None:
            result["text"] = self.text
        if self.encoding:
            result["encoding"] = self.encoding
        if self.comment:
            result["comment"] = self.comment
        return result


@dataclass
class HARResponse:
    """HAR response representation.

    Attributes:
        status: HTTP status code
        statusText: HTTP status text
        httpVersion: HTTP version string
        cookies: Response cookies
        headers: Response headers
        content: Response content
        redirectURL: Redirect URL (if applicable)
        headersSize: Total response header size in bytes
        bodySize: Response body size in bytes
    """
    status: int = 200
    statusText: str = "OK"
    httpVersion: str = "HTTP/1.1"
    cookies: List[HARCookie] = field(default_factory=list)
    headers: List[HARHeader] = field(default_factory=list)
    content: HARContent = field(default_factory=HARContent)
    redirectURL: str = ""
    headersSize: int = -1
    bodySize: int = -1

    def to_dict(self) -> Dict[str, Any]:
        """Convert to HAR-compliant dictionary.

        Returns:
            Dictionary with response data.
        """
        result: Dict[str, Any] = {
            "status": self.status,
            "statusText": self.statusText,
            "httpVersion": self.httpVersion,
        }
        if self.cookies:
            result["cookies"] = [c.to_dict() for c in self.cookies]
        if self.headers:
            result["headers"] = [h.to_dict() for h in self.headers]
        result["content"] = self.content.to_dict()
        if self.redirectURL:
            result["redirectURL"] = self.redirectURL
        result["headersSize"] = self.headersSize
        result["bodySize"] = self.bodySize
        return result


@dataclass
class HAREntry:
    """HAR entry representation (single request/response pair).

    Attributes:
        pageref: Reference to parent page
        startedDateTime: Request start time (ISO 8601)
        time: Total request time in milliseconds
        request: Request data
        response: Response data
        cache: Cache information
        timings: Timing information
        serverIPAddress: Server IP address
        connection: Connection identifier
        _meta: Extension metadata (protocol, TLS info, etc.)
        _messages: WebSocket messages (extension)
    """
    pageref: str = ""
    startedDateTime: str = ""
    time: float = 0.0
    request: HARRequest = field(default_factory=HARRequest)
    response: HARResponse = field(default_factory=HARResponse)
    cache: Dict[str, Any] = field(default_factory=dict)
    timings: HARTiming = field(default_factory=HARTiming)
    serverIPAddress: str = ""
    connection: str = ""
    _meta: Dict[str, Any] = field(default_factory=dict)
    _messages: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to HAR-compliant dictionary.

        Returns:
            Dictionary with entry data.
        """
        result: Dict[str, Any] = {
            "startedDateTime": self.startedDateTime,
            "time": self.time,
            "request": self.request.to_dict(),
            "response": self.response.to_dict(),
            "cache": self.cache,
            "timings": self.timings.to_dict(),
        }
        if self.pageref:
            result["pageref"] = self.pageref
        if self.serverIPAddress:
            result["serverIPAddress"] = self.serverIPAddress
        if self.connection:
            result["connection"] = self.connection
        if self._meta:
            result["_meta"] = self._meta
        if self._messages:
            result["_messages"] = self._messages
        return result


@dataclass
class HARPage:
    """HAR page representation.

    Attributes:
        id: Page identifier
        title: Page title
        startedDateTime: Page start time (ISO 8601)
        pageTimings: Page timing information
        comment: Additional comment
    """
    id: str = ""
    title: str = ""
    startedDateTime: str = ""
    pageTimings: Dict[str, float] = field(default_factory=dict)
    comment: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to HAR-compliant dictionary.

        Returns:
            Dictionary with page data.
        """
        result: Dict[str, Any] = {
            "id": self.id,
            "startedDateTime": self.startedDateTime,
            "pageTimings": self.pageTimings,
        }
        if self.title:
            result["title"] = self.title
        if self.comment:
            result["comment"] = self.comment
        return result


@dataclass
class HARLog:
    """HAR log representation (root structure).

    Attributes:
        version: HAR version string
        creator: Creator information
        browser: Browser information (optional)
        pages: Page list
        entries: Entry list
        comment: Additional comment
    """
    version: str = HAR_VERSION
    creator: Dict[str, str] = field(default_factory=dict)
    browser: Optional[Dict[str, str]] = None
    pages: List[HARPage] = field(default_factory=list)
    entries: List[HAREntry] = field(default_factory=list)
    comment: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to HAR-compliant dictionary.

        Returns:
            Dictionary with log data.
        """
        result: Dict[str, Any] = {
            "version": self.version,
            "creator": self.creator,
            "entries": [e.to_dict() for e in self.entries],
        }
        if self.browser:
            result["browser"] = self.browser
        if self.pages:
            result["pages"] = [p.to_dict() for p in self.pages]
        if self.comment:
            result["comment"] = self.comment
        return result


@dataclass
class HARExportConfig:
    """HAR export configuration.

    Attributes:
        include_websocket_messages: Whether to include WebSocket messages
        base64_encode_bodies: Whether to Base64 encode response bodies
        body_size_limit: Maximum body size before truncation
        include_private_ips: Whether to include private IP addresses
        include_meta: Whether to include _meta extension field
        normalize_http_version: Whether to normalize HTTP/2/3 to HTTP/1.1
    """
    include_websocket_messages: bool = True
    base64_encode_bodies: bool = True
    body_size_limit: int = DEFAULT_BODY_SIZE_LIMIT
    include_private_ips: bool = True
    include_meta: bool = True
    normalize_http_version: bool = True


class HARExporter:
    """HAR 1.2 format exporter for captured HTTP/HTTPS/WebSocket traffic.

    Converts proxy-captured traffic into HAR 1.2 format for browser DevTools
    compatibility, analysis, and replay.

    Attributes:
        config: Export configuration
        _progress_callback: Optional progress callback
    """

    def __init__(
        self,
        config: Optional[HARExportConfig] = None,
        progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Initialize HAR exporter.

        Args:
            config: Export configuration. Uses defaults if not provided.
            progress_callback: Async callback for progress reporting.
        """
        self.config = config or HARExportConfig()
        self._progress_callback = progress_callback

    async def _report_progress(self, message: str, percentage: float) -> None:
        """Report export progress.

        Args:
            message: Progress message.
            percentage: Progress percentage (0-100).
        """
        if self._progress_callback:
            await self._progress_callback(message, percentage)

    def _parse_cookies(
        self,
        cookie_string: str,
    ) -> List[HARCookie]:
        """Parse cookie string into HAR cookies.

        Args:
            cookie_string: Raw cookie header value.

        Returns:
            List of HARCookie objects.
        """
        cookies: List[HARCookie] = []
        if not cookie_string:
            return cookies

        for cookie_part in cookie_string.split(";"):
            cookie_part = cookie_part.strip()
            if "=" in cookie_part:
                name, value = cookie_part.split("=", 1)
                cookies.append(HARCookie(name=name.strip(), value=value.strip()))

        return cookies

    def _parse_set_cookies(
        self,
        set_cookie_headers: List[str],
    ) -> List[HARCookie]:
        """Parse Set-Cookie headers into HAR cookies.

        Args:
            set_cookie_headers: List of Set-Cookie header values.

        Returns:
            List of HARCookie objects with full attributes.
        """
        cookies: List[HARCookie] = []
        for header in set_cookie_headers:
            parts = header.split(";")
            if not parts:
                continue

            main_part = parts[0].strip()
            if "=" in main_part:
                name, value = main_part.split("=", 1)
                cookie = HARCookie(name=name.strip(), value=value.strip())

                for attr in parts[1:]:
                    attr = attr.strip().lower()
                    if attr.startswith("path="):
                        cookie.path = attr.split("=", 1)[1]
                    elif attr.startswith("domain="):
                        cookie.domain = attr.split("=", 1)[1]
                    elif attr.startswith("expires="):
                        cookie.expires = attr.split("=", 1)[1]
                    elif attr == "httponly":
                        cookie.httpOnly = True
                    elif attr == "secure":
                        cookie.secure = True

                cookies.append(cookie)

        return cookies

    def _parse_query_string(self, url: str) -> List[HARQueryStringParam]:
        """Parse query string from URL.

        Args:
            url: Full URL with query string.

        Returns:
            List of HARQueryStringParam objects.
        """
        params: List[HARQueryStringParam] = []
        parsed = urlparse(url)
        if parsed.query:
            parsed_params = parse_qs(parsed.query, keep_blank_values=True)
            for name, values in parsed_params.items():
                for value in values:
                    params.append(HARQueryStringParam(name=name, value=value))
        return params

    def _parse_post_data(
        self,
        body: bytes,
        content_type: str,
    ) -> Optional[HARPostData]:
        """Parse POST data based on content type.

        Args:
            body: Request body bytes.
            content_type: Content-Type header value.

        Returns:
            HARPostData object or None if not applicable.
        """
        if not body or not content_type:
            return None

        mime_type = content_type.split(";")[0].strip().lower()
        post_data = HARPostData(mimeType=mime_type)

        try:
            body_text = body.decode("utf-8", errors="replace")
        except Exception:
            post_data.text = base64.b64encode(body).decode("ascii")
            return post_data

        if mime_type == "application/x-www-form-urlencoded":
            parsed_params = parse_qs(body_text, keep_blank_values=True)
            for name, values in parsed_params.items():
                for value in values:
                    post_data.params.append(
                        HARPostDataParam(name=name, value=value)
                    )
        elif mime_type.startswith("multipart/form-data"):
            post_data.text = body_text
        else:
            post_data.text = body_text

        return post_data

    def _calculate_timings(
        self,
        proxy_timing: Dict[str, float],
    ) -> HARTiming:
        """Calculate HAR timings from proxy timing data.

        Args:
            proxy_timing: Dictionary with timing data from proxy.

        Returns:
            HARTiming object with calculated values.
        """
        timings = HARTiming()

        timings.dns = proxy_timing.get("dns", -1.0)
        timings.connect = proxy_timing.get("connect", -1.0)
        timings.ssl = proxy_timing.get("ssl", -1.0)
        timings.send = proxy_timing.get("send", -1.0)
        timings.wait = proxy_timing.get("wait", -1.0)
        timings.receive = proxy_timing.get("receive", -1.0)

        total = sum(
            v for v in [
                timings.dns, timings.connect, timings.ssl,
                timings.send, timings.wait, timings.receive,
            ]
            if v >= 0
        )
        if total <= 0 and "total" in proxy_timing:
            timings.wait = proxy_timing["total"]

        return timings

    def _encode_body(
        self,
        body: bytes,
        content_type: str,
    ) -> Tuple[Optional[str], Optional[str]]:
        """Encode response body for HAR.

        Args:
            body: Response body bytes.
            content_type: Content-Type header value.

        Returns:
            Tuple of (encoded_text, encoding).
        """
        if not body:
            return None, None

        if len(body) > self.config.body_size_limit:
            body = body[: self.config.body_size_limit]
            truncated_comment = f"Body truncated from original size"

        if self.config.base64_encode_bodies:
            try:
                text = body.decode("utf-8")
                return text, None
            except UnicodeDecodeError:
                return base64.b64encode(body).decode("ascii"), "base64"
        else:
            try:
                return body.decode("utf-8", errors="replace"), None
            except Exception:
                return base64.b64encode(body).decode("ascii"), "base64"

    def _normalize_http_version(self, version: str) -> str:
        """Normalize HTTP version for HAR compatibility.

        Args:
            version: Original HTTP version string.

        Returns:
            Normalized HTTP version string.
        """
        if not self.config.normalize_http_version:
            return version

        version_upper = version.upper()
        if version_upper in ("HTTP/2", "HTTP/2.0", "H2"):
            return "HTTP/2.0"
        elif version_upper in ("HTTP/3", "HTTP/3.0", "H3", "QUIC"):
            return "HTTP/3.0"
        elif version_upper in ("HTTP/1.0", "HTTP/1.1"):
            return version_upper
        else:
            return "HTTP/1.1"

    def _generate_page_id(self, url: str, referer: str) -> str:
        """Generate page ID based on URL and Referer.

        Args:
            url: Request URL.
            referer: Referer header value.

        Returns:
            Page identifier string.
        """
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if referer:
            referer_parsed = urlparse(referer)
            return f"page_{referer_parsed.netloc}{referer_parsed.path}"

        return f"page_{parsed.netloc}{parsed.path}"

    def _build_entry_from_proxy_data(
        self,
        request_data: Dict[str, Any],
        response_data: Dict[str, Any],
        timing_data: Optional[Dict[str, float]] = None,
        websocket_messages: Optional[List[Dict[str, Any]]] = None,
    ) -> HAREntry:
        """Build HAR entry from proxy request/response data.

        Args:
            request_data: Proxy request data dictionary.
            response_data: Proxy response data dictionary.
            timing_data: Optional timing data dictionary.
            websocket_messages: Optional WebSocket messages list.

        Returns:
            HAREntry object.
        """
        entry = HAREntry()

        req_method = request_data.get("method", "GET")
        req_url = request_data.get("url", "")
        req_headers = request_data.get("headers", {})
        req_body = request_data.get("body", b"")
        req_protocol = request_data.get("protocol", "HTTP/1.1")
        req_timestamp = request_data.get("timestamp")

        resp_status = response_data.get("status_code", 200)
        resp_status_text = response_data.get("status_text", "OK")
        resp_headers = response_data.get("headers", {})
        resp_body = response_data.get("body", b"")
        resp_protocol = response_data.get("protocol", req_protocol)
        resp_timestamp = response_data.get("timestamp")

        started_dt = req_timestamp
        if isinstance(started_dt, datetime):
            entry.startedDateTime = started_dt.isoformat()
        elif isinstance(started_dt, (int, float)):
            entry.startedDateTime = datetime.fromtimestamp(
                started_dt, tz=timezone.utc
            ).isoformat()
        else:
            entry.startedDateTime = datetime.now(tz=timezone.utc).isoformat()

        if isinstance(req_body, str):
            req_body = req_body.encode("utf-8", errors="replace")
        if isinstance(resp_body, str):
            resp_body = resp_body.encode("utf-8", errors="replace")

        req_content_type = req_headers.get("Content-Type", req_headers.get("content-type", ""))
        resp_content_type = resp_headers.get("Content-Type", resp_headers.get("content-type", ""))

        request_cookies = req_headers.get("Cookie", req_headers.get("cookie", ""))
        response_set_cookies = []
        for key, value in resp_headers.items():
            if key.lower() == "set-cookie":
                response_set_cookies.append(value)

        entry.request = HARRequest(
            method=req_method,
            url=req_url,
            httpVersion=self._normalize_http_version(req_protocol),
            cookies=self._parse_cookies(request_cookies),
            headers=[
                HARHeader(name=k, value=v) for k, v in req_headers.items()
            ],
            queryString=self._parse_query_string(req_url),
            postData=self._parse_post_data(req_body, req_content_type),
            headersSize=-1,
            bodySize=len(req_body) if req_body else -1,
        )

        encoded_text, encoding = self._encode_body(resp_body, resp_content_type)
        resp_body_size = len(resp_body) if resp_body else 0

        entry.response = HARResponse(
            status=resp_status,
            statusText=resp_status_text,
            httpVersion=self._normalize_http_version(resp_protocol),
            cookies=self._parse_set_cookies(response_set_cookies),
            headers=[
                HARHeader(name=k, value=v) for k, v in resp_headers.items()
            ],
            content=HARContent(
                size=resp_body_size,
                mimeType=resp_content_type.split(";")[0].strip() if resp_content_type else "",
                text=encoded_text,
                encoding=encoding,
            ),
            redirectURL=resp_headers.get("Location", resp_headers.get("location", "")),
            headersSize=-1,
            bodySize=resp_body_size,
        )

        timings = timing_data or {}
        entry.timings = self._calculate_timings(timings)

        total_time = sum(
            v for v in [
                entry.timings.dns, entry.timings.connect, entry.timings.ssl,
                entry.timings.send, entry.timings.wait, entry.timings.receive,
            ]
            if v >= 0
        )
        entry.time = total_time if total_time > 0 else timings.get("total", 0.0)

        entry.serverIPAddress = request_data.get("server_ip", response_data.get("server_ip", ""))
        entry.connection = request_data.get("connection_id", response_data.get("connection_id", ""))

        if self.config.include_meta:
            entry._meta = {
                "protocol": req_protocol,
                "tls_version": request_data.get("tls_version", ""),
                "ja3": request_data.get("ja3", ""),
                "ja3s": response_data.get("ja3s", ""),
                "alpn": request_data.get("alpn", ""),
            }

        if self.config.include_websocket_messages and websocket_messages:
            entry._messages = websocket_messages

        referer = req_headers.get("Referer", req_headers.get("referer", ""))
        entry.pageref = self._generate_page_id(req_url, referer)

        return entry

    def _build_pages(self, entries: List[HAREntry]) -> List[HARPage]:
        """Build HAR pages from entries.

        Args:
            entries: List of HAR entries.

        Returns:
            List of HARPage objects.
        """
        pages_map: Dict[str, HARPage] = {}

        for entry in entries:
            if not entry.pageref:
                continue

            if entry.pageref not in pages_map:
                pages_map[entry.pageref] = HARPage(
                    id=entry.pageref,
                    title=entry.pageref,
                    startedDateTime=entry.startedDateTime,
                    pageTimings={"onContentLoad": -1, "onLoad": -1},
                )
            else:
                page = pages_map[entry.pageref]
                if entry.startedDateTime < page.startedDateTime:
                    page.startedDateTime = entry.startedDateTime

        return list(pages_map.values())

    async def export_to_har(
        self,
        traffic_records: List[Dict[str, Any]],
        output_path: Optional[str] = None,
    ) -> str:
        """Export traffic records to HAR 1.2 format.

        Args:
            traffic_records: List of traffic record dictionaries.
                Each dict should have 'request', 'response', 'timing', and
                optionally 'websocket_messages' keys.
            output_path: Optional file path to write HAR JSON.

        Returns:
            HAR JSON string.
        """
        entries: List[HAREntry] = []
        total = len(traffic_records)

        for idx, record in enumerate(traffic_records):
            request_data = record.get("request", {})
            response_data = record.get("response", {})
            timing_data = record.get("timing")
            websocket_messages = record.get("websocket_messages")

            entry = self._build_entry_from_proxy_data(
                request_data=request_data,
                response_data=response_data,
                timing_data=timing_data,
                websocket_messages=websocket_messages,
            )
            entries.append(entry)

            if (idx + 1) % 100 == 0:
                progress = ((idx + 1) / total) * 100 if total > 0 else 100
                await self._report_progress(
                    f"Processing entry {idx + 1}/{total}", progress
                )

        pages = self._build_pages(entries)

        har_log = HARLog(
            version=HAR_VERSION,
            creator={
                "name": "Kunlun Penetration Testing Platform",
                "version": "1.0",
                "comment": "Generated by Kunlun HAR Exporter",
            },
            pages=pages,
            entries=entries,
        )

        har_dict = {
            "log": har_log.to_dict(),
        }

        har_json_str = json.dumps(har_dict, indent=2, ensure_ascii=False)

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(har_json_str)
            logger.info(f"HAR exported to {output_path}")

        await self._report_progress("HAR export completed", 100.0)

        return har_json_str

    async def export_selected_traffic(
        self,
        traffic_records: List[Dict[str, Any]],
        selected_indices: List[int],
        output_path: Optional[str] = None,
    ) -> str:
        """Export selected traffic records to HAR format.

        Args:
            traffic_records: Full list of traffic records.
            selected_indices: Indices of records to export.
            output_path: Optional file path to write HAR JSON.

        Returns:
            HAR JSON string.
        """
        selected_records = [
            traffic_records[i]
            for i in selected_indices
            if 0 <= i < len(traffic_records)
        ]
        return await self.export_to_har(selected_records, output_path)
