"""GraphQL endpoint and request detection module.

Provides:
- Automatic GraphQL endpoint discovery with custom path dictionary
- Request structure analysis for GraphQL query detection
- GET and POST GraphQL query parsing and extraction
- Content-Type based identification (application/graphql)
"""

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger(__name__)


class GraphQLMethod(Enum):
    """GraphQL operation methods."""
    QUERY = "query"
    MUTATION = "mutation"
    SUBSCRIPTION = "subscription"


class DetectionSource(Enum):
    """Detection source types."""
    PATH = "path"
    CONTENT_TYPE = "content_type"
    BODY_KEYWORDS = "body_keywords"
    GET_PARAM = "get_param"
    CUSTOM = "custom"


@dataclass
class GraphQLEndpoint:
    """Discovered GraphQL endpoint.

    Attributes:
        url: Full endpoint URL
        path: URL path
        method: HTTP method (GET/POST)
        detection_source: How endpoint was detected
        is_introspection_enabled: Whether introspection is enabled
        schema_version: Detected GraphQL version
        last_tested: Last test timestamp
        response_time_ms: Average response time
        is_active: Whether endpoint is active
        tags: Endpoint tags
    """
    url: str = ""
    path: str = ""
    method: str = "POST"
    detection_source: DetectionSource = DetectionSource.PATH
    is_introspection_enabled: bool = False
    schema_version: str = ""
    last_tested: float = 0.0
    response_time_ms: float = 0.0
    is_active: bool = True
    tags: List[str] = field(default_factory=list)


@dataclass
class GraphQLRequest:
    """Parsed GraphQL request.

    Attributes:
        request_id: Unique request ID
        timestamp: Request timestamp
        url: Request URL
        method: HTTP method
        operation_type: GraphQL operation type
        operation_name: Operation name
        query: Raw query string
        variables: Query variables
        extensions: Request extensions
        content_type: Content type
        headers: Request headers
        body_raw: Raw request body
        is_batch: Whether batch request
        batch_count: Number of operations in batch
    """
    request_id: str = ""
    timestamp: float = 0.0
    url: str = ""
    method: str = "POST"
    operation_type: GraphQLMethod = GraphQLMethod.QUERY
    operation_name: str = ""
    query: str = ""
    variables: Dict[str, Any] = field(default_factory=dict)
    extensions: Dict[str, Any] = field(default_factory=dict)
    content_type: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body_raw: bytes = b""
    is_batch: bool = False
    batch_count: int = 0


@dataclass
class DetectionResult:
    """GraphQL detection result.

    Attributes:
        is_graphql: Whether GraphQL detected
        confidence: Detection confidence (0-1)
        endpoints: Discovered endpoints
        requests: Detected GraphQL requests
        detection_sources: Sources of detection
        details: Detection details
    """
    is_graphql: bool = False
    confidence: float = 0.0
    endpoints: List[GraphQLEndpoint] = field(default_factory=list)
    requests: List[GraphQLRequest] = field(default_factory=list)
    detection_sources: List[DetectionSource] = field(default_factory=list)
    details: str = ""


class GraphQLDetector:
    """GraphQL endpoint and request detector.

    Provides automatic GraphQL endpoint discovery, request identification,
    and query parsing from HTTP traffic.
    """

    COMMON_PATHS: List[str] = [
        "/graphql",
        "/gql",
        "/api/graphql",
        "/api/gql",
        "/graphql/console",
        "/graphiql",
        "/playground",
        "/v1/graphql",
        "/v2/graphql",
        "/v1/gql",
        "/v2/gql",
        "/query",
        "/api/query",
        "/graphql/v1",
        "/graphql/v2",
        "/graphql/explorer",
        "/graphql/console",
        "/graphql-subscriptions",
        "/subscriptions",
        "/altair",
        "/graphql-playground",
    ]

    GRAPHQL_CONTENT_TYPES: Set[str] = {
        "application/graphql",
        "application/graphql+json",
        "application/graphql-response+json",
    }

    GRAPHQL_KEYWORDS: Set[str] = {
        "query",
        "mutation",
        "subscription",
        "__schema",
        "__type",
        "__typename",
    }

    OPERATION_PATTERN: re.Pattern[str] = re.compile(
        r"(query|mutation|subscription)\s+(\w+)?\s*\(",
        re.IGNORECASE,
    )

    FIELD_PATTERN: re.Pattern[str] = re.compile(
        r"\{\s*([\w]+)",
        re.IGNORECASE,
    )

    def __init__(
        self,
        custom_paths: Optional[List[str]] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize GraphQL detector.

        Args:
            custom_paths: Custom endpoint paths to check.
            event_bus: Event bus for broadcasting events.
        """
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._custom_paths = custom_paths or []
        self._discovered_endpoints: List[GraphQLEndpoint] = []
        self._detected_requests: List[GraphQLRequest] = []
        self._all_paths = self.COMMON_PATHS + self._custom_paths

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
        logger.info("GraphQL Detection Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("GraphQL Detection: %s", message)

    def is_graphql_content_type(self, content_type: str) -> bool:
        """Check if content type indicates GraphQL.

        Args:
            content_type: HTTP content type.

        Returns:
            True if GraphQL content type.
        """
        ct_lower = content_type.lower().split(";")[0].strip()
        return ct_lower in self.GRAPHQL_CONTENT_TYPES

    def has_graphql_keywords(self, body: str) -> bool:
        """Check if body contains GraphQL keywords.

        Args:
            body: Request body string.

        Returns:
            True if GraphQL keywords found.
        """
        body_lower = body.lower()

        for keyword in self.GRAPHQL_KEYWORDS:
            if f'"{keyword}"' in body_lower or f"'{keyword}'" in body_lower:
                return True

            if f'"query"' in body_lower or '"mutation"' in body_lower:
                return True

        return False

    def extract_graphql_from_get(self, url: str) -> Optional[str]:
        """Extract GraphQL query from GET request URL.

        Args:
            url: Request URL.

        Returns:
            GraphQL query string or None.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for key in ("query", "graphql", "q"):
            if key in params and params[key]:
                return params[key][0]

        return None

    def extract_graphql_from_post(self, body: bytes) -> Optional[Dict[str, Any]]:
        """Extract GraphQL data from POST request body.

        Args:
            body: Request body bytes.

        Returns:
            Dictionary with query/variables/extensions or None.
        """
        try:
            body_str = body.decode("utf-8")
        except UnicodeDecodeError:
            return None

        try:
            data = json.loads(body_str)

            if isinstance(data, list):
                if data and "query" in data[0]:
                    return {
                        "is_batch": True,
                        "batch": data,
                        "query": data[0].get("query", ""),
                        "variables": data[0].get("variables", {}),
                        "extensions": data[0].get("extensions", {}),
                    }

            if isinstance(data, dict) and "query" in data:
                return {
                    "is_batch": False,
                    "query": data.get("query", ""),
                    "variables": data.get("variables", {}),
                    "extensions": data.get("extensions", {}),
                }

        except (json.JSONDecodeError, ValueError):
            if "query" in body_str.lower() or "mutation" in body_str.lower():
                return {
                    "is_batch": False,
                    "query": body_str,
                    "variables": {},
                    "extensions": {},
                }

        return None

    def detect_operation_type(self, query: str) -> GraphQLMethod:
        """Detect GraphQL operation type from query.

        Args:
            query: GraphQL query string.

        Returns:
            Detected GraphQLMethod.
        """
        query_stripped = query.strip()

        if query_stripped.startswith("mutation"):
            return GraphQLMethod.MUTATION
        elif query_stripped.startswith("subscription"):
            return GraphQLMethod.SUBSCRIPTION
        elif query_stripped.startswith("query"):
            return GraphQLMethod.QUERY

        match = self.OPERATION_PATTERN.search(query_stripped)
        if match:
            op_type = match.group(1).lower()
            if op_type == "mutation":
                return GraphQLMethod.MUTATION
            elif op_type == "subscription":
                return GraphQLMethod.SUBSCRIPTION

        if any(kw in query_stripped.lower() for kw in ("mutation", "update", "create", "delete")):
            return GraphQLMethod.MUTATION

        return GraphQLMethod.QUERY

    def extract_operation_name(self, query: str) -> str:
        """Extract operation name from query.

        Args:
            query: GraphQL query string.

        Returns:
            Operation name or empty string.
        """
        match = self.OPERATION_PATTERN.search(query)
        if match and match.group(2):
            return match.group(2)
        return ""

    async def parse_graphql_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: bytes,
    ) -> Optional[GraphQLRequest]:
        """Parse complete GraphQL request from HTTP request.

        Args:
            method: HTTP method.
            url: Request URL.
            headers: HTTP headers.
            body: Request body bytes.

        Returns:
            GraphQLRequest or None.
        """
        content_type = headers.get("content-type", "")
        query_str = ""
        variables: Dict[str, Any] = {}
        extensions: Dict[str, Any] = {}
        is_batch = False
        batch_count = 0

        if method.upper() == "GET":
            extracted_get = self.extract_graphql_from_get(url)
            if extracted_get:
                query_str = extracted_get
            else:
                return None
        elif method.upper() == "POST":
            extracted_post = self.extract_graphql_from_post(body)
            if extracted_post:
                query_str = extracted_post.get("query", "")
                variables = extracted_post.get("variables", {})
                extensions = extracted_post.get("extensions", {})
                is_batch = extracted_post.get("is_batch", False)
                batch = extracted_post.get("batch", [])
                batch_count = len(batch) if batch else 1
            else:
                return None
        else:
            return None

        if not query_str:
            return None

        operation_type = self.detect_operation_type(query_str)
        operation_name = self.extract_operation_name(query_str)

        parsed = urlparse(url)
        path = parsed.path

        request = GraphQLRequest(
            request_id=f"gql_req_{int(time.time())}_{id(body)}",
            timestamp=time.time(),
            url=url,
            method=method.upper(),
            operation_type=operation_type,
            operation_name=operation_name,
            query=query_str,
            variables=variables,
            extensions=extensions,
            content_type=content_type,
            headers=headers.copy(),
            body_raw=body,
            is_batch=is_batch,
            batch_count=batch_count,
        )

        self._detected_requests.append(request)

        await self._report_log(
            f"GraphQL请求已解析: {operation_type.value} {operation_name or '(匿名)'} "
            f"({path})"
        )

        return request

    async def detect_endpoint(
        self,
        base_url: str,
        path: str,
        timeout: int = 10,
    ) -> Optional[GraphQLEndpoint]:
        """Detect if path is a GraphQL endpoint.

        Args:
            base_url: Base URL to test.
            path: Path to test.
            timeout: Request timeout.

        Returns:
            GraphQLEndpoint or None.
        """
        url = f"{base_url.rstrip('/')}{path}"

        introspection_query = """
        query {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
            }
        }
        """

        await self._report_progress(f"检测端点: {path}", 50)

        start_time = time.time()

        is_graphql = False
        is_introspection = False

        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json={"query": introspection_query},
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as response:
                    response_time = (time.time() - start_time) * 1000

                    try:
                        data = await response.json()
                        if "data" in data and "__schema" in data.get("data", {}):
                            is_graphql = True
                            is_introspection = True
                        elif "errors" in data:
                            errors = data.get("errors", [])
                            for error in errors:
                                message = error.get("message", "").lower()
                                if "introspection" in message or "disabled" in message:
                                    is_graphql = True
                                    is_introspection = False
                                    break
                    except Exception:
                        pass

        except ImportError:
            is_graphql = True
            response_time = 0.0
        except Exception:
            response_time = (time.time() - start_time) * 1000

        if is_graphql:
            endpoint = GraphQLEndpoint(
                url=url,
                path=path,
                method="POST",
                detection_source=DetectionSource.PATH,
                is_introspection_enabled=is_introspection,
                last_tested=time.time(),
                response_time_ms=response_time,
                tags=["graphql", "auto-detected"],
            )

            self._discovered_endpoints.append(endpoint)

            await self._report_log(
                f"GraphQL端点已发现: {path} "
                f"(内省: {'启用' if is_introspection else '禁用'})"
            )

            return endpoint

        return None

    async def scan_for_endpoints(
        self,
        base_url: str,
        paths: Optional[List[str]] = None,
        concurrency: int = 10,
    ) -> List[GraphQLEndpoint]:
        """Scan for GraphQL endpoints.

        Args:
            base_url: Base URL to scan.
            paths: Paths to test (uses default if None).
            concurrency: Maximum concurrent requests.

        Returns:
            List of discovered GraphQLEndpoint.
        """
        test_paths = paths or self._all_paths
        discovered: List[GraphQLEndpoint] = []

        semaphore = asyncio.Semaphore(concurrency)

        async def test_path(path: str) -> Optional[GraphQLEndpoint]:
            async with semaphore:
                return await self.detect_endpoint(base_url, path)

        tasks = [test_path(path) for path in test_paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, GraphQLEndpoint):
                discovered.append(result)
            elif isinstance(result, Exception):
                logger.error("Endpoint detection error: %s", result)

        await self._report_progress(
            f"扫描完成，发现 {len(discovered)} 个GraphQL端点",
            100,
        )

        return discovered

    def get_discovered_endpoints(self) -> List[GraphQLEndpoint]:
        """Get all discovered endpoints.

        Returns:
            List of GraphQLEndpoint.
        """
        return self._discovered_endpoints.copy()

    def get_detected_requests(
        self,
        limit: int = 100,
        operation_filter: Optional[GraphQLMethod] = None,
    ) -> List[GraphQLRequest]:
        """Get detected GraphQL requests.

        Args:
            limit: Maximum records.
            operation_filter: Filter by operation type.

        Returns:
            List of GraphQLRequest.
        """
        requests = self._detected_requests

        if operation_filter:
            requests = [r for r in requests if r.operation_type == operation_filter]

        return requests[-limit:]

    def add_custom_paths(self, paths: List[str]) -> None:
        """Add custom endpoint paths.

        Args:
            paths: Paths to add.
        """
        for path in paths:
            if path not in self._all_paths:
                self._all_paths.append(path)
                self._custom_paths.append(path)

    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics.

        Returns:
            Statistics dictionary.
        """
        return {
            "total_endpoints": len(self._discovered_endpoints),
            "introspection_enabled": sum(
                1 for e in self._discovered_endpoints
                if e.is_introspection_enabled
            ),
            "total_requests": len(self._detected_requests),
            "queries": sum(
                1 for r in self._detected_requests
                if r.operation_type == GraphQLMethod.QUERY
            ),
            "mutations": sum(
                1 for r in self._detected_requests
                if r.operation_type == GraphQLMethod.MUTATION
            ),
            "subscriptions": sum(
                1 for r in self._detected_requests
                if r.operation_type == GraphQLMethod.SUBSCRIPTION
            ),
            "batch_requests": sum(
                1 for r in self._detected_requests if r.is_batch
            ),
        }
