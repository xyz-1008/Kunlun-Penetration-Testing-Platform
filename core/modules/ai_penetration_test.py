"""AI Penetration Test: Intelligent asset analysis, payload generation, passive scan enhancement, and vulnerability verification.

Provides:
- Smart asset analysis: AI automatically analyzes target assets and recommends testing approaches
- AI-driven payload generation: Natural language to targeted payloads based on parameter types
- WAF bypass payload generation with variant creation
- Passive scan enhancement: AI as second-layer analysis engine for logical vulnerability discovery
- Smart vulnerability verification: PoC result analysis and exploitation step generation
- Best exploitation chain recommendation
"""

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

from .ai_engine import AIEngine, AIResponse, ChatMessage, ModelCapability, PromptTemplate

logger = logging.getLogger(__name__)


class AnalysisType(Enum):
    """AI analysis types."""
    ASSET_ANALYSIS = "asset_analysis"
    PAYLOAD_GENERATION = "payload_generation"
    WAF_BYPASS = "waf_bypass"
    PASSIVE_SCAN = "passive_scan"
    VULNERABILITY_VERIFICATION = "vulnerability_verification"
    JS_ENDPOINT_ANALYSIS = "js_endpoint_analysis"
    IDOR_TESTING = "idor_testing"


class ConfidenceLevel(Enum):
    """Vulnerability confidence levels."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class AssetAnalysisResult:
    """Asset analysis result from AI.

    Attributes:
        asset_id: Asset identifier
        technology_stack: Identified technology stack
        known_vulnerabilities: Known vulnerabilities for identified technologies
        recommended_tests: Recommended testing approaches
        potential_attack_vectors: Potential attack vectors
        risk_assessment: Risk assessment summary
        confidence: Analysis confidence level
        timestamp: Analysis timestamp
    """
    asset_id: str = ""
    technology_stack: List[str] = field(default_factory=list)
    known_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    recommended_tests: List[str] = field(default_factory=list)
    potential_attack_vectors: List[str] = field(default_factory=list)
    risk_assessment: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    timestamp: float = 0.0


@dataclass
class PayloadGenerationResult:
    """Payload generation result from AI.

    Attributes:
        payloads: Generated payloads
        explanations: Payload explanations
        target_vulnerability: Target vulnerability type
        success_probability: Estimated success probability
        risk_level: Payload risk level
        timestamp: Generation timestamp
    """
    payloads: List[str] = field(default_factory=list)
    explanations: List[str] = field(default_factory=list)
    target_vulnerability: str = ""
    success_probability: float = 0.0
    risk_level: str = "medium"
    timestamp: float = 0.0


@dataclass
class PassiveScanAnalysisResult:
    """Passive scan analysis result from AI.

    Attributes:
        findings: AI-analyzed findings
        false_positives: Identified false positives
        high_value_findings: High-value findings requiring manual verification
        logical_vulnerabilities: Logical vulnerabilities not covered by rules
        prioritized_recommendations: Prioritized testing recommendations
        timestamp: Analysis timestamp
    """
    findings: List[Dict[str, Any]] = field(default_factory=list)
    false_positives: List[str] = field(default_factory=list)
    high_value_findings: List[Dict[str, Any]] = field(default_factory=list)
    logical_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    prioritized_recommendations: List[str] = field(default_factory=list)
    timestamp: float = 0.0


@dataclass
class VulnerabilityVerificationResult:
    """Vulnerability verification result from AI.

    Attributes:
        is_confirmed: Whether vulnerability is confirmed
        confidence: Verification confidence level
        evidence: Evidence supporting the conclusion
        cvss_estimate: Estimated CVSS score
        next_steps: Recommended next steps
        exploitation_chain: Recommended exploitation chain
        timestamp: Verification timestamp
    """
    is_confirmed: bool = False
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    evidence: List[str] = field(default_factory=list)
    cvss_estimate: float = 0.0
    next_steps: List[str] = field(default_factory=list)
    exploitation_chain: List[str] = field(default_factory=list)
    timestamp: float = 0.0


@dataclass
class JSEndpointAnalysisResult:
    """JavaScript endpoint analysis result.

    Attributes:
        endpoints: Extracted API endpoints
        auth_mechanisms: Identified authentication mechanisms
        dangerous_endpoints: Flagged dangerous endpoints
        hardcoded_secrets: Identified hardcoded secrets
        interesting_parameters: Notable parameters or data flows
        timestamp: Analysis timestamp
    """
    endpoints: List[str] = field(default_factory=list)
    auth_mechanisms: List[str] = field(default_factory=list)
    dangerous_endpoints: List[str] = field(default_factory=list)
    hardcoded_secrets: List[str] = field(default_factory=list)
    interesting_parameters: List[str] = field(default_factory=list)
    timestamp: float = 0.0


class AIPenetrationTest:
    """AI-assisted penetration testing capabilities.

    Provides intelligent asset analysis, payload generation, passive scan
    enhancement, and vulnerability verification using AI models.

    Attributes:
        ai_engine: AI engine instance
        project_id: Current project identifier
        _analysis_callback: Optional analysis progress callback
    """

    def __init__(
        self,
        ai_engine: AIEngine,
        project_id: str = "",
        analysis_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Initialize AI penetration test module.

        Args:
            ai_engine: AI engine instance.
            project_id: Current project identifier.
            analysis_callback: Optional async callback for analysis progress.
        """
        self.ai_engine = ai_engine
        self.project_id = project_id
        self._analysis_callback = analysis_callback

    async def _report_progress(self, message: str, percentage: float) -> None:
        """Report analysis progress.

        Args:
            message: Progress message.
            percentage: Progress percentage (0-100).
        """
        if self._analysis_callback:
            await self._analysis_callback(message, percentage)

    async def analyze_asset(
        self,
        asset_info: Dict[str, Any],
        tech_stack: Optional[List[str]] = None,
    ) -> AssetAnalysisResult:
        """Analyze target asset and recommend testing approach.

        Args:
            asset_info: Asset information dictionary.
            tech_stack: Known technology stack (optional).

        Returns:
            AssetAnalysisResult with analysis and recommendations.
        """
        await self._report_progress("Starting asset analysis...", 10.0)

        template = self.ai_engine.get_prompt_template("asset_analysis")
        if not template:
            raise ValueError("Asset analysis template not found")

        system_prompt, user_prompt = template.render(
            asset_info=json.dumps(asset_info, indent=2, ensure_ascii=False),
            tech_stack="\n".join(tech_stack) if tech_stack else "Unknown",
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        await self._report_progress("Generating asset analysis...", 50.0)

        response = await self.ai_engine.chat_completion(
            messages=messages,
            project_id=self.project_id,
        )

        await self._report_progress("Parsing analysis results...", 90.0)

        result = self._parse_asset_analysis(response.content, asset_info)

        await self._report_progress("Asset analysis completed", 100.0)

        return result

    async def generate_payloads(
        self,
        vulnerability_type: str,
        target_tech: str,
        request_context: str,
        parameters: List[str],
    ) -> PayloadGenerationResult:
        """Generate targeted payloads for specific vulnerability types.

        Args:
            vulnerability_type: Type of vulnerability to test.
            target_tech: Target technology.
            request_context: Request context string.
            parameters: List of parameters to test.

        Returns:
            PayloadGenerationResult with generated payloads.
        """
        await self._report_progress("Starting payload generation...", 10.0)

        template = self.ai_engine.get_prompt_template("payload_generation")
        if not template:
            raise ValueError("Payload generation template not found")

        system_prompt, user_prompt = template.render(
            vuln_type=vulnerability_type,
            target_tech=target_tech,
            request_context=request_context,
            parameters=", ".join(parameters),
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        await self._report_progress("Generating payloads...", 50.0)

        response = await self.ai_engine.chat_completion(
            messages=messages,
            project_id=self.project_id,
        )

        await self._report_progress("Validating payloads...", 80.0)

        result = self._parse_payload_generation(response.content)

        for payload in result.payloads:
            sandbox_result = self.ai_engine.validate_payload(payload)
            if sandbox_result.status.value == "blocked":
                result.payloads.remove(payload)
                result.explanations.append(f"Payload blocked by sandbox: {sandbox_result.blocked_reasons}")

        await self._report_progress("Payload generation completed", 100.0)

        return result

    async def generate_waf_bypass(
        self,
        waf_info: str,
        original_payload: str,
        interception_response: str,
    ) -> PayloadGenerationResult:
        """Generate WAF bypass payloads based on interception analysis.

        Args:
            waf_info: WAF information string.
            original_payload: Original payload that was blocked.
            interception_response: WAF interception response.

        Returns:
            PayloadGenerationResult with bypass payloads.
        """
        await self._report_progress("Analyzing WAF interception...", 10.0)

        template = self.ai_engine.get_prompt_template("waf_bypass")
        if not template:
            raise ValueError("WAF bypass template not found")

        system_prompt, user_prompt = template.render(
            waf_info=waf_info,
            original_payload=original_payload,
            interception_response=interception_response,
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        await self._report_progress("Generating bypass payloads...", 50.0)

        response = await self.ai_engine.chat_completion(
            messages=messages,
            project_id=self.project_id,
        )

        result = self._parse_payload_generation(response.content)

        await self._report_progress("WAF bypass generation completed", 100.0)

        return result

    async def analyze_passive_scan(
        self,
        target: str,
        findings: List[Dict[str, Any]],
        traffic_sample: str,
    ) -> PassiveScanAnalysisResult:
        """Deep analysis of passive scan findings.

        Args:
            target: Target identifier.
            findings: List of passive scan findings.
            traffic_sample: Sample traffic for analysis.

        Returns:
            PassiveScanAnalysisResult with AI analysis.
        """
        await self._report_progress("Starting passive scan analysis...", 10.0)

        template = self.ai_engine.get_prompt_template("passive_scan_analysis")
        if not template:
            raise ValueError("Passive scan analysis template not found")

        system_prompt, user_prompt = template.render(
            target=target,
            findings=json.dumps(findings, indent=2, ensure_ascii=False),
            traffic_sample=traffic_sample,
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        await self._report_progress("Analyzing findings...", 50.0)

        response = await self.ai_engine.chat_completion(
            messages=messages,
            project_id=self.project_id,
        )

        await self._report_progress("Parsing analysis results...", 90.0)

        result = self._parse_passive_scan_analysis(response.content, findings)

        await self._report_progress("Passive scan analysis completed", 100.0)

        return result

    async def verify_vulnerability(
        self,
        vulnerability_type: str,
        target: str,
        poc_output: str,
        response_analysis: str,
    ) -> VulnerabilityVerificationResult:
        """Analyze PoC execution results and confirm vulnerability.

        Args:
            vulnerability_type: Type of vulnerability.
            target: Target identifier.
            poc_output: PoC execution output.
            response_analysis: Response analysis string.

        Returns:
            VulnerabilityVerificationResult with verification status.
        """
        await self._report_progress("Starting vulnerability verification...", 10.0)

        template = self.ai_engine.get_prompt_template("vulnerability_verification")
        if not template:
            raise ValueError("Vulnerability verification template not found")

        system_prompt, user_prompt = template.render(
            vuln_type=vulnerability_type,
            target=target,
            poc_output=poc_output,
            response_analysis=response_analysis,
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        await self._report_progress("Analyzing PoC results...", 50.0)

        response = await self.ai_engine.chat_completion(
            messages=messages,
            project_id=self.project_id,
        )

        await self._report_progress("Parsing verification results...", 90.0)

        result = self._parse_vulnerability_verification(response.content)

        await self._report_progress("Vulnerability verification completed", 100.0)

        return result

    async def analyze_js_endpoints(
        self,
        js_content: str,
    ) -> JSEndpointAnalysisResult:
        """Analyze JavaScript files for API endpoints and security issues.

        Args:
            js_content: JavaScript file content.

        Returns:
            JSEndpointAnalysisResult with extracted endpoints and findings.
        """
        await self._report_progress("Starting JS endpoint analysis...", 10.0)

        template = self.ai_engine.get_prompt_template("js_endpoint_analysis")
        if not template:
            raise ValueError("JS endpoint analysis template not found")

        system_prompt, user_prompt = template.render(
            js_content=js_content,
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        await self._report_progress("Analyzing JavaScript...", 50.0)

        response = await self.ai_engine.chat_completion(
            messages=messages,
            project_id=self.project_id,
        )

        result = self._parse_js_endpoint_analysis(response.content)

        await self._report_progress("JS endpoint analysis completed", 100.0)

        return result

    async def test_idor(
        self,
        original_request: str,
        response: str,
        parameters: List[str],
        known_ids: Optional[List[str]] = None,
    ) -> PayloadGenerationResult:
        """Generate and analyze IDOR test cases.

        Args:
            original_request: Original request string.
            response: Original response string.
            parameters: Parameters to test for IDOR.
            known_ids: Known user IDs for testing (optional).

        Returns:
            PayloadGenerationResult with IDOR test cases.
        """
        await self._report_progress("Starting IDOR testing...", 10.0)

        template = self.ai_engine.get_prompt_template("idor_testing")
        if not template:
            raise ValueError("IDOR testing template not found")

        system_prompt, user_prompt = template.render(
            original_request=original_request,
            response=response,
            parameters=", ".join(parameters),
            known_ids=", ".join(known_ids) if known_ids else "None",
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        await self._report_progress("Generating IDOR test cases...", 50.0)

        response_ai = await self.ai_engine.chat_completion(
            messages=messages,
            project_id=self.project_id,
        )

        result = self._parse_payload_generation(response_ai.content)

        await self._report_progress("IDOR testing completed", 100.0)

        return result

    def _parse_asset_analysis(
        self,
        ai_response: str,
        asset_info: Dict[str, Any],
    ) -> AssetAnalysisResult:
        """Parse AI asset analysis response.

        Args:
            ai_response: AI response text.
            asset_info: Original asset information.

        Returns:
            Parsed AssetAnalysisResult.
        """
        result = AssetAnalysisResult(
            asset_id=asset_info.get("id", ""),
            timestamp=time.time(),
        )

        lines = ai_response.split("\n")
        current_section = ""

        for line in lines:
            line = line.strip()
            if not line:
                continue

            if "technology" in line.lower() or "stack" in line.lower():
                current_section = "tech"
            elif "vulnerability" in line.lower() or "cve" in line.lower():
                current_section = "vulns"
            elif "recommend" in line.lower() or "test" in line.lower():
                current_section = "tests"
            elif "attack" in line.lower() or "vector" in line.lower():
                current_section = "vectors"
            elif "risk" in line.lower():
                current_section = "risk"
            elif line.startswith("-") or line.startswith("*"):
                content = line[1:].strip()
                if current_section == "tech":
                    result.technology_stack.append(content)
                elif current_section == "tests":
                    result.recommended_tests.append(content)
                elif current_section == "vectors":
                    result.potential_attack_vectors.append(content)
            elif current_section == "risk":
                result.risk_assessment += line + " "

        if "spring" in ai_response.lower() or "java" in ai_response.lower():
            result.confidence = ConfidenceLevel.HIGH
        elif len(result.technology_stack) > 0:
            result.confidence = ConfidenceLevel.MEDIUM
        else:
            result.confidence = ConfidenceLevel.LOW

        return result

    def _parse_payload_generation(self, ai_response: str) -> PayloadGenerationResult:
        """Parse AI payload generation response.

        Args:
            ai_response: AI response text.

        Returns:
            Parsed PayloadGenerationResult.
        """
        result = PayloadGenerationResult(timestamp=time.time())

        lines = ai_response.split("\n")
        current_payload = ""
        current_explanation = ""
        in_payload = False
        in_explanation = False

        for line in lines:
            if "```" in line:
                if in_payload:
                    if current_payload:
                        result.payloads.append(current_payload.strip())
                        result.explanations.append(current_explanation.strip())
                    current_payload = ""
                    current_explanation = ""
                    in_payload = False
                else:
                    in_payload = True
                continue

            if in_payload:
                current_payload += line + "\n"
            elif line.startswith("-") or line.startswith("*"):
                current_explanation += line[1:].strip() + "\n"

        if not result.payloads:
            result.payloads = [ai_response]
            result.explanations = ["AI-generated payload"]

        result.success_probability = 0.7
        result.risk_level = "medium"

        return result

    def _parse_passive_scan_analysis(
        self,
        ai_response: str,
        original_findings: List[Dict[str, Any]],
    ) -> PassiveScanAnalysisResult:
        """Parse AI passive scan analysis response.

        Args:
            ai_response: AI response text.
            original_findings: Original scan findings.

        Returns:
            Parsed PassiveScanAnalysisResult.
        """
        result = PassiveScanAnalysisResult(
            findings=original_findings,
            timestamp=time.time(),
        )

        lines = ai_response.split("\n")
        current_section = ""

        for line in lines:
            line = line.strip()
            if not line:
                continue

            if "false positive" in line.lower():
                current_section = "fp"
            elif "high value" in line.lower() or "important" in line.lower():
                current_section = "high"
            elif "logical" in line.lower() or "business" in line.lower():
                current_section = "logical"
            elif "recommend" in line.lower() or "priority" in line.lower():
                current_section = "rec"
            elif line.startswith("-") or line.startswith("*"):
                content = line[1:].strip()
                if current_section == "fp":
                    result.false_positives.append(content)
                elif current_section == "high":
                    result.high_value_findings.append({"finding": content})
                elif current_section == "logical":
                    result.logical_vulnerabilities.append({"finding": content})
                elif current_section == "rec":
                    result.prioritized_recommendations.append(content)

        return result

    def _parse_vulnerability_verification(
        self,
        ai_response: str,
    ) -> VulnerabilityVerificationResult:
        """Parse AI vulnerability verification response.

        Args:
            ai_response: AI response text.

        Returns:
            Parsed VulnerabilityVerificationResult.
        """
        result = VulnerabilityVerificationResult(timestamp=time.time())

        response_lower = ai_response.lower()

        if "confirm" in response_lower or "verified" in response_lower or "exists" in response_lower:
            result.is_confirmed = True
        elif "likely" in response_lower or "probable" in response_lower:
            result.is_confirmed = True
            result.confidence = ConfidenceLevel.MEDIUM
        elif "possible" in response_lower:
            result.confidence = ConfidenceLevel.LOW
        else:
            result.is_confirmed = False

        if "high" in response_lower:
            result.confidence = ConfidenceLevel.HIGH
        elif "medium" in response_lower:
            result.confidence = ConfidenceLevel.MEDIUM
        else:
            result.confidence = ConfidenceLevel.LOW

        cvss_match = re.search(r"cvss[:\s]*([\d.]+)", response_lower)
        if cvss_match:
            try:
                result.cvss_estimate = float(cvss_match.group(1))
            except ValueError:
                pass

        lines = ai_response.split("\n")
        current_section = ""

        for line in lines:
            line = line.strip()
            if not line:
                continue

            if "evidence" in line.lower():
                current_section = "evidence"
            elif "next step" in line.lower() or "recommend" in line.lower():
                current_section = "next"
            elif "exploit" in line.lower() or "chain" in line.lower():
                current_section = "chain"
            elif line.startswith("-") or line.startswith("*"):
                content = line[1:].strip()
                if current_section == "evidence":
                    result.evidence.append(content)
                elif current_section == "next":
                    result.next_steps.append(content)
                elif current_section == "chain":
                    result.exploitation_chain.append(content)

        return result

    def _parse_js_endpoint_analysis(
        self,
        ai_response: str,
    ) -> JSEndpointAnalysisResult:
        """Parse AI JavaScript endpoint analysis response.

        Args:
            ai_response: AI response text.

        Returns:
            Parsed JSEndpointAnalysisResult.
        """
        result = JSEndpointAnalysisResult(timestamp=time.time())

        url_pattern = re.compile(r'["\'](/[^"\']+)["\']')
        urls = url_pattern.findall(ai_response)
        result.endpoints = list(set(urls))

        dangerous_keywords = ["admin", "delete", "upload", "exec", "shell", "cmd", "password", "token", "secret"]
        for endpoint in result.endpoints:
            if any(kw in endpoint.lower() for kw in dangerous_keywords):
                result.dangerous_endpoints.append(endpoint)

        secret_pattern = re.compile(r'["\']([a-zA-Z0-9_]{20,})["\']')
        secrets = secret_pattern.findall(ai_response)
        result.hardcoded_secrets = list(set(secrets))

        lines = ai_response.split("\n")
        current_section = ""

        for line in lines:
            line = line.strip()
            if "auth" in line.lower() or "token" in line.lower():
                current_section = "auth"
            elif "parameter" in line.lower():
                current_section = "params"
            elif line.startswith("-") or line.startswith("*"):
                content = line[1:].strip()
                if current_section == "auth":
                    result.auth_mechanisms.append(content)
                elif current_section == "params":
                    result.interesting_parameters.append(content)

        return result
