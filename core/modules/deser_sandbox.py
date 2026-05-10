"""Sandbox security verification for Java deserialization payloads.

Provides:
- Local Docker sandbox execution with multi-JDK support
- Target compatibility pre-check
- Security restrictions (network isolation, resource limits, timeout)
"""

import asyncio
import base64
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class JdkVersion(Enum):
    """JDK version types."""
    JDK_6 = "6"
    JDK_7 = "7"
    JDK_8 = "8"
    JDK_11 = "11"
    JDK_17 = "17"
    JDK_21 = "21"


class SandboxStatus(Enum):
    """Sandbox execution status."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    RESOURCE_LIMIT = "resource_limit"


@dataclass
class SandboxConfig:
    """Sandbox configuration.

    Attributes:
        jdk_version: JDK version to use
        cpu_limit: CPU limit (cores)
        memory_limit: Memory limit (MB)
        disk_limit: Disk limit (MB)
        network_isolated: Whether network is isolated
        timeout_seconds: Execution timeout
        allow_reverse_callback: Whether reverse callback allowed
    """
    jdk_version: JdkVersion = JdkVersion.JDK_8
    cpu_limit: float = 1.0
    memory_limit: int = 512
    disk_limit: int = 1024
    network_isolated: bool = True
    timeout_seconds: int = 30
    allow_reverse_callback: bool = False


@dataclass
class SandboxResult:
    """Sandbox execution result.

    Attributes:
        sandbox_id: Unique sandbox identifier
        config: Sandbox configuration
        status: Execution status
        payload: Tested payload
        payload_base64: Base64 encoded payload
        execution_success: Whether execution succeeded
        command_output: Command output
        error_message: Error message if failed
        execution_time: Actual execution time
        resource_usage: Resource usage metrics
        compatibility_score: Compatibility score (0-100)
        timestamp: Execution timestamp
    """
    sandbox_id: str = ""
    config: SandboxConfig = field(default_factory=SandboxConfig)
    status: SandboxStatus = SandboxStatus.PENDING
    payload: bytes = b""
    payload_base64: str = ""
    execution_success: bool = False
    command_output: str = ""
    error_message: str = ""
    execution_time: float = 0.0
    resource_usage: Dict[str, float] = field(default_factory=dict)
    compatibility_score: float = 0.0
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "sandbox_id": self.sandbox_id,
            "jdk_version": self.config.jdk_version.value,
            "status": self.status.value,
            "execution_success": self.execution_success,
            "command_output": self.command_output,
            "error_message": self.error_message,
            "execution_time": self.execution_time,
            "compatibility_score": self.compatibility_score,
        }


@dataclass
class CompatibilityResult:
    """Compatibility pre-check result.

    Attributes:
        target_jdk: Target JDK version
        recommended_gadgets: Recommended gadget chains
        incompatible_gadgets: Incompatible gadget chains
        success_rate: Estimated success rate
        alternatives: Alternative payload suggestions
        warnings: Compatibility warnings
    """
    target_jdk: JdkVersion = JdkVersion.JDK_8
    recommended_gadgets: List[str] = field(default_factory=list)
    incompatible_gadgets: List[str] = field(default_factory=list)
    success_rate: float = 0.0
    alternatives: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class DeserSandbox:
    """Deserialization sandbox for payload verification.

    Provides Docker-based sandbox execution with multi-JDK support,
    compatibility pre-check, and security restrictions.
    """

    JDK_DOCKER_IMAGES: Dict[JdkVersion, str] = {
        JdkVersion.JDK_6: "openjdk:6-jdk",
        JdkVersion.JDK_7: "openjdk:7-jdk",
        JdkVersion.JDK_8: "openjdk:8-jdk",
        JdkVersion.JDK_11: "openjdk:11-jdk",
        JdkVersion.JDK_17: "openjdk:17-jdk",
        JdkVersion.JDK_21: "openjdk:21-jdk",
    }

    GADGET_JDK_COMPATIBILITY: Dict[str, List[JdkVersion]] = {
        "CommonsCollections1": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "CommonsCollections2": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "CommonsCollections3": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "CommonsCollections4": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "CommonsCollections5": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "CommonsCollections6": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "CommonsCollections7": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "Jdk7u21": [JdkVersion.JDK_7],
        "Jre8u20": [JdkVersion.JDK_8],
        "Spring1": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "Spring2": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "Hibernate1": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "Hibernate2": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "Groovy1": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "BeanShell1": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "Clojure1": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "Myfaces1": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "Myfaces2": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "ROME": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "Vaadin1": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "Wicket1": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "Click1": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "JavassistWeld1": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "JBossInterceptors1": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "JRMPClient": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "JRMPListener": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "JSON1": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "MozillaRhino1": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "MozillaRhino2": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "SignedObject": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8],
        "URLDNS": [JdkVersion.JDK_6, JdkVersion.JDK_7, JdkVersion.JDK_8, JdkVersion.JDK_11, JdkVersion.JDK_17, JdkVersion.JDK_21],
    }

    def __init__(
        self,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize deserialization sandbox.

        Args:
            event_bus: Event bus for broadcasting events.
        """
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._sandbox_history: List[SandboxResult] = []
        self._docker_available: bool = False

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
        logger.info("Sandbox Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("Sandbox: %s", message)

    async def check_docker_available(self) -> bool:
        """Check if Docker is available.

        Returns:
            True if Docker is available.
        """
        try:
            process = await asyncio.create_subprocess_exec(
                "docker",
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()
            self._docker_available = process.returncode == 0
            return self._docker_available
        except FileNotFoundError:
            self._docker_available = False
            return False

    async def execute_in_sandbox(
        self,
        payload: bytes,
        config: Optional[SandboxConfig] = None,
    ) -> SandboxResult:
        """Execute payload in sandbox.

        Args:
            payload: Payload to test.
            config: Sandbox configuration.

        Returns:
            SandboxResult.
        """
        start_time = time.time()
        sandbox_config = config or SandboxConfig()
        result = SandboxResult(
            sandbox_id=f"sandbox_{int(time.time())}_{secrets.token_hex(4)}",
            config=sandbox_config,
            payload=payload,
            payload_base64=base64.b64encode(payload).decode("utf-8"),
            timestamp=time.time(),
        )

        try:
            await self._report_progress("初始化沙箱", 10)

            docker_available = await self.check_docker_available()
            if not docker_available:
                result.status = SandboxStatus.FAILED
                result.error_message = "Docker不可用"
                result.execution_time = time.time() - start_time
                await self._report_log("沙箱执行失败: Docker不可用")
                return result

            await self._report_progress("创建沙箱容器", 20)

            container_id = await self._create_container(sandbox_config)
            if not container_id:
                result.status = SandboxStatus.FAILED
                result.error_message = "容器创建失败"
                result.execution_time = time.time() - start_time
                return result

            await self._report_progress("注入Payload", 40)

            await self._inject_payload(container_id, payload)

            await self._report_progress("执行Payload", 60)

            execution_result = await self._execute_payload(
                container_id,
                sandbox_config.timeout_seconds,
            )

            await self._report_progress("清理沙箱", 80)

            await self._cleanup_container(container_id)

            if execution_result:
                result.status = SandboxStatus.SUCCESS
                result.execution_success = execution_result.get("success", False)
                result.command_output = execution_result.get("output", "")
                result.execution_time = execution_result.get("time", 0.0)
            else:
                result.status = SandboxStatus.FAILED
                result.error_message = "执行超时或失败"

            result.resource_usage = await self._get_resource_usage(container_id)
            result.compatibility_score = self._calculate_compatibility_score(result)

            result.execution_time = time.time() - start_time
            await self._report_progress("完成", 100)

            self._sandbox_history.append(result)

        except Exception as e:
            result.status = SandboxStatus.FAILED
            result.error_message = str(e)
            result.execution_time = time.time() - start_time
            await self._report_log(f"沙箱执行失败: {e}")
            logger.error("Sandbox execution failed: %s", e)

        return result

    async def _create_container(self, config: SandboxConfig) -> Optional[str]:
        """Create Docker container.

        Args:
            config: Sandbox configuration.

        Returns:
            Container ID or None.
        """
        try:
            image = self.JDK_DOCKER_IMAGES.get(config.jdk_version, "openjdk:8-jdk")

            network_mode = "none" if config.network_isolated else "bridge"

            cmd = [
                "docker", "run", "-d",
                "--network", network_mode,
                "--cpus", str(config.cpu_limit),
                "--memory", f"{config.memory_limit}m",
                "--memory-swap", f"{config.memory_limit}m",
                "--pids-limit", "50",
                "--read-only",
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
                image,
                "tail", "-f", "/dev/null",
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                return stdout.decode("utf-8").strip()
            return None

        except Exception as e:
            logger.error("Container creation failed: %s", e)
            return None

    async def _inject_payload(
        self,
        container_id: str,
        payload: bytes,
    ) -> bool:
        """Inject payload into container.

        Args:
            container_id: Container ID.
            payload: Payload bytes.

        Returns:
            True if injection succeeded.
        """
        try:
            payload_path = f"/tmp/payload_{secrets.token_hex(8)}.ser"

            process = await asyncio.create_subprocess_exec(
                "docker", "exec", "-i", container_id,
                "sh", "-c", f"cat > {payload_path}",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate(input=payload)

            return process.returncode == 0

        except Exception as e:
            logger.error("Payload injection failed: %s", e)
            return False

    async def _execute_payload(
        self,
        container_id: str,
        timeout_seconds: int,
    ) -> Optional[Dict[str, Any]]:
        """Execute payload in container.

        Args:
            container_id: Container ID.
            timeout_seconds: Execution timeout.

        Returns:
            Execution result dictionary or None.
        """
        try:
            java_cmd = (
                "java -cp /tmp "
                "-Djava.security.manager=allow "
                "DeserializeTest /tmp/payload_*.ser"
            )

            process = await asyncio.create_subprocess_exec(
                "docker", "exec", container_id,
                "sh", "-c", java_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout_seconds,
                )

                return {
                    "success": process.returncode == 0,
                    "output": stdout.decode("utf-8", errors="replace"),
                    "error": stderr.decode("utf-8", errors="replace"),
                    "time": timeout_seconds,
                }

            except asyncio.TimeoutError:
                await self._kill_container_process(container_id)
                return {
                    "success": False,
                    "output": "",
                    "error": "Execution timeout",
                    "time": timeout_seconds,
                }

        except Exception as e:
            logger.error("Payload execution failed: %s", e)
            return None

    async def _cleanup_container(self, container_id: str) -> bool:
        """Cleanup container.

        Args:
            container_id: Container ID.

        Returns:
            True if cleanup succeeded.
        """
        try:
            process = await asyncio.create_subprocess_exec(
                "docker", "rm", "-f", container_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            return process.returncode == 0
        except Exception as e:
            logger.error("Container cleanup failed: %s", e)
            return False

    async def _kill_container_process(self, container_id: str) -> bool:
        """Kill process in container.

        Args:
            container_id: Container ID.

        Returns:
            True if kill succeeded.
        """
        try:
            process = await asyncio.create_subprocess_exec(
                "docker", "exec", container_id,
                "pkill", "-9", "java",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            return True
        except Exception:
            return False

    async def _get_resource_usage(self, container_id: str) -> Dict[str, float]:
        """Get container resource usage.

        Args:
            container_id: Container ID.

        Returns:
            Resource usage metrics.
        """
        usage: Dict[str, float] = {}
        try:
            process = await asyncio.create_subprocess_exec(
                "docker", "stats", "--no-stream", "--format",
                "{{.CPUPerc}}\t{{.MemUsage}}",
                container_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                parts = stdout.decode("utf-8").strip().split("\t")
                if len(parts) >= 2:
                    usage["cpu_percent"] = float(parts[0].replace("%", ""))
                    mem_parts = parts[1].split("/")
                    if len(mem_parts) >= 2:
                        usage["memory_mb"] = float(mem_parts[0].replace("MiB", "").strip())
        except Exception as e:
            logger.error("Resource usage query failed: %s", e)

        return usage

    def _calculate_compatibility_score(self, result: SandboxResult) -> float:
        """Calculate compatibility score.

        Args:
            result: Sandbox result.

        Returns:
            Compatibility score (0-100).
        """
        score = 0.0

        if result.execution_success:
            score += 50.0

        if result.status == SandboxStatus.SUCCESS:
            score += 30.0

        if result.command_output:
            score += 20.0

        return min(score, 100.0)

    async def check_compatibility(
        self,
        target_jdk: JdkVersion,
        gadget_chains: Optional[List[str]] = None,
    ) -> CompatibilityResult:
        """Check payload compatibility with target JDK.

        Args:
            target_jdk: Target JDK version.
            gadget_chains: Gadget chains to check.

        Returns:
            CompatibilityResult.
        """
        result = CompatibilityResult(target_jdk=target_jdk)

        try:
            await self._report_progress("检查兼容性", 10)

            chains_to_check = gadget_chains or list(self.GADGET_JDK_COMPATIBILITY.keys())

            for chain in chains_to_check:
                compatible_versions = self.GADGET_JDK_COMPATIBILITY.get(chain, [])

                if target_jdk in compatible_versions:
                    result.recommended_gadgets.append(chain)
                else:
                    result.incompatible_gadgets.append(chain)

            total = len(chains_to_check)
            compatible = len(result.recommended_gadgets)
            result.success_rate = (compatible / total * 100) if total > 0 else 0.0

            if not result.recommended_gadgets:
                result.warnings.append(
                    f"未找到兼容JDK {target_jdk.value}的Gadget链"
                )
                result.alternatives = [
                    "URLDNS (仅DNS检测)",
                    "尝试使用JNDI绕过",
                ]

            if len(result.incompatible_gadgets) > len(result.recommended_gadgets):
                result.warnings.append(
                    f"多数Gadget链不兼容JDK {target_jdk.value}"
                )

            await self._report_progress("完成", 100)

        except Exception as e:
            await self._report_log(f"兼容性检查失败: {e}")
            logger.error("Compatibility check failed: %s", e)

        return result

    def get_sandbox_history(self) -> List[SandboxResult]:
        """Get sandbox execution history.

        Returns:
            List of sandbox results.
        """
        return self._sandbox_history

    def get_sandbox_by_id(self, sandbox_id: str) -> Optional[SandboxResult]:
        """Get sandbox result by ID.

        Args:
            sandbox_id: Sandbox identifier.

        Returns:
            SandboxResult or None.
        """
        for result in self._sandbox_history:
            if result.sandbox_id == sandbox_id:
                return result
        return None
