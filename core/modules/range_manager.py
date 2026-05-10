"""Range Manager: Target range environment library management, Docker image pulling, and container lifecycle management.

Provides:
- Built-in 10+ common vulnerability range image references (DVWA, WebGoat, VulHub, PentesterLab, OWASP Juice Shop, etc.)
- Support for user-defined range addition (Docker Compose or Docker image address)
- Range metadata: name, description, difficulty, vulnerability type tags, estimated completion time, required system resources
- Docker image pulling and container lifecycle management
- Container resource limits (CPU, memory)
- Network isolation for range containers
"""

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class DifficultyLevel(Enum):
    """Range difficulty levels."""
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


class ContainerStatus(Enum):
    """Container status."""
    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    DESTROYED = "destroyed"
    ERROR = "error"


class VulnerabilityType(Enum):
    """Vulnerability type tags."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    FILE_UPLOAD = "file_upload"
    COMMAND_INJECTION = "command_injection"
    AUTH_BYPASS = "auth_bypass"
    IDOR = "idor"
    SSRF = "ssrf"
    XXE = "xxe"
    DESERIALIZATION = "deserialization"
    RCE = "rce"
    LFI = "lfi"
    RFI = "rfi"
    LDAP_INJECTION = "ldap_injection"
    JWT_WEAKNESS = "jwt_weakness"
    API_SECURITY = "api_security"
    BUSINESS_LOGIC = "business_logic"
    MULTIPLE = "multiple"


@dataclass
class RangeMetadata:
    """Range environment metadata.

    Attributes:
        range_id: Unique range identifier
        name: Range name
        description: Range description
        difficulty: Difficulty level
        vulnerability_types: List of vulnerability types covered
        estimated_time_minutes: Estimated completion time in minutes
        required_cpu_cores: Required CPU cores
        required_memory_mb: Required memory in MB
        docker_image: Docker image name
        docker_compose_file: Optional Docker Compose file path
        default_port: Default exposed port
        default_credentials: Default username/password pairs
        tags: Additional tags
        author: Range author/creator
        version: Range version
        created_at: Creation timestamp
        is_official: Whether this is an official range
        community_rating: Community rating (0-5)
    """
    range_id: str = ""
    name: str = ""
    description: str = ""
    difficulty: DifficultyLevel = DifficultyLevel.BEGINNER
    vulnerability_types: List[VulnerabilityType] = field(default_factory=list)
    estimated_time_minutes: int = 60
    required_cpu_cores: int = 1
    required_memory_mb: int = 512
    docker_image: str = ""
    docker_compose_file: str = ""
    default_port: int = 8080
    default_credentials: List[Dict[str, str]] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    author: str = ""
    version: str = "1.0"
    created_at: float = 0.0
    is_official: bool = True
    community_rating: float = 0.0


@dataclass
class RangeInstance:
    """Running range instance.

    Attributes:
        instance_id: Unique instance identifier
        range_id: Reference to range metadata
        container_id: Docker container ID
        container_name: Docker container name
        status: Container status
        host_port: Port mapped on host
        container_port: Port inside container
        network_name: Docker network name
        cpu_limit: CPU limit (cores)
        memory_limit_mb: Memory limit in MB
        started_at: Instance start time
        access_url: Full access URL
        proxy_configured: Whether proxy is configured
        metadata: Additional instance metadata
    """
    instance_id: str = ""
    range_id: str = ""
    container_id: str = ""
    container_name: str = ""
    status: ContainerStatus = ContainerStatus.CREATED
    host_port: int = 0
    container_port: int = 8080
    network_name: str = ""
    cpu_limit: float = 1.0
    memory_limit_mb: int = 512
    started_at: float = 0.0
    access_url: str = ""
    proxy_configured: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DockerConfig:
    """Docker configuration for range deployment.

    Attributes:
        docker_host: Docker host address
        docker_socket: Docker socket path
        network_name: Default network name for ranges
        base_port_range: Base port range for auto-assignment
        max_concurrent_ranges: Maximum concurrent running ranges
        default_cpu_limit: Default CPU limit
        default_memory_limit_mb: Default memory limit
        auto_cleanup: Whether to auto-cleanup on error
    """
    docker_host: str = "unix:///var/run/docker.sock"
    docker_socket: str = "/var/run/docker.sock"
    network_name: str = "kunlun_range_network"
    base_port_range: int = 18000
    max_concurrent_ranges: int = 5
    default_cpu_limit: float = 1.0
    default_memory_limit_mb: int = 512
    auto_cleanup: bool = True


class RangeLibrary:
    """Built-in range environment library.

    Contains metadata for 10+ common vulnerability ranges.
    """

    BUILTIN_RANGES: List[RangeMetadata] = [
        RangeMetadata(
            range_id="dvwa",
            name="DVWA (Damn Vulnerable Web Application)",
            description="A PHP/MySQL web application containing various vulnerabilities for practice. Covers SQL Injection, XSS, CSRF, File Upload, Command Injection, and more.",
            difficulty=DifficultyLevel.BEGINNER,
            vulnerability_types=[
                VulnerabilityType.SQL_INJECTION,
                VulnerabilityType.XSS,
                VulnerabilityType.CSRF,
                VulnerabilityType.FILE_UPLOAD,
                VulnerabilityType.COMMAND_INJECTION,
                VulnerabilityType.AUTH_BYPASS,
            ],
            estimated_time_minutes=120,
            required_cpu_cores=1,
            required_memory_mb=256,
            docker_image="vulnerables/web-dvwa:latest",
            default_port=80,
            default_credentials=[
                {"username": "admin", "password": "password"},
            ],
            tags=["php", "mysql", "web", "classic"],
            author="ethicalhack3r",
            version="1.10",
            created_at=1700000000.0,
            is_official=True,
            community_rating=4.8,
        ),
        RangeMetadata(
            range_id="webgoat",
            name="WebGoat",
            description="A deliberately insecure Web Application maintained by OWASP designed to teach web application security concepts. Covers OWASP Top 10 vulnerabilities.",
            difficulty=DifficultyLevel.BEGINNER,
            vulnerability_types=[
                VulnerabilityType.SQL_INJECTION,
                VulnerabilityType.XSS,
                VulnerabilityType.CSRF,
                VulnerabilityType.AUTH_BYPASS,
                VulnerabilityType.IDOR,
                VulnerabilityType.SSRF,
                VulnerabilityType.XXE,
            ],
            estimated_time_minutes=180,
            required_cpu_cores=2,
            required_memory_mb=1024,
            docker_image="webgoat/webgoat:latest",
            default_port=8080,
            default_credentials=[
                {"username": "guest", "password": "guest"},
                {"username": "admin", "password": "admin"},
            ],
            tags=["java", "spring", "owasp", "comprehensive"],
            author="OWASP",
            version="2023.8",
            created_at=1700000000.0,
            is_official=True,
            community_rating=4.9,
        ),
        RangeMetadata(
            range_id="juice_shop",
            name="OWASP Juice Shop",
            description="The most modern and complex insecure web application, including a REST API, JWT authentication, and a modern Angular frontend. Covers modern web vulnerabilities.",
            difficulty=DifficultyLevel.INTERMEDIATE,
            vulnerability_types=[
                VulnerabilityType.SQL_INJECTION,
                VulnerabilityType.XSS,
                VulnerabilityType.CSRF,
                VulnerabilityType.JWT_WEAKNESS,
                VulnerabilityType.API_SECURITY,
                VulnerabilityType.BUSINESS_LOGIC,
                VulnerabilityType.IDOR,
            ],
            estimated_time_minutes=240,
            required_cpu_cores=1,
            required_memory_mb=512,
            docker_image="bkimminich/juice-shop:latest",
            default_port=3000,
            default_credentials=[],
            tags=["nodejs", "angular", "modern", "jwt", "api"],
            author="OWASP",
            version="16.0",
            created_at=1700000000.0,
            is_official=True,
            community_rating=4.9,
        ),
        RangeMetadata(
            range_id="vulhub_struts2",
            name="VulHub - Struts2 RCE (CVE-2017-5638)",
            description="Apache Struts2 remote code execution vulnerability (CVE-2017-5638). Practice real-world CVE exploitation.",
            difficulty=DifficultyLevel.INTERMEDIATE,
            vulnerability_types=[VulnerabilityType.RCE],
            estimated_time_minutes=30,
            required_cpu_cores=1,
            required_memory_mb=512,
            docker_image="vulhub/struts2:s2-045",
            default_port=8080,
            default_credentials=[],
            tags=["java", "struts2", "cve", "rce", "real-world"],
            author="VulHub",
            version="1.0",
            created_at=1700000000.0,
            is_official=True,
            community_rating=4.5,
        ),
        RangeMetadata(
            range_id="vulhub_log4j",
            name="VulHub - Log4Shell (CVE-2021-44228)",
            description="Apache Log4j2 remote code execution vulnerability (CVE-2021-44228). One of the most critical vulnerabilities in recent years.",
            difficulty=DifficultyLevel.INTERMEDIATE,
            vulnerability_types=[VulnerabilityType.RCE, VulnerabilityType.DESERIALIZATION],
            estimated_time_minutes=45,
            required_cpu_cores=2,
            required_memory_mb=1024,
            docker_image="vulhub/log4j:2.14.1",
            default_port=8080,
            default_credentials=[],
            tags=["java", "log4j", "cve", "rce", "critical"],
            author="VulHub",
            version="1.0",
            created_at=1700000000.0,
            is_official=True,
            community_rating=4.7,
        ),
        RangeMetadata(
            range_id="pentesterlab_sqli",
            name="PentesterLab - SQL Injection",
            description="Focused SQL injection exercises covering various injection techniques, from basic to advanced bypass methods.",
            difficulty=DifficultyLevel.INTERMEDIATE,
            vulnerability_types=[VulnerabilityType.SQL_INJECTION],
            estimated_time_minutes=90,
            required_cpu_cores=1,
            required_memory_mb=256,
            docker_image="pentesterlab/sqli:latest",
            default_port=80,
            default_credentials=[],
            tags=["php", "mysql", "sqli", "focused"],
            author="PentesterLab",
            version="1.0",
            created_at=1700000000.0,
            is_official=True,
            community_rating=4.6,
        ),
        RangeMetadata(
            range_id="hackazon",
            name="Hackazon",
            description="A modern vulnerable web application with REST API, mobile app support, and realistic business logic vulnerabilities.",
            difficulty=DifficultyLevel.INTERMEDIATE,
            vulnerability_types=[
                VulnerabilityType.SQL_INJECTION,
                VulnerabilityType.XSS,
                VulnerabilityType.API_SECURITY,
                VulnerabilityType.BUSINESS_LOGIC,
                VulnerabilityType.IDOR,
            ],
            estimated_time_minutes=150,
            required_cpu_cores=1,
            required_memory_mb=512,
            docker_image="rapid7/hackazon:latest",
            default_port=80,
            default_credentials=[
                {"username": "admin", "password": "admin"},
            ],
            tags=["php", "rest", "api", "mobile", "realistic"],
            author="Rapid7",
            version="1.0",
            created_at=1700000000.0,
            is_official=True,
            community_rating=4.4,
        ),
        RangeMetadata(
            range_id="mutillidae",
            name="Mutillidae II",
            description="A vulnerable web application with built-in hints and solutions. Great for beginners learning web security.",
            difficulty=DifficultyLevel.BEGINNER,
            vulnerability_types=[
                VulnerabilityType.SQL_INJECTION,
                VulnerabilityType.XSS,
                VulnerabilityType.CSRF,
                VulnerabilityType.COMMAND_INJECTION,
                VulnerabilityType.LFI,
            ],
            estimated_time_minutes=120,
            required_cpu_cores=1,
            required_memory_mb=256,
            docker_image="owasp/mutillidae:latest",
            default_port=80,
            default_credentials=[],
            tags=["php", "hints", "beginner-friendly"],
            author="OWASP",
            version="2.0",
            created_at=1700000000.0,
            is_official=True,
            community_rating=4.3,
        ),
        RangeMetadata(
            range_id="sqli_labs",
            name="SQLi-Labs",
            description="A comprehensive SQL injection practice platform with 65+ levels covering all types of SQL injection.",
            difficulty=DifficultyLevel.INTERMEDIATE,
            vulnerability_types=[VulnerabilityType.SQL_INJECTION],
            estimated_time_minutes=300,
            required_cpu_cores=1,
            required_memory_mb=256,
            docker_image="acgpiano/sqli-labs:latest",
            default_port=80,
            default_credentials=[],
            tags=["php", "mysql", "sqli", "comprehensive", "65-levels"],
            author="Audi",
            version="1.0",
            created_at=1700000000.0,
            is_official=True,
            community_rating=4.7,
        ),
        RangeMetadata(
            range_id="xss_lab",
            name="XSS-Labs",
            description="A XSS practice platform with 20+ levels covering reflected, stored, and DOM-based XSS.",
            difficulty=DifficultyLevel.BEGINNER,
            vulnerability_types=[VulnerabilityType.XSS],
            estimated_time_minutes=120,
            required_cpu_cores=1,
            required_memory_mb=256,
            docker_image="registry.cn-beijing.aliyuncs.com/7est/xss-labs:latest",
            default_port=80,
            default_credentials=[],
            tags=["php", "xss", "reflected", "stored", "dom"],
            author="do0dl3",
            version="1.0",
            created_at=1700000000.0,
            is_official=True,
            community_rating=4.5,
        ),
        RangeMetadata(
            range_id="upload_labs",
            name="Upload-Labs",
            description="A file upload vulnerability practice platform covering various bypass techniques.",
            difficulty=DifficultyLevel.INTERMEDIATE,
            vulnerability_types=[VulnerabilityType.FILE_UPLOAD],
            estimated_time_minutes=90,
            required_cpu_cores=1,
            required_memory_mb=256,
            docker_image="c0ny1/upload-labs:latest",
            default_port=80,
            default_credentials=[],
            tags=["php", "file-upload", "bypass"],
            author="c0ny1",
            version="1.0",
            created_at=1700000000.0,
            is_official=True,
            community_rating=4.6,
        ),
        RangeMetadata(
            range_id="portswigger_web_security",
            name="PortSwigger Web Security Academy (Local Mirror)",
            description="Local mirror of PortSwigger's Web Security Academy labs. Covers all major web vulnerability types with high-quality exercises.",
            difficulty=DifficultyLevel.ADVANCED,
            vulnerability_types=[
                VulnerabilityType.SQL_INJECTION,
                VulnerabilityType.XSS,
                VulnerabilityType.CSRF,
                VulnerabilityType.SSRF,
                VulnerabilityType.XXE,
                VulnerabilityType.DESERIALIZATION,
                VulnerabilityType.AUTH_BYPASS,
                VulnerabilityType.API_SECURITY,
            ],
            estimated_time_minutes=600,
            required_cpu_cores=2,
            required_memory_mb=1024,
            docker_image="portswigger/web-security-academy:latest",
            default_port=8080,
            default_credentials=[],
            tags=["java", "comprehensive", "advanced", "portswigger"],
            author="PortSwigger",
            version="2024.1",
            created_at=1700000000.0,
            is_official=True,
            community_rating=5.0,
        ),
    ]

    def __init__(self, storage_path: str = "") -> None:
        """Initialize range library.

        Args:
            storage_path: Directory path for custom range storage.
        """
        self.storage_path = storage_path
        self._ranges: Dict[str, RangeMetadata] = {}
        self._load_builtin_ranges()

        if storage_path:
            os.makedirs(storage_path, exist_ok=True)
            self._load_custom_ranges()

    def _load_builtin_ranges(self) -> None:
        """Load built-in range metadata."""
        for range_meta in self.BUILTIN_RANGES:
            self._ranges[range_meta.range_id] = range_meta

    def _load_custom_ranges(self) -> None:
        """Load custom range metadata from storage."""
        if not self.storage_path:
            return

        try:
            ranges_file = os.path.join(self.storage_path, "custom_ranges.json")
            if os.path.exists(ranges_file):
                with open(ranges_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for range_data in data:
                        range_meta = RangeMetadata(
                            range_id=range_data.get("range_id", ""),
                            name=range_data.get("name", ""),
                            description=range_data.get("description", ""),
                            difficulty=DifficultyLevel(range_data.get("difficulty", "beginner")),
                            vulnerability_types=[
                                VulnerabilityType(v)
                                for v in range_data.get("vulnerability_types", [])
                            ],
                            estimated_time_minutes=range_data.get("estimated_time_minutes", 60),
                            required_cpu_cores=range_data.get("required_cpu_cores", 1),
                            required_memory_mb=range_data.get("required_memory_mb", 512),
                            docker_image=range_data.get("docker_image", ""),
                            docker_compose_file=range_data.get("docker_compose_file", ""),
                            default_port=range_data.get("default_port", 8080),
                            default_credentials=range_data.get("default_credentials", []),
                            tags=range_data.get("tags", []),
                            author=range_data.get("author", ""),
                            version=range_data.get("version", "1.0"),
                            created_at=range_data.get("created_at", time.time()),
                            is_official=False,
                            community_rating=range_data.get("community_rating", 0.0),
                        )
                        self._ranges[range_meta.range_id] = range_meta

        except Exception as e:
            logger.error(f"Failed to load custom ranges: {e}")

    def get_range(self, range_id: str) -> Optional[RangeMetadata]:
        """Get range metadata by ID.

        Args:
            range_id: Range identifier.

        Returns:
            RangeMetadata or None if not found.
        """
        return self._ranges.get(range_id)

    def get_all_ranges(self) -> List[RangeMetadata]:
        """Get all range metadata.

        Returns:
            List of all RangeMetadata objects.
        """
        return list(self._ranges.values())

    def get_ranges_by_difficulty(self, difficulty: DifficultyLevel) -> List[RangeMetadata]:
        """Get ranges by difficulty level.

        Args:
            difficulty: Difficulty level filter.

        Returns:
            List of matching RangeMetadata objects.
        """
        return [r for r in self._ranges.values() if r.difficulty == difficulty]

    def get_ranges_by_vulnerability(
        self, vuln_type: VulnerabilityType
    ) -> List[RangeMetadata]:
        """Get ranges by vulnerability type.

        Args:
            vuln_type: Vulnerability type filter.

        Returns:
            List of matching RangeMetadata objects.
        """
        return [
            r for r in self._ranges.values() if vuln_type in r.vulnerability_types
        ]

    def search_ranges(self, query: str) -> List[RangeMetadata]:
        """Search ranges by query string.

        Args:
            query: Search query.

        Returns:
            List of matching RangeMetadata objects.
        """
        query_lower = query.lower()
        results: List[RangeMetadata] = []

        for range_meta in self._ranges.values():
            if (
                query_lower in range_meta.name.lower()
                or query_lower in range_meta.description.lower()
                or any(query_lower in tag.lower() for tag in range_meta.tags)
                or any(query_lower in v.value for v in range_meta.vulnerability_types)
            ):
                results.append(range_meta)

        return results

    def add_custom_range(self, range_meta: RangeMetadata) -> str:
        """Add custom range to library.

        Args:
            range_meta: RangeMetadata to add.

        Returns:
            Range ID.
        """
        range_meta.is_official = False
        range_meta.created_at = time.time()
        self._ranges[range_meta.range_id] = range_meta
        self._save_custom_ranges()
        return range_meta.range_id

    def remove_custom_range(self, range_id: str) -> bool:
        """Remove custom range from library.

        Args:
            range_id: Range identifier.

        Returns:
            True if removed successfully.
        """
        range_meta = self._ranges.get(range_id)
        if range_meta and not range_meta.is_official:
            del self._ranges[range_id]
            self._save_custom_ranges()
            return True
        return False

    def _save_custom_ranges(self) -> None:
        """Save custom ranges to storage."""
        if not self.storage_path:
            return

        try:
            ranges_file = os.path.join(self.storage_path, "custom_ranges.json")
            custom_ranges = [
                {
                    "range_id": r.range_id,
                    "name": r.name,
                    "description": r.description,
                    "difficulty": r.difficulty.value,
                    "vulnerability_types": [v.value for v in r.vulnerability_types],
                    "estimated_time_minutes": r.estimated_time_minutes,
                    "required_cpu_cores": r.required_cpu_cores,
                    "required_memory_mb": r.required_memory_mb,
                    "docker_image": r.docker_image,
                    "docker_compose_file": r.docker_compose_file,
                    "default_port": r.default_port,
                    "default_credentials": r.default_credentials,
                    "tags": r.tags,
                    "author": r.author,
                    "version": r.version,
                    "created_at": r.created_at,
                    "community_rating": r.community_rating,
                }
                for r in self._ranges.values()
                if not r.is_official
            ]
            with open(ranges_file, "w", encoding="utf-8") as f:
                json.dump(custom_ranges, f, ensure_ascii=False, indent=2)

        except Exception as e:
            logger.error(f"Failed to save custom ranges: {e}")


class DockerManager:
    """Docker container lifecycle manager for range environments.

    Handles Docker image pulling, container creation, resource limits,
    network isolation, and container cleanup.
    """

    def __init__(
        self,
        config: Optional[DockerConfig] = None,
        progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Initialize Docker manager.

        Args:
            config: Docker configuration. Uses defaults if None.
            progress_callback: Optional async callback for progress reporting.
        """
        self.config = config or DockerConfig()
        self._progress_callback = progress_callback
        self._used_ports: Set[int] = set()
        self._running_containers: Dict[str, RangeInstance] = {}

    async def _report_progress(self, message: str, percentage: float) -> None:
        """Report operation progress.

        Args:
            message: Progress message.
            percentage: Progress percentage (0-100).
        """
        if self._progress_callback:
            await self._progress_callback(message, percentage)

    async def pull_image(self, image: str) -> bool:
        """Pull Docker image.

        Args:
            image: Docker image name.

        Returns:
            True if pull successful.
        """
        await self._report_progress(f"Pulling image: {image}", 10.0)

        try:
            process = await asyncio.create_subprocess_exec(
                "docker",
                "pull",
                image,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                await self._report_progress(f"Image pulled: {image}", 100.0)
                return True
            else:
                logger.error(f"Failed to pull image: {stderr.decode()}")
                await self._report_progress(f"Failed to pull image: {image}", 100.0)
                return False

        except FileNotFoundError:
            logger.error("Docker not found. Please install Docker.")
            return False
        except Exception as e:
            logger.error(f"Error pulling image: {e}")
            return False

    async def create_network(self) -> bool:
        """Create isolated Docker network for ranges.

        Returns:
            True if network created or already exists.
        """
        try:
            process = await asyncio.create_subprocess_exec(
                "docker",
                "network",
                "create",
                "--driver",
                "bridge",
                self.config.network_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0 or "already exists" in stderr.decode().lower():
                return True
            else:
                logger.error(f"Failed to create network: {stderr.decode()}")
                return False

        except Exception as e:
            logger.error(f"Error creating network: {e}")
            return False

    async def start_container(
        self,
        range_meta: RangeMetadata,
        cpu_limit: Optional[float] = None,
        memory_limit_mb: Optional[int] = None,
    ) -> Optional[RangeInstance]:
        """Start range container.

        Args:
            range_meta: Range metadata.
            cpu_limit: CPU limit override.
            memory_limit_mb: Memory limit override.

        Returns:
            RangeInstance or None if failed.
        """
        await self._report_progress(f"Starting range: {range_meta.name}", 10.0)

        host_port = self._allocate_port()
        if not host_port:
            logger.error("No available ports for range")
            return None

        cpu = cpu_limit or self.config.default_cpu_limit
        memory = memory_limit_mb or self.config.default_memory_limit_mb

        container_name = f"kunlun_{range_meta.range_id}_{int(time.time())}"

        await self._report_progress(f"Creating container: {container_name}", 30.0)

        try:
            cmd = [
                "docker",
                "run",
                "-d",
                "--name",
                container_name,
                "--network",
                self.config.network_name,
                "-p",
                f"{host_port}:{range_meta.default_port}",
                "--cpus",
                str(cpu),
                "--memory",
                f"{memory}m",
                "--restart",
                "no",
            ]

            if range_meta.docker_compose_file:
                cmd = [
                    "docker-compose",
                    "-f",
                    range_meta.docker_compose_file,
                    "up",
                    "-d",
                ]
            else:
                cmd.append(range_meta.docker_image)

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                logger.error(f"Failed to start container: {stderr.decode()}")
                self._release_port(host_port)
                return None

            container_id = stdout.decode().strip()

            await self._report_progress("Waiting for container to be ready...", 70.0)

            await asyncio.sleep(3)

            instance = RangeInstance(
                instance_id=f"instance_{int(time.time())}",
                range_id=range_meta.range_id,
                container_id=container_id,
                container_name=container_name,
                status=ContainerStatus.RUNNING,
                host_port=host_port,
                container_port=range_meta.default_port,
                network_name=self.config.network_name,
                cpu_limit=cpu,
                memory_limit_mb=memory,
                started_at=time.time(),
                access_url=f"http://localhost:{host_port}",
                proxy_configured=False,
                metadata={
                    "range_name": range_meta.name,
                    "difficulty": range_meta.difficulty.value,
                    "default_credentials": range_meta.default_credentials,
                },
            )

            self._running_containers[instance.instance_id] = instance

            await self._report_progress(
                f"Range started: {instance.access_url}", 100.0
            )

            return instance

        except Exception as e:
            logger.error(f"Error starting container: {e}")
            self._release_port(host_port)
            return None

    async def stop_container(self, instance_id: str) -> bool:
        """Stop range container.

        Args:
            instance_id: Instance identifier.

        Returns:
            True if stopped successfully.
        """
        instance = self._running_containers.get(instance_id)
        if not instance:
            return False

        try:
            process = await asyncio.create_subprocess_exec(
                "docker",
                "stop",
                instance.container_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                instance.status = ContainerStatus.STOPPED
                self._release_port(instance.host_port)
                return True
            else:
                logger.error(f"Failed to stop container: {stderr.decode()}")
                return False

        except Exception as e:
            logger.error(f"Error stopping container: {e}")
            return False

    async def destroy_container(self, instance_id: str) -> bool:
        """Destroy range container and cleanup.

        Args:
            instance_id: Instance identifier.

        Returns:
            True if destroyed successfully.
        """
        instance = self._running_containers.get(instance_id)
        if not instance:
            return False

        try:
            process = await asyncio.create_subprocess_exec(
                "docker",
                "rm",
                "-f",
                instance.container_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                instance.status = ContainerStatus.DESTROYED
                self._release_port(instance.host_port)
                del self._running_containers[instance_id]
                return True
            else:
                logger.error(f"Failed to destroy container: {stderr.decode()}")
                return False

        except Exception as e:
            logger.error(f"Error destroying container: {e}")
            return False

    async def get_container_logs(self, instance_id: str, tail: int = 100) -> str:
        """Get container logs.

        Args:
            instance_id: Instance identifier.
            tail: Number of log lines to retrieve.

        Returns:
            Container log string.
        """
        instance = self._running_containers.get(instance_id)
        if not instance:
            return ""

        try:
            process = await asyncio.create_subprocess_exec(
                "docker",
                "logs",
                "--tail",
                str(tail),
                instance.container_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await process.communicate()

            return stdout.decode() + stderr.decode()

        except Exception as e:
            logger.error(f"Error getting logs: {e}")
            return ""

    async def list_running_instances(self) -> List[RangeInstance]:
        """List all running range instances.

        Returns:
            List of running RangeInstance objects.
        """
        return [
            i for i in self._running_containers.values()
            if i.status == ContainerStatus.RUNNING
        ]

    def _allocate_port(self) -> Optional[int]:
        """Allocate next available port.

        Returns:
            Port number or None if no ports available.
        """
        base = self.config.base_port_range
        max_port = base + 1000

        for port in range(base, max_port):
            if port not in self._used_ports:
                self._used_ports.add(port)
                return port

        return None

    def _release_port(self, port: int) -> None:
        """Release allocated port.

        Args:
            port: Port number to release.
        """
        self._used_ports.discard(port)
