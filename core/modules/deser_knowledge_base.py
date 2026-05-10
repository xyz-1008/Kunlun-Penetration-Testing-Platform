"""Knowledge base for Java deserialization vulnerabilities.

Provides:
- Knowledge graph (CVE → affected versions → exploit chains → remediation)
- Version compatibility matrix
- Practical case library
"""

import asyncio
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class SeverityLevel(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class NodeType(Enum):
    """Knowledge graph node types."""
    CVE = "cve"
    PRODUCT = "product"
    VERSION = "version"
    GADGET_CHAIN = "gadget_chain"
    DEPENDENCY = "dependency"
    REMEDIATION = "remediation"
    CASE = "case"


@dataclass
class CveNode:
    """CVE knowledge graph node.

    Attributes:
        cve_id: CVE identifier
        name: Vulnerability name
        severity: Severity level
        cvss_score: CVSS score
        description: Vulnerability description
        affected_products: Affected products
        affected_versions: Affected version ranges
        gadget_chains: Related gadget chains
        remediation: Remediation suggestions
        references: Reference URLs
        mitre_technique: MITRE ATT&CK technique ID
        published_date: Publication date
    """
    cve_id: str = ""
    name: str = ""
    severity: SeverityLevel = SeverityLevel.HIGH
    cvss_score: float = 0.0
    description: str = ""
    affected_products: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    gadget_chains: List[str] = field(default_factory=list)
    remediation: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    mitre_technique: str = "T1566.001"
    published_date: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "cve_id": self.cve_id,
            "name": self.name,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "description": self.description,
            "affected_products": self.affected_products,
            "gadget_chains": self.gadget_chains,
            "remediation": self.remediation,
            "mitre_technique": self.mitre_technique,
        }


@dataclass
class GadgetChainNode:
    """Gadget chain knowledge graph node.

    Attributes:
        chain_id: Chain identifier
        name: Chain name
        description: Chain description
        dependencies: Required dependencies
        compatible_jdks: Compatible JDK versions
        severity: Severity level
        success_rate: Historical success rate
        mitre_technique: MITRE ATT&CK technique ID
    """
    chain_id: str = ""
    name: str = ""
    description: str = ""
    dependencies: List[str] = field(default_factory=list)
    compatible_jdks: List[str] = field(default_factory=list)
    severity: SeverityLevel = SeverityLevel.HIGH
    success_rate: float = 0.0
    mitre_technique: str = "T1566.001"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "chain_id": self.chain_id,
            "name": self.name,
            "description": self.description,
            "dependencies": self.dependencies,
            "compatible_jdks": self.compatible_jdks,
            "severity": self.severity.value,
            "success_rate": self.success_rate,
        }


@dataclass
class CaseNode:
    """Practical case node.

    Attributes:
        case_id: Case identifier
        title: Case title
        industry: Target industry
        vulnerability_type: Vulnerability type
        target_product: Target product
        target_version: Target version
        gadget_chain: Used gadget chain
        exploitation_steps: Exploitation steps
        success_effect: Success effect
        remediation_applied: Remediation applied
        anonymized: Whether data is anonymized
        author: Case author
        created_date: Creation date
    """
    case_id: str = ""
    title: str = ""
    industry: str = ""
    vulnerability_type: str = ""
    target_product: str = ""
    target_version: str = ""
    gadget_chain: str = ""
    exploitation_steps: List[str] = field(default_factory=list)
    success_effect: str = ""
    remediation_applied: str = ""
    anonymized: bool = True
    author: str = ""
    created_date: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "case_id": self.case_id,
            "title": self.title,
            "industry": self.industry,
            "vulnerability_type": self.vulnerability_type,
            "target_product": self.target_product,
            "gadget_chain": self.gadget_chain,
            "exploitation_steps": self.exploitation_steps,
            "success_effect": self.success_effect,
            "anonymized": self.anonymized,
        }


@dataclass
class VersionMatrixEntry:
    """Version compatibility matrix entry.

    Attributes:
        gadget_chain: Gadget chain name
        jdk_versions: Compatible JDK versions
        dependency_versions: Compatible dependency versions
        success_rate: Success rate
        notes: Additional notes
    """
    gadget_chain: str = ""
    jdk_versions: List[str] = field(default_factory=list)
    dependency_versions: Dict[str, List[str]] = field(default_factory=dict)
    success_rate: float = 0.0
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "gadget_chain": self.gadget_chain,
            "jdk_versions": self.jdk_versions,
            "dependency_versions": self.dependency_versions,
            "success_rate": self.success_rate,
        }


@dataclass
class KnowledgeGraphData:
    """Knowledge graph data structure.

    Attributes:
        nodes: Graph nodes
        edges: Graph edges
        node_count: Node count
        edge_count: Edge count
    """
    nodes: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    edges: List[Dict[str, str]] = field(default_factory=list)
    node_count: int = 0
    edge_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "nodes": self.nodes,
            "edges": self.edges,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
        }


class DeserKnowledgeBase:
    """Deserialization vulnerability knowledge base.

    Provides knowledge graph, version compatibility matrix,
    and practical case library.
    """

    BUILT_IN_CVES: Dict[str, Dict[str, Any]] = {
        "CVE-2015-7501": {
            "name": "Commons Collections Deserialization",
            "severity": SeverityLevel.CRITICAL,
            "cvss_score": 9.8,
            "description": "Apache Commons Collections反序列化远程代码执行",
            "affected_products": ["Apache Commons Collections"],
            "affected_versions": ["3.2.1 and earlier"],
            "gadget_chains": ["CommonsCollections1", "CommonsCollections2", "CommonsCollections3"],
            "remediation": [
                "升级到Commons Collections 3.2.2+",
                "使用ObjectInputFilter过滤反序列化",
                "禁用不必要的反序列化端点",
            ],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2015-7501",
                "https://github.com/frohoff/ysoserial",
            ],
            "mitre_technique": "T1566.001",
            "published_date": "2015-11-06",
        },
        "CVE-2020-2555": {
            "name": "WebLogic IIOP Deserialization",
            "severity": SeverityLevel.CRITICAL,
            "cvss_score": 9.8,
            "description": "Oracle WebLogic Server IIOP协议反序列化远程代码执行",
            "affected_products": ["Oracle WebLogic Server"],
            "affected_versions": ["10.3.6.0", "12.1.3.0", "12.2.1.3", "12.2.1.4"],
            "gadget_chains": ["CommonsCollections1", "CommonsCollections4"],
            "remediation": [
                "应用Oracle安全补丁",
                "禁用IIOP协议",
                "配置网络访问控制",
            ],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2020-2555",
            ],
            "mitre_technique": "T1566.001",
            "published_date": "2020-01-15",
        },
        "CVE-2022-22947": {
            "name": "Spring Cloud Gateway RCE",
            "severity": SeverityLevel.CRITICAL,
            "cvss_score": 9.8,
            "description": "Spring Cloud Gateway Actuator端点远程代码执行",
            "affected_products": ["Spring Cloud Gateway"],
            "affected_versions": ["< 3.1.1", "< 3.0.7"],
            "gadget_chains": ["Spring1", "Spring2"],
            "remediation": [
                "升级到Spring Cloud Gateway 3.1.1+或3.0.7+",
                "禁用Actuator端点或添加认证",
                "配置网络安全策略",
            ],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-22947",
            ],
            "mitre_technique": "T1566.001",
            "published_date": "2022-03-01",
        },
        "CVE-2022-22965": {
            "name": "Spring4Shell",
            "severity": SeverityLevel.CRITICAL,
            "cvss_score": 9.8,
            "description": "Spring Framework数据绑定远程代码执行",
            "affected_products": ["Spring Framework"],
            "affected_versions": ["< 5.3.18", "< 5.2.20"],
            "gadget_chains": ["Spring1", "Spring2"],
            "remediation": [
                "升级到Spring Framework 5.3.18+或5.2.20+",
                "配置数据绑定白名单",
                "使用WAF规则防护",
            ],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
            ],
            "mitre_technique": "T1566.001",
            "published_date": "2022-03-31",
        },
        "CVE-2016-4437": {
            "name": "Shiro RememberMe Deserialization",
            "severity": SeverityLevel.CRITICAL,
            "cvss_score": 9.8,
            "description": "Apache Shiro RememberMe Cookie反序列化远程代码执行",
            "affected_products": ["Apache Shiro"],
            "affected_versions": ["< 1.2.5"],
            "gadget_chains": ["CommonsCollections1", "CommonsCollections2"],
            "remediation": [
                "升级到Shiro 1.2.5+",
                "修改默认加密密钥",
                "禁用RememberMe功能",
            ],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2016-4437",
            ],
            "mitre_technique": "T1566.001",
            "published_date": "2016-06-13",
        },
    }

    BUILT_IN_GADGET_CHAINS: Dict[str, Dict[str, Any]] = {
        "CommonsCollections1": {
            "name": "CommonsCollections1",
            "description": "基于Commons Collections的LazyInvocationHandler反序列化链",
            "dependencies": ["commons-collections:3.2.1"],
            "compatible_jdks": ["6", "7", "8"],
            "severity": SeverityLevel.CRITICAL,
            "success_rate": 85.0,
            "mitre_technique": "T1566.001",
        },
        "CommonsCollections2": {
            "name": "CommonsCollections2",
            "description": "基于Commons Collections 4的InvokerTransformer反序列化链",
            "dependencies": ["commons-collections4:4.0"],
            "compatible_jdks": ["6", "7", "8"],
            "severity": SeverityLevel.CRITICAL,
            "success_rate": 80.0,
            "mitre_technique": "T1566.001",
        },
        "CommonsCollections3": {
            "name": "CommonsCollections3",
            "description": "基于Commons Collections的TrAXFilter反序列化链",
            "dependencies": ["commons-collections:3.2.1"],
            "compatible_jdks": ["6", "7", "8"],
            "severity": SeverityLevel.CRITICAL,
            "success_rate": 75.0,
            "mitre_technique": "T1566.001",
        },
        "CommonsCollections4": {
            "name": "CommonsCollections4",
            "description": "基于Commons Collections 4的TrAXFilter反序列化链",
            "dependencies": ["commons-collections4:4.0"],
            "compatible_jdks": ["6", "7", "8"],
            "severity": SeverityLevel.CRITICAL,
            "success_rate": 70.0,
            "mitre_technique": "T1566.001",
        },
        "CommonsCollections5": {
            "name": "CommonsCollections5",
            "description": "基于Commons Collections的BadAttributeValueExpException反序列化链",
            "dependencies": ["commons-collections:3.2.1"],
            "compatible_jdks": ["6", "7", "8"],
            "severity": SeverityLevel.CRITICAL,
            "success_rate": 85.0,
            "mitre_technique": "T1566.001",
        },
        "CommonsCollections6": {
            "name": "CommonsCollections6",
            "description": "基于Commons Collections的HashSet反序列化链",
            "dependencies": ["commons-collections:3.2.1"],
            "compatible_jdks": ["6", "7", "8"],
            "severity": SeverityLevel.CRITICAL,
            "success_rate": 90.0,
            "mitre_technique": "T1566.001",
        },
        "CommonsCollections7": {
            "name": "CommonsCollections7",
            "description": "基于Commons Collections的Hashtable反序列化链",
            "dependencies": ["commons-collections:3.2.1"],
            "compatible_jdks": ["6", "7", "8"],
            "severity": SeverityLevel.CRITICAL,
            "success_rate": 80.0,
            "mitre_technique": "T1566.001",
        },
        "Jdk7u21": {
            "name": "Jdk7u21",
            "description": "基于JDK 7u21的TemplatesImpl反序列化链",
            "dependencies": [],
            "compatible_jdks": ["7"],
            "severity": SeverityLevel.CRITICAL,
            "success_rate": 70.0,
            "mitre_technique": "T1566.001",
        },
        "Jre8u20": {
            "name": "Jre8u20",
            "description": "基于JRE 8u20的TemplatesImpl反序列化链",
            "dependencies": [],
            "compatible_jdks": ["8"],
            "severity": SeverityLevel.CRITICAL,
            "success_rate": 65.0,
            "mitre_technique": "T1566.001",
        },
        "Spring1": {
            "name": "Spring1",
            "description": "基于Spring Framework的ServiceFactory反序列化链",
            "dependencies": ["spring-core", "spring-beans"],
            "compatible_jdks": ["6", "7", "8"],
            "severity": SeverityLevel.CRITICAL,
            "success_rate": 75.0,
            "mitre_technique": "T1566.001",
        },
        "Spring2": {
            "name": "Spring2",
            "description": "基于Spring Framework的JtaTransactionManager反序列化链",
            "dependencies": ["spring-core", "spring-beans"],
            "compatible_jdks": ["6", "7", "8"],
            "severity": SeverityLevel.CRITICAL,
            "success_rate": 70.0,
            "mitre_technique": "T1566.001",
        },
        "Hibernate1": {
            "name": "Hibernate1",
            "description": "基于Hibernate的PojoComponentTuplizer反序列化链",
            "dependencies": ["hibernate-core"],
            "compatible_jdks": ["6", "7", "8"],
            "severity": SeverityLevel.HIGH,
            "success_rate": 60.0,
            "mitre_technique": "T1566.001",
        },
        "Groovy1": {
            "name": "Groovy1",
            "description": "基于Groovy的MethodClosure反序列化链",
            "dependencies": ["groovy"],
            "compatible_jdks": ["6", "7", "8"],
            "severity": SeverityLevel.HIGH,
            "success_rate": 65.0,
            "mitre_technique": "T1566.001",
        },
        "BeanShell1": {
            "name": "BeanShell1",
            "description": "基于BeanShell的XThis反序列化链",
            "dependencies": ["bsh"],
            "compatible_jdks": ["6", "7", "8"],
            "severity": SeverityLevel.HIGH,
            "success_rate": 60.0,
            "mitre_technique": "T1566.001",
        },
        "ROME": {
            "name": "ROME",
            "description": "基于ROME的EqualsBean反序列化链",
            "dependencies": ["rome"],
            "compatible_jdks": ["6", "7", "8"],
            "severity": SeverityLevel.HIGH,
            "success_rate": 55.0,
            "mitre_technique": "T1566.001",
        },
        "URLDNS": {
            "name": "URLDNS",
            "description": "基于URL的DNS检测链（无RCE）",
            "dependencies": [],
            "compatible_jdks": ["6", "7", "8", "11", "17", "21"],
            "severity": SeverityLevel.INFO,
            "success_rate": 95.0,
            "mitre_technique": "T1566.001",
        },
    }

    BUILT_IN_CASES: List[Dict[str, Any]] = [
        {
            "title": "某金融系统Shiro反序列化利用",
            "industry": "金融",
            "vulnerability_type": "反序列化",
            "target_product": "Apache Shiro",
            "target_version": "1.2.4",
            "gadget_chain": "CommonsCollections6",
            "exploitation_steps": [
                "检测RememberMe Cookie存在",
                "使用ysoserial生成CommonsCollections6 payload",
                "使用默认密钥加密payload",
                "发送恶意请求获取命令执行",
                "注入Filter内存马实现持久化",
            ],
            "success_effect": "获取root权限，内网横向移动",
            "remediation_applied": "升级Shiro到1.2.5+，修改默认密钥",
            "anonymized": True,
            "author": "安全研究员A",
            "created_date": "2023-01-15",
        },
        {
            "title": "某电商平台Spring4Shell利用",
            "industry": "电商",
            "vulnerability_type": "数据绑定RCE",
            "target_product": "Spring Framework",
            "target_version": "5.3.17",
            "gadget_chain": "Spring1",
            "exploitation_steps": [
                "识别Spring Framework版本",
                "构造恶意class.module.classLoader请求",
                "写入webshell到tomcat目录",
                "通过webshell执行命令",
            ],
            "success_effect": "获取应用服务器权限",
            "remediation_applied": "升级Spring到5.3.18+，配置WAF规则",
            "anonymized": True,
            "author": "安全研究员B",
            "created_date": "2022-04-10",
        },
        {
            "title": "某政务系统WebLogic T3协议利用",
            "industry": "政务",
            "vulnerability_type": "T3协议反序列化",
            "target_product": "Oracle WebLogic",
            "target_version": "12.2.1.3",
            "gadget_chain": "CommonsCollections1",
            "exploitation_steps": [
                "检测T3协议开放",
                "使用T3协议握手",
                "发送序列化payload",
                "获取命令执行",
            ],
            "success_effect": "获取WebLogic服务器权限",
            "remediation_applied": "应用Oracle安全补丁，禁用T3协议",
            "anonymized": True,
            "author": "安全研究员C",
            "created_date": "2023-06-20",
        },
    ]

    VERSION_MATRIX: List[VersionMatrixEntry] = []

    def __init__(self) -> None:
        """Initialize knowledge base."""
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._cve_nodes: Dict[str, CveNode] = {}
        self._gadget_nodes: Dict[str, GadgetChainNode] = {}
        self._case_nodes: List[CaseNode] = []
        self._graph_data: KnowledgeGraphData = KnowledgeGraphData()
        self._initialize_built_in_data()

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
        logger.info("Knowledge Base Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("Knowledge Base: %s", message)

    def _initialize_built_in_data(self) -> None:
        """Initialize built-in knowledge data."""
        for cve_id, cve_data in self.BUILT_IN_CVES.items():
            self._cve_nodes[cve_id] = CveNode(
                cve_id=cve_id,
                name=cve_data["name"],
                severity=cve_data["severity"],
                cvss_score=cve_data["cvss_score"],
                description=cve_data["description"],
                affected_products=cve_data["affected_products"],
                affected_versions=cve_data["affected_versions"],
                gadget_chains=cve_data["gadget_chains"],
                remediation=cve_data["remediation"],
                references=cve_data["references"],
                mitre_technique=cve_data["mitre_technique"],
                published_date=cve_data["published_date"],
            )

        for chain_id, chain_data in self.BUILT_IN_GADGET_CHAINS.items():
            self._gadget_nodes[chain_id] = GadgetChainNode(
                chain_id=chain_id,
                name=chain_data["name"],
                description=chain_data["description"],
                dependencies=chain_data["dependencies"],
                compatible_jdks=chain_data["compatible_jdks"],
                severity=chain_data["severity"],
                success_rate=chain_data["success_rate"],
                mitre_technique=chain_data["mitre_technique"],
            )

        for case_data in self.BUILT_IN_CASES:
            self._case_nodes.append(CaseNode(
                case_id=f"case_{secrets.token_hex(4)}",
                title=case_data["title"],
                industry=case_data["industry"],
                vulnerability_type=case_data["vulnerability_type"],
                target_product=case_data["target_product"],
                target_version=case_data["target_version"],
                gadget_chain=case_data["gadget_chain"],
                exploitation_steps=case_data["exploitation_steps"],
                success_effect=case_data["success_effect"],
                remediation_applied=case_data["remediation_applied"],
                anonymized=case_data["anonymized"],
                author=case_data["author"],
                created_date=case_data["created_date"],
            ))

        self._build_version_matrix()
        self._build_graph()

    def _build_version_matrix(self) -> None:
        """Build version compatibility matrix."""
        self.VERSION_MATRIX = []
        for chain_id, chain_data in self.BUILT_IN_GADGET_CHAINS.items():
            entry = VersionMatrixEntry(
                gadget_chain=chain_id,
                jdk_versions=chain_data["compatible_jdks"],
                dependency_versions={
                    dep: ["*"] for dep in chain_data["dependencies"]
                },
                success_rate=chain_data["success_rate"],
                notes=chain_data["description"],
            )
            self.VERSION_MATRIX.append(entry)

    def _build_graph(self) -> None:
        """Build knowledge graph."""
        self._graph_data = KnowledgeGraphData()

        for cve_id, cve_node in self._cve_nodes.items():
            self._graph_data.nodes[cve_id] = {
                "type": NodeType.CVE.value,
                "data": cve_node.to_dict(),
            }

        for chain_id, chain_node in self._gadget_nodes.items():
            self._graph_data.nodes[chain_id] = {
                "type": NodeType.GADGET_CHAIN.value,
                "data": chain_node.to_dict(),
            }

        for cve_id, cve_node in self._cve_nodes.items():
            for chain in cve_node.gadget_chains:
                self._graph_data.edges.append({
                    "source": cve_id,
                    "target": chain,
                    "relation": "uses",
                })

        self._graph_data.node_count = len(self._graph_data.nodes)
        self._graph_data.edge_count = len(self._graph_data.edges)

    async def get_cve_details(self, cve_id: str) -> Optional[CveNode]:
        """Get CVE details.

        Args:
            cve_id: CVE identifier.

        Returns:
            CveNode or None.
        """
        return self._cve_nodes.get(cve_id)

    async def get_gadget_chain_details(self, chain_id: str) -> Optional[GadgetChainNode]:
        """Get gadget chain details.

        Args:
            chain_id: Chain identifier.

        Returns:
            GadgetChainNode or None.
        """
        return self._gadget_nodes.get(chain_id)

    async def get_compatible_chains(self, jdk_version: str) -> List[GadgetChainNode]:
        """Get gadget chains compatible with JDK version.

        Args:
            jdk_version: JDK version string.

        Returns:
            List of compatible GadgetChainNode.
        """
        compatible: List[GadgetChainNode] = []
        for chain in self._gadget_nodes.values():
            if jdk_version in chain.compatible_jdks:
                compatible.append(chain)
        return compatible

    async def get_version_matrix(
        self,
        filter_jdk: Optional[str] = None,
    ) -> List[VersionMatrixEntry]:
        """Get version compatibility matrix.

        Args:
            filter_jdk: Filter by JDK version.

        Returns:
            List of VersionMatrixEntry.
        """
        if filter_jdk:
            return [
                entry for entry in self.VERSION_MATRIX
                if filter_jdk in entry.jdk_versions
            ]
        return self.VERSION_MATRIX

    async def get_cases(
        self,
        filter_industry: Optional[str] = None,
        filter_product: Optional[str] = None,
    ) -> List[CaseNode]:
        """Get practical cases.

        Args:
            filter_industry: Filter by industry.
            filter_product: Filter by target product.

        Returns:
            List of CaseNode.
        """
        cases = self._case_nodes

        if filter_industry:
            cases = [c for c in cases if filter_industry.lower() in c.industry.lower()]

        if filter_product:
            cases = [c for c in cases if filter_product.lower() in c.target_product.lower()]

        return cases

    async def get_knowledge_graph(self) -> KnowledgeGraphData:
        """Get knowledge graph data.

        Returns:
            KnowledgeGraphData.
        """
        return self._graph_data

    async def search_cves(
        self,
        keyword: str,
    ) -> List[CveNode]:
        """Search CVEs by keyword.

        Args:
            keyword: Search keyword.

        Returns:
            List of matching CveNode.
        """
        results: List[CveNode] = []
        keyword_lower = keyword.lower()

        for cve in self._cve_nodes.values():
            if (
                keyword_lower in cve.cve_id.lower()
                or keyword_lower in cve.name.lower()
                or keyword_lower in cve.description.lower()
            ):
                results.append(cve)

        return results

    async def add_custom_case(self, case: CaseNode) -> bool:
        """Add custom case to library.

        Args:
            case: Case to add.

        Returns:
            True if added successfully.
        """
        try:
            if not case.case_id:
                case.case_id = f"case_{int(time.time())}_{secrets.token_hex(4)}"
            self._case_nodes.append(case)
            return True
        except Exception as e:
            logger.error("Failed to add custom case: %s", e)
            return False

    async def export_knowledge_base(self) -> Dict[str, Any]:
        """Export knowledge base data.

        Returns:
            Knowledge base data dictionary.
        """
        return {
            "cves": {k: v.to_dict() for k, v in self._cve_nodes.items()},
            "gadget_chains": {k: v.to_dict() for k, v in self._gadget_nodes.items()},
            "cases": [c.to_dict() for c in self._case_nodes],
            "version_matrix": [e.to_dict() for e in self.VERSION_MATRIX],
            "graph": self._graph_data.to_dict(),
        }
