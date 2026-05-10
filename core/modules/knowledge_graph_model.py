"""Knowledge Graph Data Models: Entity and relationship type definitions using Pydantic.

Defines:
- Node types: IP, Domain, Port/Service, Vulnerability, Credential, Host, Domain Controller,
  Attack Technique, User/Account
- Edge types: DNS Resolution, Port Open, Vulnerability Affects, Credential Association,
  Lateral Movement, Domain Trust, Certificate Sharing, Same Application Family,
  Attack Technique Mapping
- Graph metadata and query result models
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class NodeType(str, Enum):
    """Types of nodes in the knowledge graph."""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    PORT_SERVICE = "port_service"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    HOST = "host"
    DOMAIN_CONTROLLER = "domain_controller"
    ATTACK_TECHNIQUE = "attack_technique"
    USER_ACCOUNT = "user_account"


class EdgeType(str, Enum):
    """Types of edges (relationships) in the knowledge graph."""
    DNS_RESOLUTION = "dns_resolution"
    PORT_OPEN = "port_open"
    VULNERABILITY_AFFECTS = "vulnerability_affects"
    CREDENTIAL_ASSOCIATION = "credential_association"
    LATERAL_MOVEMENT = "lateral_movement"
    DOMAIN_TRUST = "domain_trust"
    CERTIFICATE_SHARING = "certificate_sharing"
    SAME_APP_FAMILY = "same_app_family"
    ATTACK_TECHNIQUE_MAPPING = "attack_technique_mapping"


class SeverityLevel(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CredentialType(str, Enum):
    """Types of credentials."""
    PASSWORD = "password"
    HASH = "hash"
    TICKET = "ticket"
    KEY = "key"


class AttackPhase(str, Enum):
    """Attack phases for layered view."""
    EXTERNAL_RECON = "external_recon"
    INITIAL_ACCESS = "initial_access"
    ESTABLISH_FOOTHOLD = "establish_foothold"
    LATERAL_MOVEMENT = "lateral_movement"
    DOMAIN_COMPROMISE = "domain_compromise"


class GraphNode(BaseModel):
    """Base model for graph nodes.

    Attributes:
        node_id: Unique identifier for the node
        node_type: Type of the node
        label: Display label for the node
        properties: Additional properties specific to node type
        created_at: Node creation timestamp
        updated_at: Last update timestamp
    """
    node_id: str = Field(..., description="Unique node identifier")
    node_type: NodeType = Field(..., description="Node type")
    label: str = Field(..., description="Display label")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Node properties")
    created_at: datetime = Field(default_factory=datetime.now, description="Creation time")
    updated_at: datetime = Field(default_factory=datetime.now, description="Last update time")


class GraphEdge(BaseModel):
    """Base model for graph edges.

    Attributes:
        edge_id: Unique identifier for the edge
        source_id: Source node ID
        target_id: Target node ID
        edge_type: Type of the relationship
        weight: Edge weight for path calculation (lower = easier to traverse)
        properties: Additional properties specific to edge type
        created_at: Edge creation timestamp
    """
    edge_id: str = Field(..., description="Unique edge identifier")
    source_id: str = Field(..., description="Source node ID")
    target_id: str = Field(..., description="Target node ID")
    edge_type: EdgeType = Field(..., description="Edge type")
    weight: float = Field(default=1.0, description="Edge weight for pathfinding")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Edge properties")
    created_at: datetime = Field(default_factory=datetime.now, description="Creation time")


class IPAddressNode(GraphNode):
    """IP address node.

    Attributes:
        ip: IP address string
        version: IP version (4 or 6)
        is_public: Whether this is a public IP
        location: Geographic location
        isp: Internet service provider
    """
    node_type: NodeType = NodeType.IP_ADDRESS
    ip: str = Field(..., description="IP address")
    version: int = Field(default=4, description="IP version")
    is_public: bool = Field(default=True, description="Whether public IP")
    location: str = Field(default="", description="Geographic location")
    isp: str = Field(default="", description="ISP name")


class DomainNode(GraphNode):
    """Domain name node.

    Attributes:
        domain: Domain name
        registrar: Domain registrar
        expiry_date: Domain expiration date
        dns_records: DNS record entries
    """
    node_type: NodeType = NodeType.DOMAIN
    domain: str = Field(..., description="Domain name")
    registrar: str = Field(default="", description="Domain registrar")
    expiry_date: Optional[str] = Field(default=None, description="Expiry date")
    dns_records: List[str] = Field(default_factory=list, description="DNS records")


class PortServiceNode(GraphNode):
    """Port/service node.

    Attributes:
        port: Port number
        protocol: Protocol (TCP/UDP)
        service_name: Service name
        version: Service version
        banner: Service banner
    """
    node_type: NodeType = NodeType.PORT_SERVICE
    port: int = Field(..., description="Port number")
    protocol: str = Field(default="tcp", description="Protocol")
    service_name: str = Field(default="", description="Service name")
    version: str = Field(default="", description="Service version")
    banner: str = Field(default="", description="Service banner")


class VulnerabilityNode(GraphNode):
    """Vulnerability node.

    Attributes:
        cve_id: CVE identifier
        cvss_score: CVSS score (0-10)
        vuln_name: Vulnerability name
        severity: Severity level
        is_exploited: Whether vulnerability has been exploited
    """
    node_type: NodeType = NodeType.VULNERABILITY
    cve_id: str = Field(default="", description="CVE identifier")
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0, description="CVSS score")
    vuln_name: str = Field(default="", description="Vulnerability name")
    severity: SeverityLevel = Field(default=SeverityLevel.INFO, description="Severity level")
    is_exploited: bool = Field(default=False, description="Whether exploited")


class CredentialNode(GraphNode):
    """Credential node (sensitive data, display masked).

    Attributes:
        cred_type: Credential type
        target: Target system/service
        username: Username (masked)
        obtained_at: When credential was obtained
    """
    node_type: NodeType = NodeType.CREDENTIAL
    cred_type: CredentialType = Field(..., description="Credential type")
    target: str = Field(default="", description="Target system")
    username: str = Field(default="", description="Username (masked)")
    obtained_at: Optional[datetime] = Field(default=None, description="Obtained time")


class HostNode(GraphNode):
    """Host node.

    Attributes:
        hostname: Host name
        os: Operating system
        domain_member: Domain membership info
        privilege_level: Current privilege level
    """
    node_type: NodeType = NodeType.HOST
    hostname: str = Field(default="", description="Host name")
    os: str = Field(default="", description="Operating system")
    domain_member: str = Field(default="", description="Domain membership")
    privilege_level: str = Field(default="user", description="Privilege level")


class DomainControllerNode(GraphNode):
    """Domain controller node.

    Attributes:
        domain_name: Domain name
        functional_level: Domain functional level
        trust_relationships: Trust relationships with other domains
    """
    node_type: NodeType = NodeType.DOMAIN_CONTROLLER
    domain_name: str = Field(..., description="Domain name")
    functional_level: str = Field(default="", description="Functional level")
    trust_relationships: List[str] = Field(default_factory=list, description="Trust relationships")


class AttackTechniqueNode(GraphNode):
    """ATT&CK attack technique node.

    Attributes:
        attack_id: ATT&CK technique ID
        technique_name: Technique name
        tactic: Tactic category
    """
    node_type: NodeType = NodeType.ATTACK_TECHNIQUE
    attack_id: str = Field(..., description="ATT&CK ID")
    technique_name: str = Field(..., description="Technique name")
    tactic: str = Field(default="", description="Tactic category")


class UserAccountNode(GraphNode):
    """User/account node.

    Attributes:
        username: Username
        sid: Security identifier
        domain: Domain the account belongs to
        groups: Group memberships
    """
    node_type: NodeType = NodeType.USER_ACCOUNT
    username: str = Field(..., description="Username")
    sid: str = Field(default="", description="Security identifier")
    domain: str = Field(default="", description="Domain")
    groups: List[str] = Field(default_factory=list, description="Group memberships")


class GraphMetadata(BaseModel):
    """Metadata for the knowledge graph.

    Attributes:
        graph_id: Unique graph identifier
        name: Graph name
        description: Graph description
        node_count: Number of nodes
        edge_count: Number of edges
        created_at: Creation timestamp
        updated_at: Last update timestamp
        attack_phase_counts: Node counts per attack phase
    """
    graph_id: str = Field(..., description="Graph identifier")
    name: str = Field(..., description="Graph name")
    description: str = Field(default="", description="Description")
    node_count: int = Field(default=0, description="Node count")
    edge_count: int = Field(default=0, description="Edge count")
    created_at: datetime = Field(default_factory=datetime.now, description="Creation time")
    updated_at: datetime = Field(default_factory=datetime.now, description="Last update time")
    attack_phase_counts: Dict[AttackPhase, int] = Field(default_factory=dict, description="Phase counts")


class AttackPath(BaseModel):
    """Attack path result.

    Attributes:
        path_id: Unique path identifier
        nodes: Ordered list of node IDs in the path
        edges: Ordered list of edge IDs in the path
        total_weight: Total path weight
        description: Human-readable path description
        risk_score: Risk score for this path (0-100)
    """
    path_id: str = Field(..., description="Path identifier")
    nodes: List[str] = Field(default_factory=list, description="Node IDs in path")
    edges: List[str] = Field(default_factory=list, description="Edge IDs in path")
    total_weight: float = Field(default=0.0, description="Total weight")
    description: str = Field(default="", description="Path description")
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Risk score")


class AttackRecommendation(BaseModel):
    """Attack target recommendation.

    Attributes:
        target_node_id: Recommended target node ID
        target_label: Target display label
        reason: Recommendation reason
        success_probability: Estimated success probability (0-1)
        required_credentials: Required credentials for this attack
        next_steps: Suggested next steps after compromise
    """
    target_node_id: str = Field(..., description="Target node ID")
    target_label: str = Field(..., description="Target label")
    reason: str = Field(..., description="Recommendation reason")
    success_probability: float = Field(default=0.0, ge=0.0, le=1.0, description="Success probability")
    required_credentials: List[str] = Field(default_factory=list, description="Required credentials")
    next_steps: List[str] = Field(default_factory=list, description="Next steps")


class AttackSurfaceScore(BaseModel):
    """Attack surface assessment score card.

    Attributes:
        overall_score: Overall attack surface score (0-100, higher = more exposed)
        external_exposure_score: External exposure score
        internal_risk_score: Internal lateral movement risk score
        domain_risk_score: Domain compromise risk score
        public_ip_count: Number of public IPs
        open_port_count: Number of open ports
        high_severity_vuln_count: Number of high severity vulnerabilities
        reachable_host_count: Number of reachable internal hosts
        credential_coverage: Percentage of hosts covered by known credentials
        domain_path_count: Number of paths to domain controller
        shortest_domain_path_length: Shortest path length to domain controller
    """
    overall_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Overall score")
    external_exposure_score: float = Field(default=0.0, ge=0.0, le=100.0, description="External score")
    internal_risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Internal score")
    domain_risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Domain score")
    public_ip_count: int = Field(default=0, description="Public IP count")
    open_port_count: int = Field(default=0, description="Open port count")
    high_severity_vuln_count: int = Field(default=0, description="High severity vuln count")
    reachable_host_count: int = Field(default=0, description="Reachable host count")
    credential_coverage: float = Field(default=0.0, ge=0.0, le=1.0, description="Credential coverage")
    domain_path_count: int = Field(default=0, description="Domain path count")
    shortest_domain_path_length: int = Field(default=0, description="Shortest domain path")


class QueryResult(BaseModel):
    """Graph query result.

    Attributes:
        query: Original query string
        matched_nodes: List of matched node IDs
        matched_edges: List of matched edge IDs
        highlighted_paths: Paths to highlight
        metadata: Additional query metadata
    """
    query: str = Field(..., description="Query string")
    matched_nodes: List[str] = Field(default_factory=list, description="Matched node IDs")
    matched_edges: List[str] = Field(default_factory=list, description="Matched edge IDs")
    highlighted_paths: List[AttackPath] = Field(default_factory=list, description="Highlighted paths")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Query metadata")
