"""Knowledge Graph Builder: Automatic graph construction engine from various data sources.

Provides:
- Automatic graph construction from asset discovery results
- Vulnerability scanning result integration
- Lateral movement log processing
- Credential database integration
- Domain penetration result integration
- FID clustering result integration
- Incremental graph updates
"""

import hashlib
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx

from .knowledge_graph_model import (
    AttackPhase,
    AttackTechniqueNode,
    CredentialNode,
    CredentialType,
    DomainControllerNode,
    DomainNode,
    EdgeType,
    GraphEdge,
    GraphMetadata,
    GraphNode,
    HostNode,
    IPAddressNode,
    NodeType,
    PortServiceNode,
    SeverityLevel,
    UserAccountNode,
    VulnerabilityNode,
)

logger = logging.getLogger(__name__)


class KnowledgeGraphBuilder:
    """Builds and maintains the knowledge graph from various data sources.

    Provides automatic graph construction, incremental updates, and
    relationship inference from asset discovery, vulnerability scanning,
    lateral movement logs, and credential databases.
    """

    def __init__(self) -> None:
        """Initialize the knowledge graph builder."""
        self.graph: nx.MultiDiGraph[str] = nx.MultiDiGraph()
        self._node_index: Dict[str, GraphNode] = {}
        self._edge_index: Dict[str, GraphEdge] = {}
        self._metadata = GraphMetadata(
            graph_id=f"kg_{int(datetime.now().timestamp())}",
            name="Kunlun Knowledge Graph",
        )

    def get_metadata(self) -> GraphMetadata:
        """Get current graph metadata.

        Returns:
            GraphMetadata with current statistics.
        """
        self._metadata.node_count = len(self._node_index)
        self._metadata.edge_count = len(self._edge_index)
        self._metadata.updated_at = datetime.now()

        phase_counts: Dict[AttackPhase, int] = {phase: 0 for phase in AttackPhase}
        for node in self._node_index.values():
            phase = node.properties.get("attack_phase")
            if phase and phase in AttackPhase.__members__.values():
                phase_counts[AttackPhase(phase)] += 1

        self._metadata.attack_phase_counts = phase_counts
        return self._metadata

    def add_ip_node(
        self,
        ip: str,
        version: int = 4,
        is_public: bool = True,
        location: str = "",
        isp: str = "",
        attack_phase: AttackPhase = AttackPhase.EXTERNAL_RECON,
    ) -> str:
        """Add an IP address node to the graph.

        Args:
            ip: IP address string.
            version: IP version (4 or 6).
            is_public: Whether this is a public IP.
            location: Geographic location.
            isp: ISP name.
            attack_phase: Attack phase classification.

        Returns:
            Node ID.
        """
        node_id = f"ip_{ip}"

        if node_id not in self._node_index:
            node = IPAddressNode(
                node_id=node_id,
                label=ip,
                ip=ip,
                version=version,
                is_public=is_public,
                location=location,
                isp=isp,
                properties={"attack_phase": attack_phase.value},
            )
            self._add_node(node)

        return node_id

    def add_domain_node(
        self,
        domain: str,
        registrar: str = "",
        expiry_date: Optional[str] = None,
        dns_records: Optional[List[str]] = None,
    ) -> str:
        """Add a domain name node to the graph.

        Args:
            domain: Domain name.
            registrar: Domain registrar.
            expiry_date: Domain expiration date.
            dns_records: DNS record entries.

        Returns:
            Node ID.
        """
        node_id = f"domain_{domain}"

        if node_id not in self._node_index:
            node = DomainNode(
                node_id=node_id,
                label=domain,
                domain=domain,
                registrar=registrar,
                expiry_date=expiry_date,
                dns_records=dns_records or [],
            )
            self._add_node(node)

        return node_id

    def add_port_service_node(
        self,
        port: int,
        protocol: str = "tcp",
        service_name: str = "",
        version: str = "",
        banner: str = "",
    ) -> str:
        """Add a port/service node to the graph.

        Args:
            port: Port number.
            protocol: Protocol (TCP/UDP).
            service_name: Service name.
            version: Service version.
            banner: Service banner.

        Returns:
            Node ID.
        """
        node_id = f"port_{port}_{protocol}"

        if node_id not in self._node_index:
            node = PortServiceNode(
                node_id=node_id,
                label=f"{port}/{protocol}",
                port=port,
                protocol=protocol,
                service_name=service_name,
                version=version,
                banner=banner,
            )
            self._add_node(node)

        return node_id

    def add_vulnerability_node(
        self,
        cve_id: str,
        cvss_score: float,
        vuln_name: str,
        severity: SeverityLevel,
        is_exploited: bool = False,
    ) -> str:
        """Add a vulnerability node to the graph.

        Args:
            cve_id: CVE identifier.
            cvss_score: CVSS score (0-10).
            vuln_name: Vulnerability name.
            severity: Severity level.
            is_exploited: Whether vulnerability has been exploited.

        Returns:
            Node ID.
        """
        node_id = f"vuln_{cve_id}"

        if node_id not in self._node_index:
            node = VulnerabilityNode(
                node_id=node_id,
                label=cve_id,
                cve_id=cve_id,
                cvss_score=cvss_score,
                vuln_name=vuln_name,
                severity=severity,
                is_exploited=is_exploited,
                properties={
                    "importance": cvss_score,
                    "attack_phase": AttackPhase.INITIAL_ACCESS.value,
                },
            )
            self._add_node(node)

        return node_id

    def add_credential_node(
        self,
        cred_type: CredentialType,
        target: str = "",
        username: str = "",
        obtained_at: Optional[datetime] = None,
    ) -> str:
        """Add a credential node to the graph.

        Args:
            cred_type: Credential type.
            target: Target system/service.
            username: Username (masked).
            obtained_at: When credential was obtained.

        Returns:
            Node ID.
        """
        cred_hash = hashlib.md5(f"{cred_type.value}:{target}:{username}".encode()).hexdigest()[:8]
        node_id = f"cred_{cred_hash}"

        if node_id not in self._node_index:
            node = CredentialNode(
                node_id=node_id,
                label=f"{cred_type.value}:{username}",
                cred_type=cred_type,
                target=target,
                username=username,
                obtained_at=obtained_at,
                properties={"attack_phase": AttackPhase.ESTABLISH_FOOTHOLD.value},
            )
            self._add_node(node)

        return node_id

    def add_host_node(
        self,
        hostname: str,
        os_info: str = "",
        domain_member: str = "",
        privilege_level: str = "user",
        attack_phase: AttackPhase = AttackPhase.ESTABLISH_FOOTHOLD,
    ) -> str:
        """Add a host node to the graph.

        Args:
            hostname: Host name.
            os_info: Operating system.
            domain_member: Domain membership info.
            privilege_level: Current privilege level.
            attack_phase: Attack phase classification.

        Returns:
            Node ID.
        """
        node_id = f"host_{hostname}"

        if node_id not in self._node_index:
            node = HostNode(
                node_id=node_id,
                label=hostname,
                hostname=hostname,
                os=os_info,
                domain_member=domain_member,
                privilege_level=privilege_level,
                properties={"attack_phase": attack_phase.value},
            )
            self._add_node(node)

        return node_id

    def add_domain_controller_node(
        self,
        domain_name: str,
        functional_level: str = "",
        trust_relationships: Optional[List[str]] = None,
    ) -> str:
        """Add a domain controller node to the graph.

        Args:
            domain_name: Domain name.
            functional_level: Domain functional level.
            trust_relationships: Trust relationships with other domains.

        Returns:
            Node ID.
        """
        node_id = f"dc_{domain_name}"

        if node_id not in self._node_index:
            node = DomainControllerNode(
                node_id=node_id,
                label=f"DC:{domain_name}",
                domain_name=domain_name,
                functional_level=functional_level,
                trust_relationships=trust_relationships or [],
                properties={"attack_phase": AttackPhase.DOMAIN_COMPROMISE.value},
            )
            self._add_node(node)

        return node_id

    def add_attack_technique_node(
        self,
        attack_id: str,
        technique_name: str,
        tactic: str = "",
    ) -> str:
        """Add an ATT&CK attack technique node to the graph.

        Args:
            attack_id: ATT&CK technique ID.
            technique_name: Technique name.
            tactic: Tactic category.

        Returns:
            Node ID.
        """
        node_id = f"attack_{attack_id}"

        if node_id not in self._node_index:
            node = AttackTechniqueNode(
                node_id=node_id,
                label=f"{attack_id}: {technique_name}",
                attack_id=attack_id,
                technique_name=technique_name,
                tactic=tactic,
            )
            self._add_node(node)

        return node_id

    def add_user_account_node(
        self,
        username: str,
        sid: str = "",
        domain: str = "",
        groups: Optional[List[str]] = None,
    ) -> str:
        """Add a user/account node to the graph.

        Args:
            username: Username.
            sid: Security identifier.
            domain: Domain the account belongs to.
            groups: Group memberships.

        Returns:
            Node ID.
        """
        node_id = f"user_{username}"

        if node_id not in self._node_index:
            node = UserAccountNode(
                node_id=node_id,
                label=username,
                username=username,
                sid=sid,
                domain=domain,
                groups=groups or [],
            )
            self._add_node(node)

        return node_id

    def add_dns_resolution_edge(self, domain_id: str, ip_id: str) -> str:
        """Add a DNS resolution edge from domain to IP.

        Args:
            domain_id: Domain node ID.
            ip_id: IP node ID.

        Returns:
            Edge ID.
        """
        edge_id = f"edge_dns_{domain_id}_{ip_id}"

        if edge_id not in self._edge_index:
            edge = GraphEdge(
                edge_id=edge_id,
                source_id=domain_id,
                target_id=ip_id,
                edge_type=EdgeType.DNS_RESOLUTION,
                weight=1.0,
            )
            self._add_edge(edge)

        return edge_id

    def add_port_open_edge(self, ip_id: str, port_id: str) -> str:
        """Add a port open edge from IP to port/service.

        Args:
            ip_id: IP node ID.
            port_id: Port/service node ID.

        Returns:
            Edge ID.
        """
        edge_id = f"edge_port_{ip_id}_{port_id}"

        if edge_id not in self._edge_index:
            edge = GraphEdge(
                edge_id=edge_id,
                source_id=ip_id,
                target_id=port_id,
                edge_type=EdgeType.PORT_OPEN,
                weight=1.0,
            )
            self._add_edge(edge)

        return edge_id

    def add_vulnerability_affects_edge(
        self,
        vuln_id: str,
        target_id: str,
        weight: Optional[float] = None,
    ) -> str:
        """Add a vulnerability affects edge.

        Args:
            vuln_id: Vulnerability node ID.
            target_id: Target node ID (port/service or IP).
            weight: Edge weight (lower = easier to exploit).

        Returns:
            Edge ID.
        """
        edge_id = f"edge_vuln_{vuln_id}_{target_id}"

        if edge_id not in self._edge_index:
            if weight is None:
                vuln_node = self._node_index.get(vuln_id)
                if isinstance(vuln_node, VulnerabilityNode):
                    weight = max(0.1, 1.0 - (vuln_node.cvss_score / 10.0))
                else:
                    weight = 1.0

            edge = GraphEdge(
                edge_id=edge_id,
                source_id=vuln_id,
                target_id=target_id,
                edge_type=EdgeType.VULNERABILITY_AFFECTS,
                weight=weight,
            )
            self._add_edge(edge)

        return edge_id

    def add_credential_association_edge(
        self,
        cred_id: str,
        target_id: str,
        weight: float = 0.1,
    ) -> str:
        """Add a credential association edge.

        Args:
            cred_id: Credential node ID.
            target_id: Target node ID (IP/host).
            weight: Edge weight (credentials have low weight = easy access).

        Returns:
            Edge ID.
        """
        edge_id = f"edge_cred_{cred_id}_{target_id}"

        if edge_id not in self._edge_index:
            edge = GraphEdge(
                edge_id=edge_id,
                source_id=cred_id,
                target_id=target_id,
                edge_type=EdgeType.CREDENTIAL_ASSOCIATION,
                weight=weight,
            )
            self._add_edge(edge)

        return edge_id

    def add_lateral_movement_edge(
        self,
        source_host_id: str,
        target_host_id: str,
        method: str = "",
        weight: float = 0.5,
    ) -> str:
        """Add a lateral movement edge between hosts.

        Args:
            source_host_id: Source host node ID.
            target_host_id: Target host node ID.
            method: Lateral movement method.
            weight: Edge weight.

        Returns:
            Edge ID.
        """
        edge_id = f"edge_lateral_{source_host_id}_{target_host_id}"

        if edge_id not in self._edge_index:
            edge = GraphEdge(
                edge_id=edge_id,
                source_id=source_host_id,
                target_id=target_host_id,
                edge_type=EdgeType.LATERAL_MOVEMENT,
                weight=weight,
                properties={"method": method},
            )
            self._add_edge(edge)

        return edge_id

    def add_domain_trust_edge(
        self,
        source_dc_id: str,
        target_dc_id: str,
        trust_type: str = "",
    ) -> str:
        """Add a domain trust edge between domain controllers.

        Args:
            source_dc_id: Source domain controller node ID.
            target_dc_id: Target domain controller node ID.
            trust_type: Type of trust relationship.

        Returns:
            Edge ID.
        """
        edge_id = f"edge_trust_{source_dc_id}_{target_dc_id}"

        if edge_id not in self._edge_index:
            edge = GraphEdge(
                edge_id=edge_id,
                source_id=source_dc_id,
                target_id=target_dc_id,
                edge_type=EdgeType.DOMAIN_TRUST,
                weight=0.8,
                properties={"trust_type": trust_type},
            )
            self._add_edge(edge)

        return edge_id

    def add_certificate_sharing_edge(
        self,
        source_id: str,
        target_id: str,
        cert_hash: str = "",
    ) -> str:
        """Add a certificate sharing edge.

        Args:
            source_id: Source node ID.
            target_id: Target node ID.
            cert_hash: Certificate hash.

        Returns:
            Edge ID.
        """
        edge_id = f"edge_cert_{source_id}_{target_id}"

        if edge_id not in self._edge_index:
            edge = GraphEdge(
                edge_id=edge_id,
                source_id=source_id,
                target_id=target_id,
                edge_type=EdgeType.CERTIFICATE_SHARING,
                weight=1.0,
                properties={"cert_hash": cert_hash},
            )
            self._add_edge(edge)

        return edge_id

    def add_same_app_family_edge(
        self,
        source_id: str,
        target_id: str,
        fid_cluster: str = "",
    ) -> str:
        """Add a same application Family edge.

        Args:
            source_id: Source node ID.
            target_id: Target node ID.
            fid_cluster: FID cluster identifier.

        Returns:
            Edge ID.
        """
        edge_id = f"edge_family_{source_id}_{target_id}"

        if edge_id not in self._edge_index:
            edge = GraphEdge(
                edge_id=edge_id,
                source_id=source_id,
                target_id=target_id,
                edge_type=EdgeType.SAME_APP_FAMILY,
                weight=1.0,
                properties={"fid_cluster": fid_cluster},
            )
            self._add_edge(edge)

        return edge_id

    def add_attack_technique_mapping_edge(
        self,
        event_id: str,
        technique_id: str,
    ) -> str:
        """Add an attack technique mapping edge.

        Args:
            event_id: Attack event node ID.
            technique_id: Attack technique node ID.

        Returns:
            Edge ID.
        """
        edge_id = f"edge_attack_map_{event_id}_{technique_id}"

        if edge_id not in self._edge_index:
            edge = GraphEdge(
                edge_id=edge_id,
                source_id=event_id,
                target_id=technique_id,
                edge_type=EdgeType.ATTACK_TECHNIQUE_MAPPING,
                weight=1.0,
            )
            self._add_edge(edge)

        return edge_id

    def build_from_asset_discovery(
        self,
        assets: List[Dict[str, Any]],
    ) -> Tuple[int, int]:
        """Build graph from asset discovery results.

        Args:
            assets: List of asset dictionaries with IP, domain, port, service info.

        Returns:
            Tuple of (nodes_added, edges_added).
        """
        nodes_added = 0
        edges_added = 0

        for asset in assets:
            ip = asset.get("ip", "")
            if ip:
                ip_id = self.add_ip_node(
                    ip=ip,
                    version=asset.get("version", 4),
                    is_public=asset.get("is_public", True),
                    location=asset.get("location", ""),
                    isp=asset.get("isp", ""),
                )
                nodes_added += 1

            domain = asset.get("domain", "")
            if domain and ip:
                domain_id = self.add_domain_node(
                    domain=domain,
                    registrar=asset.get("registrar", ""),
                    expiry_date=asset.get("expiry_date"),
                )
                nodes_added += 1
                self.add_dns_resolution_edge(domain_id, ip_id)
                edges_added += 1

            port = asset.get("port")
            if port is not None and ip:
                port_id = self.add_port_service_node(
                    port=port,
                    protocol=asset.get("protocol", "tcp"),
                    service_name=asset.get("service_name", ""),
                    version=asset.get("service_version", ""),
                    banner=asset.get("banner", ""),
                )
                nodes_added += 1
                self.add_port_open_edge(ip_id, port_id)
                edges_added += 1

        return nodes_added, edges_added

    def build_from_vulnerability_scan(
        self,
        vulnerabilities: List[Dict[str, Any]],
    ) -> Tuple[int, int]:
        """Build graph from vulnerability scanning results.

        Args:
            vulnerabilities: List of vulnerability dictionaries.

        Returns:
            Tuple of (nodes_added, edges_added).
        """
        nodes_added = 0
        edges_added = 0

        for vuln in vulnerabilities:
            cve_id = vuln.get("cve_id", "")
            if not cve_id:
                continue

            vuln_id = self.add_vulnerability_node(
                cve_id=cve_id,
                cvss_score=vuln.get("cvss_score", 0.0),
                vuln_name=vuln.get("vuln_name", ""),
                severity=SeverityLevel(vuln.get("severity", "info")),
                is_exploited=vuln.get("is_exploited", False),
            )
            nodes_added += 1

            target_id = vuln.get("target_id", "")
            if target_id:
                self.add_vulnerability_affects_edge(vuln_id, target_id)
                edges_added += 1

        return nodes_added, edges_added

    def build_from_lateral_movement_logs(
        self,
        movements: List[Dict[str, Any]],
    ) -> Tuple[int, int]:
        """Build graph from lateral movement operation logs.

        Args:
            movements: List of lateral movement dictionaries.

        Returns:
            Tuple of (nodes_added, edges_added).
        """
        nodes_added = 0
        edges_added = 0

        for movement in movements:
            source_host = movement.get("source_host", "")
            target_host = movement.get("target_host", "")

            if source_host:
                source_id = self.add_host_node(
                    hostname=source_host,
                    os_info=movement.get("source_os", ""),
                    privilege_level=movement.get("source_privilege", "user"),
                )
                nodes_added += 1

            if target_host:
                target_id = self.add_host_node(
                    hostname=target_host,
                    os_info=movement.get("target_os", ""),
                    privilege_level=movement.get("target_privilege", "user"),
                )
                nodes_added += 1

            if source_host and target_host:
                self.add_lateral_movement_edge(
                    f"host_{source_host}",
                    f"host_{target_host}",
                    method=movement.get("method", ""),
                    weight=movement.get("weight", 0.5),
                )
                edges_added += 1

        return nodes_added, edges_added

    def build_from_credentials(
        self,
        credentials: List[Dict[str, Any]],
    ) -> Tuple[int, int]:
        """Build graph from credential database.

        Args:
            credentials: List of credential dictionaries.

        Returns:
            Tuple of (nodes_added, edges_added).
        """
        nodes_added = 0
        edges_added = 0

        for cred in credentials:
            cred_type_str = cred.get("cred_type", "password")
            cred_type = CredentialType(cred_type_str)

            cred_id = self.add_credential_node(
                cred_type=cred_type,
                target=cred.get("target", ""),
                username=cred.get("username", ""),
                obtained_at=cred.get("obtained_at"),
            )
            nodes_added += 1

            target_id = cred.get("target_id", "")
            if target_id:
                self.add_credential_association_edge(cred_id, target_id)
                edges_added += 1

        return nodes_added, edges_added

    def build_from_domain_pentest(
        self,
        domain_data: List[Dict[str, Any]],
    ) -> Tuple[int, int]:
        """Build graph from domain penetration results.

        Args:
            domain_data: List of domain penetration dictionaries.

        Returns:
            Tuple of (nodes_added, edges_added).
        """
        nodes_added = 0
        edges_added = 0

        for data in domain_data:
            domain_name = data.get("domain_name", "")
            if domain_name:
                dc_id = self.add_domain_controller_node(
                    domain_name=domain_name,
                    functional_level=data.get("functional_level", ""),
                    trust_relationships=data.get("trust_relationships", []),
                )
                nodes_added += 1

            trust_targets = data.get("trust_targets", [])
            for trust_target in trust_targets:
                target_dc_id = self.add_domain_controller_node(
                    domain_name=trust_target,
                )
                nodes_added += 1

                if domain_name:
                    self.add_domain_trust_edge(
                        f"dc_{domain_name}",
                        f"dc_{trust_target}",
                        trust_type=data.get("trust_type", ""),
                    )
                    edges_added += 1

        return nodes_added, edges_added

    def build_from_fid_clustering(
        self,
        clusters: List[Dict[str, Any]],
    ) -> Tuple[int, int]:
        """Build graph from FID clustering results.

        Args:
            clusters: List of FID cluster dictionaries.

        Returns:
            Tuple of (nodes_added, edges_added).
        """
        edges_added = 0

        for cluster in clusters:
            fid = cluster.get("fid", "")
            members = cluster.get("members", [])

            for i, member_a in enumerate(members):
                for member_b in members[i + 1:]:
                    self.add_same_app_family_edge(member_a, member_b, fid_cluster=fid)
                    edges_added += 1

        return 0, edges_added

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Get a node by ID.

        Args:
            node_id: Node identifier.

        Returns:
            GraphNode or None.
        """
        return self._node_index.get(node_id)

    def get_edge(self, edge_id: str) -> Optional[GraphEdge]:
        """Get an edge by ID.

        Args:
            edge_id: Edge identifier.

        Returns:
            GraphEdge or None.
        """
        return self._edge_index.get(edge_id)

    def get_all_nodes(self) -> Dict[str, GraphNode]:
        """Get all nodes in the graph.

        Returns:
            Dictionary mapping node IDs to GraphNode objects.
        """
        return dict(self._node_index)

    def get_all_edges(self) -> Dict[str, GraphEdge]:
        """Get all edges in the graph.

        Returns:
            Dictionary mapping edge IDs to GraphEdge objects.
        """
        return dict(self._edge_index)

    def get_networkx_graph(self) -> nx.MultiDiGraph[str]:
        """Get the underlying NetworkX graph.

        Returns:
            NetworkX MultiDiGraph.
        """
        return self.graph

    def clear(self) -> None:
        """Clear the entire graph."""
        self.graph.clear()
        self._node_index.clear()
        self._edge_index.clear()
        self._metadata = GraphMetadata(
            graph_id=f"kg_{int(datetime.now().timestamp())}",
            name="Kunlun Knowledge Graph",
        )

    def _add_node(self, node: GraphNode) -> None:
        """Add a node to the internal graph.

        Args:
            node: GraphNode to add.
        """
        self._node_index[node.node_id] = node
        self.graph.add_node(node.node_id, **node.model_dump())

    def _add_edge(self, edge: GraphEdge) -> None:
        """Add an edge to the internal graph.

        Args:
            edge: GraphEdge to add.
        """
        self._edge_index[edge.edge_id] = edge
        self.graph.add_edge(
            edge.source_id,
            edge.target_id,
            key=edge.edge_id,
            **edge.model_dump(),
        )
