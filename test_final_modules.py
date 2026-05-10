"""
Test suite for final stage modules:
beacon_lifecycle, c2_observability, c2_automation, profile_ide, profile_marketplace, threat_intel
"""

import sys
import os
import asyncio
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "core", "modules"))

print("=" * 70)
print("Final Stage Modules - Comprehensive Test Suite")
print("=" * 70)

errors = []

# =============================================================================
# Test 1: beacon_lifecycle.py
# =============================================================================
print("\n[1] Testing beacon_lifecycle.py...")

try:
    from beacon_lifecycle import (
        BeaconLifecycleManager,
        LifecyclePolicy,
        BeaconLifecycle,
        EncryptionKey,
        KeyManager,
        CleanupEngine,
        LifecycleType,
        BeaconState,
        CleanupPhase,
        get_lifecycle_manager,
    )

    policy_short = LifecyclePolicy.short_term()
    assert policy_short.lifecycle_type == LifecycleType.SHORT_TERM, "Short term type mismatch"
    assert policy_short.duration_hours == 24.0, "Duration mismatch"

    policy_mid = LifecyclePolicy.mid_term()
    assert policy_mid.duration_hours == 168.0, "Mid term duration mismatch"

    policy_long = LifecyclePolicy.long_term()
    assert policy_long.duration_hours == 2160.0, "Long term duration mismatch"

    key_mgr = KeyManager()
    key = key_mgr.generate_key(duration_hours=24.0)
    assert len(key.key_material) == 32, "Key material length mismatch"
    assert key.is_active, "New key should be active"

    new_active, new_retired = key_mgr.rotate_key([key], [], duration_hours=24.0)
    assert len(new_active) == 1, "Should have 1 active key"
    assert len(new_retired) == 1, "Should have 1 retired key"
    assert not new_retired[0].is_active, "Retired key should not be active"

    manager = get_lifecycle_manager()
    lifecycle = manager.create_lifecycle("test_beacon_1", policy_short)
    assert lifecycle.beacon_id == "test_beacon_1", "Beacon ID mismatch"
    assert lifecycle.state == BeaconState.ACTIVE, "State should be active"
    assert lifecycle.time_remaining > 0, "Should have time remaining"

    extended = manager.extend_lifecycle("test_beacon_1", additional_hours=48.0)
    assert extended, "Extension should succeed"

    terminated = manager.terminate_lifecycle("test_beacon_1")
    assert terminated, "Termination should succeed"

    status = manager.get_status()
    assert "total_beacons" in status, "Missing total_beacons"

    print("  OK: beacon_lifecycle.py - All tests passed")

except Exception as e:
    errors.append(f"beacon_lifecycle.py: {e}")
    print(f"  FAIL: beacon_lifecycle.py - {e}")

# =============================================================================
# Test 2: c2_observability.py
# =============================================================================
print("\n[2] Testing c2_observability.py...")

try:
    from c2_observability import (
        C2ObservabilityManager,
        BeaconHealthMetrics,
        AnomalyDetector,
        AlertManager,
        Alert,
        OperationalStats,
        NotificationConfig,
        BeaconStatus,
        AlertSeverity,
        AlertType,
        NotificationChannel,
        get_observability_manager,
    )

    metrics = BeaconHealthMetrics(
        beacon_id="test_beacon",
        status=BeaconStatus.ONLINE,
        latency_ms=100.0,
        packet_loss_rate=0.01,
        camouflage_similarity=0.95,
        consecutive_failures=0,
    )
    assert 0 < metrics.health_score <= 1.0, "Health score out of range"

    detector = AnomalyDetector()
    for i in range(20):
        detector.add_data_point("beacon_1", 60.0 + (i % 3))

    is_anomaly = detector.check_anomaly("beacon_1", 60.0)
    assert not is_anomaly, "Normal value should not be anomaly"

    is_anomaly = detector.check_anomaly("beacon_1", 500.0)
    assert is_anomaly, "Extreme value should be anomaly"

    alert_mgr = AlertManager()
    alert = alert_mgr.create_alert(
        AlertType.BEACON_OFFLINE,
        "test_beacon",
        "Test offline alert",
        AlertSeverity.MEDIUM,
    )
    assert alert.alert_type == AlertType.BEACON_OFFLINE, "Alert type mismatch"

    acknowledged = alert_mgr.acknowledge_alert(alert.alert_id)
    assert acknowledged, "Acknowledge should succeed"

    manager = get_observability_manager()
    manager.update_beacon_metrics(
        "test_beacon_2",
        latency_ms=50.0,
        packet_loss=0.0,
        throughput=1024.0,
        camouflage_score=0.9,
        heartbeat_interval=60.0,
    )

    dashboard = manager.get_dashboard()
    assert "total_beacons" in dashboard, "Missing total_beacons"

    status = manager.get_status()
    assert "dashboard" in status, "Missing dashboard"

    print("  OK: c2_observability.py - All tests passed")

except Exception as e:
    errors.append(f"c2_observability.py: {e}")
    print(f"  FAIL: c2_observability.py - {e}")

# =============================================================================
# Test 3: c2_automation.py
# =============================================================================
print("\n[3] Testing c2_automation.py...")

try:
    from c2_automation import (
        C2AutomationManager,
        BeaconAutoScaler,
        IntelligentSleepScheduler,
        FaultRecoveryManager,
        BeaconDeploymentConfig,
        SleepSchedule,
        RecoveryState,
        SubnetDistribution,
        RecoveryStage,
        SleepMode,
        NetworkActivityLevel,
        get_automation_manager,
    )

    config = BeaconDeploymentConfig(
        min_beacons=2,
        max_beacons=10,
        target_beacons=5,
    )
    scaler = BeaconAutoScaler(config)
    scaler.register_beacon("beacon_1", "10.0.1.0/24")
    scaler.register_beacon("beacon_2", "10.0.2.0/24")

    distribution = scaler.get_subnet_distribution()
    assert len(distribution) == 2, "Should have 2 subnets"

    status = scaler.get_status()
    assert status["total_beacons"] == 2, "Beacon count mismatch"

    scheduler = IntelligentSleepScheduler()
    schedule = scheduler.create_schedule(
        "beacon_1",
        base_interval=60.0,
        active_hours=(9, 17),
    )
    assert schedule.base_interval_seconds == 60.0, "Interval mismatch"

    scheduler.update_activity_level("network_1", NetworkActivityLevel.HIGH)
    adjusted = scheduler.adjust_schedule_for_activity("beacon_1", "network_1")
    assert adjusted.mode == SleepMode.ACTIVE, "High activity should be active mode"

    scheduler.update_activity_level("network_1", NetworkActivityLevel.LOW)
    adjusted = scheduler.adjust_schedule_for_activity("beacon_1", "network_1")
    assert adjusted.mode == SleepMode.SILENT, "Low activity should be silent mode"

    interval = scheduler.get_next_interval("beacon_1")
    assert interval > 0, "Interval should be positive"

    recovery_mgr = FaultRecoveryManager()
    state = recovery_mgr.start_recovery("beacon_1")
    assert state.should_retry, "Should be able to retry"
    assert state.current_stage == RecoveryStage.RETRY, "Initial stage mismatch"

    recovery_mgr.cache_data("beacon_1", {"data": "test"})
    cached = recovery_mgr.get_cached_data("beacon_1")
    assert len(cached) == 1, "Should have 1 cached item"

    manager = get_automation_manager()
    mgr_status = manager.get_status()
    assert "auto_scaler" in mgr_status, "Missing auto_scaler"
    assert "sleep_scheduler" in mgr_status, "Missing sleep_scheduler"
    assert "fault_recovery" in mgr_status, "Missing fault_recovery"

    print("  OK: c2_automation.py - All tests passed")

except Exception as e:
    errors.append(f"c2_automation.py: {e}")
    print(f"  FAIL: c2_automation.py - {e}")

# =============================================================================
# Test 4: profile_ide.py
# =============================================================================
print("\n[4] Testing profile_ide.py...")

try:
    from profile_ide import (
        ProfileIDEManager,
        ProfileValidator,
        TrafficComparator,
        SandboxEnvironment,
        ValidationIssue,
        HttpRequestPreview,
        TrafficDifference,
        SimilarityScore,
        SandboxResult,
        ValidationSeverity,
        TrafficDiffType,
        SandboxStatus,
        get_profile_ide_manager,
    )

    validator = ProfileValidator()

    valid_yaml = """
name: Test Profile
version: "1.0"
http:
  method: GET
  headers:
    User-Agent: Mozilla/5.0
heartbeat:
  interval: 60
  jitter: 10
encryption:
  algorithm: aes-256
"""
    issues = validator.validate(valid_yaml)
    error_count = sum(1 for i in issues if i.severity == ValidationSeverity.ERROR)
    assert error_count == 0, f"Valid YAML should have no errors, got {error_count}"

    invalid_yaml = "not: valid: yaml: structure:"
    issues = validator.validate(invalid_yaml)
    assert len(issues) > 0, "Invalid YAML should have issues"

    comparator = TrafficComparator()
    comparator.add_reference_traffic(
        headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*"},
        body="",
        method="GET",
    )

    similarity = comparator.compare(
        profile_headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*"},
        profile_body="",
        profile_method="GET",
    )
    assert similarity.header_score == 1.0, "Headers should match perfectly"

    similarity_mismatch = comparator.compare(
        profile_headers={"User-Agent": "CustomAgent/1.0"},
        profile_body="",
        profile_method="GET",
    )
    assert similarity_mismatch.header_score < 1.0, "Mismatched headers should score lower"

    suggestions = comparator.get_optimization_suggestions(similarity_mismatch)
    assert len(suggestions) > 0, "Should have optimization suggestions"

    sandbox = SandboxEnvironment()

    manager = get_profile_ide_manager()
    manager.set_current_profile(valid_yaml)

    validation = manager.validate_current_profile()
    error_count = sum(1 for i in validation if i.severity == ValidationSeverity.ERROR)
    assert error_count == 0, "Valid profile should have no errors"

    preview = manager.preview_request()
    assert preview.method == "GET", "Method mismatch"
    assert "User-Agent" in preview.headers, "Missing User-Agent"

    ide_status = manager.get_status()
    assert ide_status["profile_loaded"], "Profile should be loaded"

    print("  OK: profile_ide.py - All tests passed")

except Exception as e:
    errors.append(f"profile_ide.py: {e}")
    print(f"  FAIL: profile_ide.py - {e}")

# =============================================================================
# Test 5: profile_marketplace.py
# =============================================================================
print("\n[5] Testing profile_marketplace.py...")

try:
    from profile_marketplace import (
        ProfileMarketplaceManager,
        MarketplaceClient,
        ProfileRegistry,
        ProfileMetadata,
        ProfileStats,
        Review,
        MarketplaceListing,
        Industry,
        Environment,
        Protocol,
        ProfileStatus,
        get_marketplace_manager,
    )

    registry = ProfileRegistry()

    metadata = ProfileMetadata(
        profile_id="test_profile_1",
        name="Test Finance Profile",
        description="A test profile for finance sector",
        author="test_author",
        industry=Industry.FINANCE,
        environment=Environment.ON_PREMISE,
        protocols=[Protocol.HTTPS],
        status=ProfileStatus.PUBLISHED,
    )

    listing = MarketplaceListing(
        metadata=metadata,
        stats=ProfileStats(profile_id="test_profile_1"),
        yaml_content="name: Test",
    )
    registry.add_profile(listing)

    retrieved = registry.get_profile("test_profile_1")
    assert retrieved is not None, "Profile should be retrievable"
    assert retrieved.metadata.industry == Industry.FINANCE, "Industry mismatch"

    finance_profiles = registry.list_profiles(industry=Industry.FINANCE)
    assert len(finance_profiles) == 1, "Should find 1 finance profile"

    registry.record_download("test_profile_1")
    assert listing.stats.download_count == 1, "Download count should be 1"

    client = MarketplaceClient(registry=registry)
    hot_profiles = asyncio.get_event_loop().run_until_complete(
        client.get_hot_profiles(limit=5),
    )
    assert len(hot_profiles) >= 0, "Should return hot profiles"

    rated = asyncio.get_event_loop().run_until_complete(
        client.rate_profile("test_profile_1", rating=4, comment="Good profile", author="tester"),
    )
    assert rated, "Rating should succeed"
    assert listing.stats.rating == 4.0, "Rating should be 4.0"
    assert listing.stats.rating_count == 1, "Rating count should be 1"

    manager = get_marketplace_manager()
    mgr_status = manager.get_status()
    assert "client" in mgr_status, "Missing client"

    print("  OK: profile_marketplace.py - All tests passed")

except Exception as e:
    errors.append(f"profile_marketplace.py: {e}")
    print(f"  FAIL: profile_marketplace.py - {e}")

# =============================================================================
# Test 6: threat_intel.py
# =============================================================================
print("\n[6] Testing threat_intel.py...")

try:
    from threat_intel import (
        ThreatIntelligenceManager,
        ThreatIntelClient,
        DetectionRuleAnalyzer,
        ProfileAutoEvasionEngine,
        IOC,
        DetectionRule,
        EvasionRecommendation,
        ThreatActor,
        IntelFeedConfig,
        IntelSource,
        DetectionRuleType,
        ThreatLevel,
        EvasionStatus,
        get_threat_intel_manager,
    )

    analyzer = DetectionRuleAnalyzer()

    yara_rule = DetectionRule(
        rule_id="test_yara_1",
        rule_type=DetectionRuleType.YARA,
        name="Test YARA Rule",
        content='rule TestRule { strings: $a = "malicious_string" condition: $a }',
        severity=ThreatLevel.HIGH,
        is_active=True,
    )
    analyzer.add_rule(yara_rule)

    profile_config = {
        "http": {
            "headers": {"User-Agent": "malicious_string"},
            "method": "GET",
        },
    }

    risk_score, recommendations = analyzer.analyze_profile_risk(profile_config)
    assert risk_score > 0, "Risk score should be > 0 for matching profile"

    evasion_engine = ProfileAutoEvasionEngine(analyzer)
    result = asyncio.get_event_loop().run_until_complete(
        evasion_engine.apply_evasion(profile_config, recommendations, auto_apply=True),
    )
    assert "original_risk" in result, "Missing original_risk"
    assert "new_risk" in result, "Missing new_risk"

    intel_client = ThreatIntelClient()
    feed_config = IntelFeedConfig(
        source=IntelSource.MISP,
        url="https://misp.example.com",
        api_key="test_key",
    )
    intel_client.add_feed(feed_config)

    ioc = IOC(
        ioc_id="test_ioc_1",
        ioc_type="hash",
        value="abcd1234",
        threat_level=ThreatLevel.HIGH,
        source=IntelSource.MISP,
        confidence=0.9,
    )
    intel_client.add_ioc(ioc)

    iocs = intel_client.get_iocs(min_confidence=0.5)
    assert len(iocs) == 1, "Should find 1 IOC"

    manager = get_threat_intel_manager()
    mgr_status = manager.get_status()
    assert "intel_client" in mgr_status, "Missing intel_client"
    assert "analyzer" in mgr_status, "Missing analyzer"
    assert "evasion_engine" in mgr_status, "Missing evasion_engine"

    print("  OK: threat_intel.py - All tests passed")

except Exception as e:
    errors.append(f"threat_intel.py: {e}")
    print(f"  FAIL: threat_intel.py - {e}")

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
    print("SUCCESS: All final stage modules passed validation!")
    print("=" * 70)
