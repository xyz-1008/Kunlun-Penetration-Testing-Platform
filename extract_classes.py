import re
from pathlib import Path

modules_dir = Path(r"d:\ai项目\测试项目\开发\渗透测试工具1.0.1\AutoPenTest_Desktop\core\modules")

unregistered = [
    "asset_manager", "extender", "fingerprint_matcher", "malleable_profile",
    "mitm_diagnostics", "mitm_fuzzer_integration", "mitm_h2_advanced",
    "mitm_h3_advanced", "mitm_lateral_movement", "mitm_mobile_support",
    "mitm_performance", "mitm_protocol_negotiator", "mitm_replay_fuzzer",
    "mitm_reverse_integration", "mitm_reverse_linkage", "mitm_security",
    "mitm_security_audit", "mitm_traffic_collaboration", "mitm_vuln_linkage",
    "nuclei_helpers", "nuclei_models", "plugin_debugger", "plugin_dependency",
    "plugin_engine", "plugin_management_ui", "plugin_manager", "plugin_market",
    "plugin_market_ops", "plugin_sandbox", "plugin_security", "poc_engine",
    "poc_verification_manager", "poc_verification_ui", "pqc_crypto",
    "process_mask", "profile_generator", "profile_ide", "profile_marketplace",
    "profile_tester", "protobuf_decoder", "protobuf_schema", "quic_connection_pool",
    "quic_protocol", "quic_tls", "range_deployer", "range_integration",
    "range_manager", "rasp_waf_bypass", "report_generator", "result_models",
    "sandbox_executor", "scanner", "self_destruct", "self_healing_c2",
    "session_mfa_bypass", "shadow_credentials", "shiro_exploit", "siem_evasion",
    "skeleton_key", "skill_evaluator", "ssp_backdoor", "supply_chain_hijack",
    "swarm_intelligence", "template_ai_generator", "template_analytics",
    "template_audit", "template_commerce", "template_editor", "template_executor",
    "template_incentive", "template_integration", "template_marketplace",
    "template_recorder", "template_replay", "template_validator", "test_ai_security",
    "threat_intel", "tls_fingerprint", "token_lifecycle", "traffic_engine",
    "traffic_learner", "updater_checker", "updater_downloader", "updater_installer",
    "updater_plugin", "updater_ui", "updater_version", "vuln_manager",
    "weblogic_exploit", "wireless_ble_scanner", "workflow_editor", "workflow_engine"
]

# Extract main class from each module
for mod_name in sorted(unregistered):
    py_file = modules_dir / f"{mod_name}.py"
    if not py_file.exists():
        print(f"# SKIP: {mod_name} (file not found)")
        continue
    
    content = py_file.read_text(encoding='utf-8')
    
    # Find class definitions, skip BaseModel, Enum, etc.
    classes = re.findall(r'^class\s+(\w+)\s*[\(:]', content, re.MULTILINE)
    
    # Filter out non-module classes
    skip_patterns = ['BaseModel', 'Enum', 'Config', 'Settings', 'Info', 'Result', 
                     'Request', 'Response', 'Status', 'Type', 'Level', 'Mode',
                     'State', 'Action', 'Event', 'Message', 'Data', 'Node', 'Edge']
    
    main_class = None
    for cls in classes:
        if any(skip in cls for skip in skip_patterns):
            continue
        if cls.lower().startswith(mod_name.replace('_', '')):
            main_class = cls
            break
    
    if not main_class and classes:
        # Take the first class that doesn't look like a model
        for cls in classes:
            if not any(skip in cls for skip in skip_patterns):
                main_class = cls
                break
    
    if not main_class:
        main_class = classes[0] if classes else f"{mod_name.title().replace('_', '')}"
    
    print(f"{mod_name}: {main_class}")
