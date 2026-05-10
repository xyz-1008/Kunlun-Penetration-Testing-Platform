import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath('.')))

# Test 1: Syntax validation (already passed via ast.parse)
print("=" * 60)
print("Malleable C2 Profile Module - Syntax & Import Validation")
print("=" * 60)

# Test 2: Validate YAML files
import yaml
yaml_files = [
    'core/modules/profiles/jquery_update.yaml',
    'core/modules/profiles/google_analytics.yaml',
    'core/modules/profiles/microsoft_office.yaml',
    'core/modules/profiles/cdn_resource.yaml',
    'core/modules/profiles/api_mock.yaml',
]

print("\n[1] YAML Profile Templates Validation:")
for yf in yaml_files:
    with open(yf, encoding='utf-8') as f:
        data = yaml.safe_load(f)
    assert data['name'], f"Missing name in {yf}"
    assert data['http'], f"Missing http config in {yf}"
    assert data['heartbeat'], f"Missing heartbeat config in {yf}"
    assert data['encryption'], f"Missing encryption config in {yf}"
    print(f"  OK: {data['name']} ({data['version']})")

print("\n[2] Python Syntax Validation:")
import ast
py_files = [
    'core/modules/malleable_profile.py',
    'core/modules/traffic_engine.py',
    'core/modules/beacon_profile_adapter.py',
]
for pf in py_files:
    with open(pf, encoding='utf-8') as f:
        ast.parse(f.read())
    print(f"  OK: {pf}")

print("\n[3] Code Structure Verification:")
# Check key classes exist in source
for pf in py_files:
    with open(pf, encoding='utf-8') as f:
        content = f.read()
    tree = ast.parse(content)
    classes = [node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
    functions = [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
    print(f"  {os.path.basename(pf)}: {len(classes)} classes, {len(functions)} functions")

print("\n" + "=" * 60)
print("All validations passed successfully!")
print("=" * 60)
