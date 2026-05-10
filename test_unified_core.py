"""
统一后端核心测试
测试所有核心组件功能
"""

import sys
import os
import threading
from pathlib import Path
import tempfile
import shutil

# 添加项目路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


def test_event_bus():
    """测试事件总线"""
    print("\n" + "=" * 60)
    print("测试 1: 事件总线")
    print("=" * 60)
    
    from core.event_bus import EventBus, EventPriority
    
    bus = EventBus()
    received_events = []
    
    def on_test_event(event):
        received_events.append(event)
    
    # 订阅事件
    bus.subscribe("test.event", on_test_event)
    bus.subscribe("test.event", lambda e: None, priority=EventPriority.HIGH)
    bus.subscribe("other.event", lambda e: None)
    
    # 发布事件
    bus.publish("test.event", "test_source", {"key": "value"})
    bus.publish("test.event", "test_source", {"key": "value2"})
    
    assert len(received_events) == 2, f"应收到2个事件，实际收到{len(received_events)}个"
    
    # 测试事件历史
    history = bus.get_event_history("test.event")
    assert len(history) == 2, f"历史应有2个事件，实际{len(history)}个"
    
    # 测试统计
    stats = bus.get_stats()
    assert stats['total_events'] == 2
    assert stats['subscriber_count'] == 3
    
    print("✓ 事件订阅/发布正常")
    print("✓ 事件历史记录正常")
    print("✓ 事件统计正常")
    print("✓ 事件总线测试通过")
    
    return True


def test_data_bus():
    """测试数据总线"""
    print("\n" + "=" * 60)
    print("测试 2: 数据总线")
    print("=" * 60)
    
    from core.data_bus import DataBus, Base
    from sqlalchemy import Column, Integer, String
    
    # 创建临时数据库
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_databus.db")
    
    try:
        # 定义测试模型（使用唯一表名避免冲突）
        class TestModel(Base):
            __tablename__ = 'test_models_databus'
            id = Column(Integer, primary_key=True)
            name = Column(String(100))
        
        # 初始化数据总线
        data_bus = DataBus(db_path)
        data_bus.register_model("test", TestModel)
        data_bus.create_all_tables()
        
        # 测试写入
        def write_test(session):
            obj = TestModel(name="test_data")
            session.add(obj)
            session.flush()
            return obj.id
        
        obj_id = data_bus.execute_write(write_test)
        assert obj_id is not None, "写入应返回对象ID"
        
        # 测试读取
        def read_test(session):
            result = session.query(TestModel).filter_by(name="test_data").first()
            if result:
                # 在会话内访问属性，避免detached state
                return {"id": result.id, "name": result.name}
            return None
        
        result = data_bus.execute_query(read_test)
        assert result is not None, "应能读取到数据"
        assert result['name'] == "test_data", f"名称应为'test_data'，实际为'{result['name']}'"
        
        # 测试统计
        stats = data_bus.get_stats()
        assert stats['model_count'] == 1
        assert stats['connection_active'] is True
        
        print("✓ 数据库连接正常")
        print("✓ 数据写入正常")
        print("✓ 数据读取正常")
        print("✓ 数据库统计正常")
        print("✓ 数据总线测试通过")
        
        data_bus.close()
        return True
        
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_module_registry():
    """测试模块注册中心"""
    print("\n" + "=" * 60)
    print("测试 3: 模块注册中心")
    print("=" * 60)
    
    from core.module_registry import ModuleRegistry, ModuleState
    
    registry = ModuleRegistry()
    
    # 创建模拟模块
    class MockModule:
        def __init__(self, name):
            self.name = name
            self.initialized = False
        
        def initialize(self, **kwargs):
            self.initialized = True
        
        def get_status_info(self):
            return {"name": self.name, "initialized": self.initialized}
    
    # 注册模块
    module_a = MockModule("ModuleA")
    module_b = MockModule("ModuleB")
    
    registry.register("module_a", module_a)
    registry.register("module_b", module_b, dependencies=["module_a"])
    
    # 测试获取模块
    assert registry.get_module("module_a") is module_a
    assert registry.get_module("module_b") is module_b
    
    # 测试初始化
    registry.initialize_module("module_a")
    assert module_a.initialized is True
    
    registry.initialize_module("module_b")
    assert module_b.initialized is True
    
    # 测试统计
    stats = registry.get_stats()
    assert stats['total_modules'] == 2
    assert stats['active_modules'] == 2
    
    print("✓ 模块注册正常")
    print("✓ 模块依赖检查正常")
    print("✓ 模块初始化正常")
    print("✓ 模块统计正常")
    print("✓ 模块注册中心测试通过")
    
    return True


def test_application():
    """测试应用单例"""
    print("\n" + "=" * 60)
    print("测试 4: 应用单例")
    print("=" * 60)
    
    from core.application import Application, get_app, initialize_app
    
    # 重置Application单例
    Application._instance = None
    Application._lock = threading.Lock()
    
    # 创建临时目录
    temp_dir = tempfile.mkdtemp()
    
    try:
        # 初始化应用
        app = initialize_app(project_root=temp_dir)
        
        # 测试单例
        app2 = get_app()
        assert app is app2, "应用应为单例"
        
        # 测试状态
        assert app.is_running() is True
        assert app.get_project_root() == Path(temp_dir)
        
        # 测试模块注册
        class TestModule:
            def __init__(self):
                self.initialized = False
            
            def initialize(self, **kwargs):
                self.initialized = True
            
            def test_service(self, data):
                return f"Processed: {data}"
            
            def get_status_info(self):
                return {"initialized": self.initialized}
        
        test_module = TestModule()
        app.register_module("test_module", test_module)
        
        # 测试模块初始化
        app.initialize_module("test_module")
        assert test_module.initialized is True
        
        # 测试服务调用
        result = app.call_module_service("test_module", "test_service", "hello")
        assert result == "Processed: hello"
        
        # 测试事件发布订阅
        received = []
        app.subscribe_event("test.event", lambda e: received.append(e))
        app.publish_event("test.event", "test", {"data": "value"})
        assert len(received) == 1
        
        # 测试UI回调
        ui_received = []
        app.register_ui_callback("ui.update", lambda d: ui_received.append(d))
        app.notify_ui("ui.update", {"key": "value"})
        assert len(ui_received) == 1
        
        # 测试统计
        stats = app.get_comprehensive_stats()
        assert 'application' in stats
        assert 'modules' in stats
        assert 'database' in stats
        assert 'events' in stats
        
        print("✓ 应用单例正常")
        print("✓ 模块注册和初始化正常")
        print("✓ 服务调用正常")
        print("✓ 事件发布订阅正常")
        print("✓ UI回调正常")
        print("✓ 应用统计正常")
        print("✓ 应用单例测试通过")
        
        # 关闭应用
        app.shutdown()
        assert app.is_running() is False
        
        return True
        
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_integration():
    """测试集成场景"""
    print("\n" + "=" * 60)
    print("测试 5: 集成场景")
    print("=" * 60)
    
    from core.application import Application, initialize_app
    
    # 重置Application单例
    Application._instance = None
    Application._lock = threading.Lock()
    
    temp_dir = tempfile.mkdtemp()
    
    try:
        # 初始化应用
        app = initialize_app(project_root=temp_dir)
        
        # 模拟模块间通信场景
        # 1. 资产模块发现新资产
        # 2. 发布事件
        # 3. 漏洞模块订阅并处理
        
        asset_found = []
        vuln_processed = []
        
        def on_asset_discovered(event):
            asset_found.append(event.data)
            # 触发漏洞扫描
            app.publish_event(
                "vuln.scan.request",
                "asset_module",
                {"target": event.data.get('domain'), "asset_id": event.data.get('id')}
            )
        
        def on_vuln_scan(event):
            vuln_processed.append(event.data)
        
        app.subscribe_event("asset.discovered", on_asset_discovered)
        app.subscribe_event("vuln.scan.request", on_vuln_scan)
        
        # 模拟资产发现
        app.publish_event(
            "asset.discovered",
            "scanner_module",
            {"id": "asset_001", "domain": "example.com", "ip": "192.168.1.1"}
        )
        
        assert len(asset_found) == 1
        assert len(vuln_processed) == 1
        assert vuln_processed[0]['target'] == "example.com"
        
        # 测试数据共享
        from core.data_bus import Base
        from sqlalchemy import Column, Integer, String
        
        class AssetModel(Base):
            __tablename__ = 'assets_test'
            id = Column(Integer, primary_key=True)
            domain = Column(String(255))
            ip = Column(String(50))
        
        app.data_bus.register_model("asset", AssetModel)
        # 注意：不要重复调用create_all_tables()，因为应用初始化时已调用
        # 使用execute_write来创建表
        def create_table(session):
            from sqlalchemy import inspect
            inspector = inspect(session.bind)
            if 'assets_test' not in inspector.get_table_names():
                AssetModel.__table__.create(session.bind)
        
        try:
            app.data_bus.execute_write(create_table)
        except:
            pass  # 表可能已存在
        
        def add_asset(session):
            asset = AssetModel(domain="test.com", ip="10.0.0.1")
            session.add(asset)
            session.flush()
            return asset.id
        
        asset_id = app.data_bus.execute_write(add_asset)
        
        def get_asset(session):
            asset = session.query(AssetModel).filter_by(id=asset_id).first()
            if asset:
                return {"id": asset.id, "domain": asset.domain, "ip": asset.ip}
            return None
        
        asset = app.data_bus.execute_query(get_asset)
        assert asset['domain'] == "test.com"
        
        print("✓ 模块间事件通信正常")
        print("✓ 事件链式触发正常")
        print("✓ 数据共享正常")
        print("✓ 集成场景测试通过")
        
        app.shutdown()
        return True
        
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def main():
    """运行所有测试"""
    print("\n" + "=" * 60)
    print("统一后端核心测试")
    print("=" * 60)
    
    tests = [
        ("事件总线", test_event_bus),
        ("数据总线", test_data_bus),
        ("模块注册中心", test_module_registry),
        ("应用单例", test_application),
        ("集成场景", test_integration),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n✗ {name} 测试异常: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))
    
    # 汇总结果
    print("\n" + "=" * 60)
    print("测试汇总")
    print("=" * 60)
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    for name, result in results:
        status = "✓ 通过" if result else "✗ 失败"
        print(f"  {status}: {name}")
    
    print(f"\n总计: {passed}/{total} 通过")
    
    if passed == total:
        print("\n🎉 所有测试通过！")
    else:
        print(f"\n⚠ {total - passed} 个测试失败")
    
    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
