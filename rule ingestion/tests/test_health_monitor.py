from app.services.health_monitor import HealthMonitor


def test_healthy_connector():
    monitor = HealthMonitor()
    monitor.register_connector("test-1", "TestVendor", "TestProduct")

    monitor.record_query("test-1", 0.5, True)
    monitor.record_query("test-1", 1.0, True)

    health = monitor.get_health("test-1")

    assert health is not None
    assert health.availability == 100.0
    assert health.error_rate == 0.0
    assert health.avg_latency == 0.75
    assert health.health_score == 100.0
    assert health.status == "Green"


def test_error_rate_affects_health_score():
    monitor = HealthMonitor()
    monitor.register_connector("test-2", "TestVendor", "TestProduct")

    monitor.record_query("test-2", 1.0, True)
    monitor.record_query("test-2", 1.0, False)

    health = monitor.get_health("test-2")

    assert health is not None
    assert health.error_rate == 50.0
    assert health.availability == 50.0
    assert health.health_score == 55.0
    assert health.status == "Amber"


def test_high_latency_affects_health_score():
    monitor = HealthMonitor()
    monitor.register_connector("test-3", "TestVendor", "TestProduct")

    monitor.record_query("test-3", 4.0, True)

    health = monitor.get_health("test-3")

    assert health is not None
    assert health.avg_latency == 4.0
    assert health.health_score == 90.0
    assert health.status == "Green"


def test_unavailable_connector():
    monitor = HealthMonitor()
    monitor.register_connector("test-4", "TestVendor", "TestProduct")

    monitor.record_connection_status("test-4", False)

    health = monitor.get_health("test-4")

    assert health is not None
    assert health.availability == 0.0
    assert health.health_score == 20.0
    assert health.status == "Red"


def test_all_connector_health():
    monitor = HealthMonitor()
    monitor.register_connector("test-1", "VendorA", "ProductA")
    monitor.register_connector("test-2", "VendorB", "ProductB")

    health = monitor.get_all_health()

    assert len(health) == 2
    assert {item.connector_id for item in health} == {"test-1", "test-2"}
