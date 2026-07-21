from core.models import Alert, BandwidthSample, Host, LatencySample
from storage.store import NetwatchStore


def _store(tmp_path):
    return NetwatchStore(str(tmp_path / "netwatch.db"))


def test_schema_creates_cleanly(tmp_path):
    store = _store(tmp_path)
    assert store.hosts() == []
    store.close()


def test_upsert_host_is_idempotent(tmp_path):
    store = _store(tmp_path)
    store.upsert_host(Host(ip="10.0.0.1", mac="aa:bb", first_seen=1.0, last_seen=1.0, status="up"))
    store.upsert_host(Host(ip="10.0.0.1", mac="aa:bb", first_seen=1.0, last_seen=2.0, status="up"))
    hosts = store.hosts()
    assert len(hosts) == 1
    assert hosts[0]["last_seen"] == 2.0
    store.close()


def test_upsert_host_keeps_hostname_when_new_is_blank(tmp_path):
    store = _store(tmp_path)
    store.upsert_host(Host(ip="10.0.0.1", hostname="router", first_seen=1.0, last_seen=1.0))
    store.upsert_host(Host(ip="10.0.0.1", hostname="", first_seen=1.0, last_seen=2.0))
    assert store.hosts()[0]["hostname"] == "router"
    store.close()


def test_log_latency_and_history(tmp_path):
    store = _store(tmp_path)
    store.log_latency(LatencySample(ip="10.0.0.1", ts=1.0, rtt_ms=12.5, method="tcp"))
    store.log_latency(LatencySample(ip="10.0.0.1", ts=2.0, rtt_ms=None, method="tcp"))
    history = store.latency_history("10.0.0.1")
    assert len(history) == 2
    assert history[0]["ts"] == 1.0
    assert history[1]["rtt_ms"] is None
    store.close()


def test_log_bandwidth_and_history(tmp_path):
    store = _store(tmp_path)
    store.log_bandwidth(BandwidthSample(iface="eth0", ts=1.0, rx_bytes=100, tx_bytes=50, rx_bps=10.0, tx_bps=5.0))
    history = store.bandwidth_history("eth0")
    assert len(history) == 1
    assert history[0]["rx_bps"] == 10.0
    store.close()


def test_log_alert_and_recent(tmp_path):
    store = _store(tmp_path)
    store.log_alert(Alert(kind="host_down", severity="high", target="10.0.0.1", detail="down", ts=1.0))
    alerts = store.recent_alerts()
    assert len(alerts) == 1
    assert alerts[0]["kind"] == "host_down"
    store.close()


def test_stats_aggregation(tmp_path):
    store = _store(tmp_path)
    store.upsert_host(Host(ip="10.0.0.1", first_seen=1.0, last_seen=1.0, status="up"))
    store.upsert_host(Host(ip="10.0.0.2", first_seen=1.0, last_seen=1.0, status="down"))
    store.log_latency(LatencySample(ip="10.0.0.1", ts=1.0, rtt_ms=10.0, method="tcp"))
    store.log_latency(LatencySample(ip="10.0.0.1", ts=2.0, rtt_ms=20.0, method="tcp"))
    store.log_alert(Alert(kind="host_down", severity="high", target="10.0.0.2", detail="down", ts=1.0))

    stats = store.stats()
    assert stats["total_hosts"] == 2
    assert stats["hosts_up"] == 1
    assert stats["hosts_down"] == 1
    assert stats["latency_samples"] == 2
    assert stats["avg_rtt_ms"] == 15.0
    assert stats["alert_count"] == 1
    assert stats["alerts_by_kind"] == {"host_down": 1}
    store.close()


def test_stats_with_no_data(tmp_path):
    store = _store(tmp_path)
    stats = store.stats()
    assert stats["total_hosts"] == 0
    assert stats["avg_rtt_ms"] is None
    store.close()
