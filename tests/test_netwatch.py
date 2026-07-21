import argparse

from core.config import DetectConfig, DiscoveryConfig, MonitorConfig, NetwatchConfig
from monitor.bandwidth import BandwidthMonitor
from monitor.latency import Prober
from netwatch import NetWatch, build_config
from storage.store import NetwatchStore


def _config(tmp_path, **overrides):
    cfg = NetwatchConfig(
        discovery=DiscoveryConfig(static_hosts=["10.0.0.1", "10.0.0.2"], interval_seconds=9999),
        monitor=MonitorConfig(method="tcp", interval_seconds=0.0),
        detect=DetectConfig(down_after_missed=2, latency_spike_min_samples=3),
        data_dir=str(tmp_path),
        db_path=str(tmp_path / "netwatch.db"),
    )
    for key, value in overrides.items():
        setattr(cfg, key, value)
    return cfg


def _engine(tmp_path, rtts, bandwidth_snapshots=None):
    config = _config(tmp_path)
    prober = Prober(send_fn=lambda ip, timeout: rtts.get(ip), clock=lambda: 1.0)
    snapshots = iter(bandwidth_snapshots or [{}])
    bandwidth = BandwidthMonitor(counters_fn=lambda: next(snapshots, {}), clock=lambda: 1.0)
    alerts_seen = []
    engine = NetWatch(
        config,
        store=NetwatchStore(config.db_path),
        prober=prober,
        bandwidth=bandwidth,
        on_alert=alerts_seen.append,
    )
    return engine, alerts_seen


def test_discover_populates_hosts_and_store(tmp_path):
    engine, _ = _engine(tmp_path, rtts={})
    hosts = engine.discover()
    assert {h.ip for h in hosts} == {"10.0.0.1", "10.0.0.2"}
    assert {h["ip"] for h in engine.store.hosts()} == {"10.0.0.1", "10.0.0.2"}
    engine.close()


def test_probe_all_logs_latency_and_updates_status(tmp_path):
    engine, _ = _engine(tmp_path, rtts={"10.0.0.1": 5.0, "10.0.0.2": None})
    engine.discover()
    engine.probe_all()
    assert engine.hosts["10.0.0.1"].status == "up"
    history = engine.store.latency_history("10.0.0.1")
    assert history[0]["rtt_ms"] == 5.0
    engine.close()


def test_probe_all_fires_host_down_alert_end_to_end(tmp_path):
    engine, alerts_seen = _engine(tmp_path, rtts={"10.0.0.1": None, "10.0.0.2": None})
    engine.discover()
    engine.probe_all()  # miss 1
    engine.probe_all()  # miss 2 -> down_after_missed=2

    kinds = [a.kind for a in alerts_seen]
    assert "host_down" in kinds
    assert engine.hosts["10.0.0.1"].status == "down"
    stored_alerts = [row["kind"] for row in engine.store.recent_alerts()]
    assert "host_down" in stored_alerts
    engine.close()


def test_sample_bandwidth_logs_samples(tmp_path):
    engine, _ = _engine(
        tmp_path,
        rtts={},
        bandwidth_snapshots=[{"eth0": (100, 50)}, {"eth0": (200, 100)}],
    )
    engine.sample_bandwidth()
    engine.sample_bandwidth()
    history = engine.store.bandwidth_history("eth0")
    assert len(history) == 2
    engine.close()


def test_run_forever_stops_on_flag_and_ticks_without_real_sleep(tmp_path):
    engine, _ = _engine(tmp_path, rtts={"10.0.0.1": 1.0, "10.0.0.2": 1.0})
    ticks = {"n": 0}
    sleeps = []

    def stop_flag():
        ticks["n"] += 1
        return ticks["n"] > 2

    engine.run_forever(stop_flag=stop_flag, sleep_fn=sleeps.append, clock=lambda: 1.0)

    assert len(sleeps) == 2
    assert len(engine.store.latency_history("10.0.0.1")) == 2
    engine.close()


def test_hosts_latency_bandwidth_callbacks_fire(tmp_path):
    config = _config(tmp_path)
    prober = Prober(send_fn=lambda ip, timeout: 5.0, clock=lambda: 1.0)
    snapshots = iter([{"eth0": (100, 50)}])
    bandwidth = BandwidthMonitor(counters_fn=lambda: next(snapshots, {}), clock=lambda: 1.0)

    seen_hosts, seen_latency, seen_bandwidth = [], [], []
    engine = NetWatch(
        config,
        store=NetwatchStore(config.db_path),
        prober=prober,
        bandwidth=bandwidth,
        on_hosts=seen_hosts.append,
        on_latency=seen_latency.append,
        on_bandwidth=seen_bandwidth.append,
    )

    engine.discover()
    engine.probe_all()
    engine.sample_bandwidth()

    assert len(seen_hosts) == 1 and len(seen_hosts[0]) == 2
    assert len(seen_latency) == 2
    assert len(seen_bandwidth) == 1
    engine.close()


def test_build_config_from_static_hosts_file(tmp_path):
    hosts_file = tmp_path / "hosts.json"
    hosts_file.write_text('["10.0.0.1", "10.0.0.2"]')
    db_path = tmp_path / "out.db"

    args = argparse.Namespace(
        static_hosts_file=str(hosts_file),
        cidr=None,
        method="tcp",
        tcp_port=8080,
        interval=2.0,
        db=str(db_path),
        iface=None,
    )
    config = build_config(args)
    assert config.discovery.static_hosts == ["10.0.0.1", "10.0.0.2"]
    assert config.monitor.tcp_port == 8080
    assert config.db_path == str(db_path)


def test_build_config_defaults_without_args():
    args = argparse.Namespace()
    config = build_config(args)
    assert config.discovery.static_hosts == []
    assert config.monitor.method == "tcp"
