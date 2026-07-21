from core.models import Alert, BandwidthSample, Host, LatencySample


def test_host_to_dict_and_defaults():
    host = Host(ip="10.0.0.1")
    d = host.to_dict()
    assert d == {
        "ip": "10.0.0.1",
        "mac": "",
        "hostname": "",
        "first_seen": 0.0,
        "last_seen": 0.0,
        "status": "unknown",
    }


def test_latency_sample_round_trip():
    sample = LatencySample(ip="10.0.0.1", ts=1.0, rtt_ms=12.5, method="tcp")
    assert sample.to_dict() == {"ip": "10.0.0.1", "ts": 1.0, "rtt_ms": 12.5, "method": "tcp"}


def test_latency_sample_timeout_is_none():
    sample = LatencySample(ip="10.0.0.1", ts=1.0, rtt_ms=None, method="icmp")
    assert sample.to_dict()["rtt_ms"] is None


def test_bandwidth_sample_round_trip():
    sample = BandwidthSample(iface="eth0", ts=1.0, rx_bytes=100, tx_bytes=50, rx_bps=1.0, tx_bps=2.0)
    assert sample.to_dict()["iface"] == "eth0"


def test_alert_default_ts_is_populated():
    alert = Alert(kind="host_down", severity="high", target="10.0.0.1", detail="down")
    assert alert.ts > 0


def test_alert_explicit_ts_is_kept():
    alert = Alert(kind="host_down", severity="high", target="10.0.0.1", detail="down", ts=42.0)
    assert alert.ts == 42.0
