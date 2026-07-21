from core.config import DetectConfig
from core.models import BandwidthSample, Host, LatencySample
from detect.alerts import AlertDetector


def _cfg(**overrides) -> DetectConfig:
    base = dict(
        down_after_missed=3,
        latency_baseline_window=20,
        latency_spike_multiplier=3.0,
        latency_spike_min_samples=5,
        bandwidth_baseline_window=20,
        bandwidth_spike_multiplier=3.0,
        bandwidth_spike_min_samples=5,
        arp_flap_window=60.0,
        alert_cooldown=30.0,
    )
    base.update(overrides)
    return DetectConfig(**base)


# --- host down / recovered -------------------------------------------------

def test_host_down_fires_exactly_at_threshold():
    det = AlertDetector(_cfg(down_after_missed=3))
    alerts = []
    for i in range(3):
        alerts += det.on_latency_sample(LatencySample(ip="10.0.0.1", ts=float(i), rtt_ms=None, method="tcp"))
    kinds = [a.kind for a in alerts]
    assert kinds.count("host_down") == 1


def test_no_host_down_one_miss_short_of_threshold():
    det = AlertDetector(_cfg(down_after_missed=3))
    alerts = []
    for i in range(2):
        alerts += det.on_latency_sample(LatencySample(ip="10.0.0.1", ts=float(i), rtt_ms=None, method="tcp"))
    assert alerts == []


def test_host_recovered_fires_once_after_down():
    det = AlertDetector(_cfg(down_after_missed=2))
    for i in range(2):
        det.on_latency_sample(LatencySample(ip="10.0.0.1", ts=float(i), rtt_ms=None, method="tcp"))
    alerts = det.on_latency_sample(LatencySample(ip="10.0.0.1", ts=10.0, rtt_ms=5.0, method="tcp"))
    assert [a.kind for a in alerts] == ["host_recovered"]


def test_no_recovered_alert_when_never_down():
    det = AlertDetector(_cfg())
    alerts = det.on_latency_sample(LatencySample(ip="10.0.0.1", ts=0.0, rtt_ms=5.0, method="tcp"))
    assert alerts == []


def test_host_down_cooldown_suppresses_repeat():
    det = AlertDetector(_cfg(down_after_missed=1, alert_cooldown=100.0))
    first = det.on_latency_sample(LatencySample(ip="10.0.0.1", ts=0.0, rtt_ms=None, method="tcp"))
    # Recover then go down again quickly, still inside the cooldown window.
    det.on_latency_sample(LatencySample(ip="10.0.0.1", ts=1.0, rtt_ms=5.0, method="tcp"))
    second = det.on_latency_sample(LatencySample(ip="10.0.0.1", ts=2.0, rtt_ms=None, method="tcp"))
    assert len(first) == 1
    assert all(a.kind != "host_down" for a in second)


# --- latency spike -----------------------------------------------------------

def test_latency_spike_fires_above_baseline():
    det = AlertDetector(_cfg(latency_spike_min_samples=5, latency_spike_multiplier=3.0))
    for i in range(5):
        det.on_latency_sample(LatencySample(ip="10.0.0.1", ts=float(i), rtt_ms=10.0, method="tcp"))
    alerts = det.on_latency_sample(LatencySample(ip="10.0.0.1", ts=6.0, rtt_ms=100.0, method="tcp"))
    assert [a.kind for a in alerts] == ["latency_spike"]


def test_no_latency_spike_for_normal_jitter():
    det = AlertDetector(_cfg(latency_spike_min_samples=5, latency_spike_multiplier=3.0))
    for i in range(5):
        det.on_latency_sample(LatencySample(ip="10.0.0.1", ts=float(i), rtt_ms=10.0, method="tcp"))
    alerts = det.on_latency_sample(LatencySample(ip="10.0.0.1", ts=6.0, rtt_ms=15.0, method="tcp"))
    assert alerts == []


def test_no_latency_spike_before_enough_baseline_samples():
    det = AlertDetector(_cfg(latency_spike_min_samples=5, latency_spike_multiplier=3.0))
    for i in range(3):
        det.on_latency_sample(LatencySample(ip="10.0.0.1", ts=float(i), rtt_ms=10.0, method="tcp"))
    alerts = det.on_latency_sample(LatencySample(ip="10.0.0.1", ts=4.0, rtt_ms=1000.0, method="tcp"))
    assert alerts == []


# --- bandwidth spike ----------------------------------------------------------

def test_bandwidth_spike_fires_above_baseline():
    det = AlertDetector(_cfg(bandwidth_spike_min_samples=5, bandwidth_spike_multiplier=3.0))
    for i in range(5):
        det.on_bandwidth_sample(
            BandwidthSample(iface="eth0", ts=float(i), rx_bytes=0, tx_bytes=0, rx_bps=1000.0, tx_bps=500.0)
        )
    alerts = det.on_bandwidth_sample(
        BandwidthSample(iface="eth0", ts=6.0, rx_bytes=0, tx_bytes=0, rx_bps=10000.0, tx_bps=500.0)
    )
    assert [a.kind for a in alerts] == ["bandwidth_spike"]


def test_no_bandwidth_spike_for_normal_variation():
    det = AlertDetector(_cfg(bandwidth_spike_min_samples=5, bandwidth_spike_multiplier=3.0))
    for i in range(5):
        det.on_bandwidth_sample(
            BandwidthSample(iface="eth0", ts=float(i), rx_bytes=0, tx_bytes=0, rx_bps=1000.0, tx_bps=500.0)
        )
    alerts = det.on_bandwidth_sample(
        BandwidthSample(iface="eth0", ts=6.0, rx_bytes=0, tx_bytes=0, rx_bps=1200.0, tx_bps=550.0)
    )
    assert alerts == []


# --- ARP spoof / MAC flap -----------------------------------------------------

def test_no_alert_on_first_ever_sighting():
    det = AlertDetector(_cfg())
    alerts = det.on_discovery([Host(ip="10.0.0.1", mac="aa:aa:aa:aa:aa:01")])
    assert alerts == []


def test_one_time_mac_change_is_low_severity():
    times = iter([0.0, 5.0])
    det = AlertDetector(_cfg(), clock=lambda: next(times))
    det.on_discovery([Host(ip="10.0.0.1", mac="aa:aa:aa:aa:aa:01")])
    alerts = det.on_discovery([Host(ip="10.0.0.1", mac="aa:aa:aa:aa:aa:02")])
    assert len(alerts) == 1
    assert alerts[0].kind == "arp_spoof"
    assert alerts[0].severity == "low"


def test_mac_flap_within_window_escalates_to_high():
    times = iter([0.0, 5.0, 10.0])
    det = AlertDetector(_cfg(arp_flap_window=60.0), clock=lambda: next(times))
    det.on_discovery([Host(ip="10.0.0.1", mac="aa:aa:aa:aa:aa:01")])
    det.on_discovery([Host(ip="10.0.0.1", mac="aa:aa:aa:aa:aa:02")])
    alerts = det.on_discovery([Host(ip="10.0.0.1", mac="aa:aa:aa:aa:aa:01")])
    assert len(alerts) == 1
    assert alerts[0].kind == "arp_spoof"
    assert alerts[0].severity == "high"


def test_mac_flap_outside_window_does_not_escalate():
    times = iter([0.0, 5.0, 1000.0])
    det = AlertDetector(_cfg(arp_flap_window=60.0), clock=lambda: next(times))
    det.on_discovery([Host(ip="10.0.0.1", mac="aa:aa:aa:aa:aa:01")])
    det.on_discovery([Host(ip="10.0.0.1", mac="aa:aa:aa:aa:aa:02")])
    alerts = det.on_discovery([Host(ip="10.0.0.1", mac="aa:aa:aa:aa:aa:01")])
    assert alerts[0].severity == "low"


def test_hosts_without_mac_are_skipped():
    det = AlertDetector(_cfg())
    det.on_discovery([Host(ip="10.0.0.1", mac="")])
    alerts = det.on_discovery([Host(ip="10.0.0.1", mac="")])
    assert alerts == []


def test_stable_mac_never_alerts():
    det = AlertDetector(_cfg())
    for _ in range(5):
        alerts = det.on_discovery([Host(ip="10.0.0.1", mac="aa:aa:aa:aa:aa:01")])
    assert alerts == []


def test_arp_spoof_high_severity_escalation_not_suppressed_by_low_cooldown():
    # A low-severity change should not block the high-severity escalation
    # that follows shortly after, even though both share the same target key.
    times = iter([0.0, 1.0, 2.0])
    det = AlertDetector(_cfg(arp_flap_window=60.0, alert_cooldown=100.0), clock=lambda: next(times))
    det.on_discovery([Host(ip="10.0.0.1", mac="aa:aa:aa:aa:aa:01")])
    low_alerts = det.on_discovery([Host(ip="10.0.0.1", mac="aa:aa:aa:aa:aa:02")])
    high_alerts = det.on_discovery([Host(ip="10.0.0.1", mac="aa:aa:aa:aa:aa:01")])
    assert low_alerts[0].severity == "low"
    assert high_alerts[0].severity == "high"
