from monitor.bandwidth import BandwidthMonitor


def test_first_sample_for_new_iface_yields_zero_bps():
    monitor = BandwidthMonitor(counters_fn=lambda: {"eth0": (1000, 500)}, clock=lambda: 10.0)
    samples = monitor.sample()
    assert len(samples) == 1
    assert samples[0].rx_bps == 0.0
    assert samples[0].tx_bps == 0.0
    assert samples[0].rx_bytes == 1000
    assert samples[0].tx_bytes == 500


def test_second_sample_computes_exact_rate():
    snapshots = iter([{"eth0": (1000, 500)}, {"eth0": (2000, 1000)}])
    clocks = iter([10.0, 12.0])

    monitor = BandwidthMonitor(counters_fn=lambda: next(snapshots), clock=lambda: next(clocks))
    monitor.sample()
    second = monitor.sample()[0]

    # delta_bytes=1000 over 2s -> 1000*8/2 = 4000 bps
    assert second.rx_bps == 4000.0
    assert second.tx_bps == 2000.0


def test_multiple_interfaces_tracked_independently():
    monitor = BandwidthMonitor(counters_fn=lambda: {"eth0": (100, 50), "wlan0": (200, 100)}, clock=lambda: 1.0)
    samples = monitor.sample()
    assert {s.iface for s in samples} == {"eth0", "wlan0"}


def test_only_iface_filter():
    monitor = BandwidthMonitor(counters_fn=lambda: {"eth0": (100, 50), "wlan0": (200, 100)}, clock=lambda: 1.0)
    samples = monitor.sample(only_iface="eth0")
    assert len(samples) == 1
    assert samples[0].iface == "eth0"


def test_zero_time_delta_does_not_divide_by_zero():
    monitor = BandwidthMonitor(counters_fn=lambda: {"eth0": (100, 50)}, clock=lambda: 5.0)
    monitor.sample()
    same_tick = monitor.sample()
    assert same_tick[0].rx_bps == 0.0
