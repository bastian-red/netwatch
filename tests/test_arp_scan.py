from discovery.arp_scan import ArpScanner


def test_static_hosts_only_never_calls_sweep_fn():
    calls = []

    def sweep_fn(cidr, timeout):
        calls.append((cidr, timeout))
        return []

    scanner = ArpScanner(sweep_fn=sweep_fn, static_hosts=["10.0.0.1", "10.0.0.2"])
    hosts = scanner.scan(cidr=None)

    assert calls == []
    assert [h.ip for h in hosts] == ["10.0.0.1", "10.0.0.2"]
    assert all(h.status == "up" for h in hosts)


def test_arp_sweep_results_via_injected_sweep_fn():
    def sweep_fn(cidr, timeout):
        assert cidr == "192.168.1.0/24"
        return [("192.168.1.10", "aa:bb:cc:dd:ee:01"), ("192.168.1.20", "aa:bb:cc:dd:ee:02")]

    scanner = ArpScanner(sweep_fn=sweep_fn)
    hosts = scanner.scan(cidr="192.168.1.0/24")

    assert [h.ip for h in hosts] == ["192.168.1.10", "192.168.1.20"]
    assert hosts[0].mac == "aa:bb:cc:dd:ee:01"


def test_static_host_also_seen_in_sweep_is_deduped_and_gets_mac():
    def sweep_fn(cidr, timeout):
        return [("10.0.0.1", "aa:bb:cc:dd:ee:01")]

    scanner = ArpScanner(sweep_fn=sweep_fn, static_hosts=["10.0.0.1"])
    hosts = scanner.scan(cidr="10.0.0.0/24")

    assert len(hosts) == 1
    assert hosts[0].mac == "aa:bb:cc:dd:ee:01"


def test_no_cidr_and_no_static_hosts_returns_empty():
    scanner = ArpScanner(sweep_fn=lambda cidr, timeout: (_ for _ in ()).throw(AssertionError("should not be called")))
    assert scanner.scan(cidr=None) == []
