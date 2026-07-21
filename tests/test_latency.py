import socket
import threading

from monitor.latency import Prober, tcp_ping


def test_prober_uses_injected_send_fn_and_clock():
    rtts = {"10.0.0.1": 12.5, "10.0.0.2": None}
    ticks = iter([100.0, 101.0])

    prober = Prober(send_fn=lambda ip, timeout: rtts[ip], clock=lambda: next(ticks))
    a = prober.probe("10.0.0.1")
    b = prober.probe("10.0.0.2")

    assert a.rtt_ms == 12.5
    assert a.ts == 100.0
    assert b.rtt_ms is None
    assert b.ts == 101.0


def test_probe_many_preserves_order():
    prober = Prober(send_fn=lambda ip, timeout: float(ip.split(".")[-1]), clock=lambda: 0.0)
    samples = prober.probe_many(["10.0.0.3", "10.0.0.1", "10.0.0.2"])
    assert [s.ip for s in samples] == ["10.0.0.3", "10.0.0.1", "10.0.0.2"]
    assert [s.rtt_ms for s in samples] == [3.0, 1.0, 2.0]


def test_probe_method_label_matches_send_fn():
    prober = Prober(send_fn=tcp_ping, clock=lambda: 0.0)
    # Closed local port -> instant failure, no real network dependency.
    sample = prober.probe("127.0.0.1", timeout=0.2)
    assert sample.method == "tcp"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_tcp_ping_success_against_local_listener():
    port = _free_port()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(1)

    def accept_once():
        conn, _ = server.accept()
        conn.close()

    t = threading.Thread(target=accept_once, daemon=True)
    t.start()
    try:
        rtt = tcp_ping("127.0.0.1", port=port, timeout=1.0)
        assert rtt is not None
        assert rtt >= 0.0
    finally:
        t.join(timeout=1.0)
        server.close()


def test_tcp_ping_timeout_against_closed_port_returns_none():
    port = _free_port()  # bound briefly then released -> nothing listening
    rtt = tcp_ping("127.0.0.1", port=port, timeout=0.3)
    assert rtt is None
