"""Latency probing: ICMP ping (privileged) and TCP-connect timing (unprivileged).

``Prober`` takes its send function as a constructor argument, the same
injectable-callback shape used for ARP discovery, so tests never call the real
network: they pass a fake ``send_fn`` and a fake ``clock`` and get fully
deterministic ``LatencySample`` output.
"""

from __future__ import annotations

import socket
import time
from typing import Callable, Optional, Sequence

from core.models import LatencySample

SendFn = Callable[[str, float], Optional[float]]


def icmp_ping(ip: str, timeout: float = 1.0) -> Optional[float]:
    """Send one ICMP echo via scapy and return the round-trip time in ms, or None on timeout.

    Needs raw-socket privileges (root or CAP_NET_RAW).
    """
    from scapy.all import ICMP, IP, sr1

    start = time.time()
    reply = sr1(IP(dst=ip) / ICMP(), timeout=timeout, verbose=False)
    if reply is None:
        return None
    return (time.time() - start) * 1000.0


def tcp_ping(ip: str, timeout: float = 1.0, port: int = 80) -> Optional[float]:
    """Time a TCP connect handshake to ``ip:port`` in ms, or None on failure/timeout.

    No privileges needed; works against any host with an open TCP port.
    """
    start = time.time()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            pass
    except OSError:
        return None
    return (time.time() - start) * 1000.0


class Prober:
    """Probes a set of IPs for latency using an injectable send function."""

    def __init__(self, send_fn: SendFn = tcp_ping, clock: Callable[[], float] = time.time) -> None:
        self.send_fn = send_fn
        self.clock = clock

    def probe(self, ip: str, timeout: float = 1.0) -> LatencySample:
        method = getattr(self.send_fn, "__name__", "custom").replace("_ping", "")
        rtt = self.send_fn(ip, timeout)
        return LatencySample(ip=ip, ts=self.clock(), rtt_ms=rtt, method=method)

    def probe_many(self, ips: Sequence[str], timeout: float = 1.0) -> list[LatencySample]:
        return [self.probe(ip, timeout) for ip in ips]
