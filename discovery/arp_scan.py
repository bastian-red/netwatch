"""Host discovery: ARP sweep of a subnet, plus an unprivileged static-hosts path.

``arp_sweep`` needs raw-socket privileges (root or CAP_NET_RAW), same story as
live packet capture in the packet-analyzer sibling. ``ArpScanner`` decouples
that requirement from the rest of the pipeline: pass a ``static_hosts`` list
and no CIDR, and ``scan()`` never touches scapy or the network at all, which is
what the CLI defaults, the eval suite, and every test use.
"""

from __future__ import annotations

import time
from typing import Callable, Optional, Sequence

from core.models import Host

SweepFn = Callable[[str, float], list[tuple[str, str]]]


def arp_sweep(cidr: str, timeout: float = 2.0, iface: Optional[str] = None) -> list[tuple[str, str]]:
    """Broadcast an ARP request across ``cidr`` and collect (ip, mac) replies.

    Needs raw-socket privileges (root or CAP_NET_RAW).
    """
    from scapy.all import ARP, Ether, srp

    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    kwargs = {"timeout": timeout, "verbose": False}
    if iface:
        kwargs["iface"] = iface
    answered, _ = srp(request, **kwargs)
    return [(received.psrc, received.hwsrc) for _, received in answered]


class ArpScanner:
    """Discovers hosts via ARP sweep and/or a static, unprivileged host list."""

    def __init__(self, sweep_fn: SweepFn = arp_sweep, static_hosts: Sequence[str] = ()) -> None:
        self.sweep_fn = sweep_fn
        self.static_hosts = list(static_hosts)

    def scan(self, cidr: Optional[str] = None, timeout: float = 2.0) -> list[Host]:
        now = time.time()
        found: dict[str, Host] = {}

        for ip in self.static_hosts:
            found[ip] = Host(ip=ip, first_seen=now, last_seen=now, status="up")

        if cidr:
            for ip, mac in self.sweep_fn(cidr, timeout):
                existing = found.get(ip)
                found[ip] = Host(
                    ip=ip,
                    mac=mac,
                    first_seen=existing.first_seen if existing else now,
                    last_seen=now,
                    status="up",
                )

        return sorted(found.values(), key=lambda h: h.ip)
