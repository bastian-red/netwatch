"""Seeded synthetic corpora for the detection evals.

Two independent sub-corpora, both deterministic given a seed:

``generate_uptime`` builds per-host latency sequences whose "expected_down"
ground truth is computed with the *same* consecutive-miss counting rule
:class:`detect.alerts.AlertDetector` implements. This validates the
*implementation* of that rule against many randomized sequences (an
implementation bug -- an off-by-one, a wrong reset -- shows up as recall/
precision below ~1.0), rather than judging the rule against an impossible
zero-lag ideal.

``generate_arp`` builds per-IP MAC-change sequences labeled malicious
(sustained flapping, simulating an active spoofer) or benign (stable, a
one-time DHCP-style reassignment, or -- the deliberately hard case -- a rare
benign flap that lands inside the detection window, and a deliberately slow
malicious flap that lands outside it). This is a genuinely harder
discrimination problem than host-down, which is why its eval thresholds are
lower.
"""

from __future__ import annotations

import random
from typing import Optional


def generate_uptime(
    seed: int = 1337,
    n_hosts: int = 30,
    ticks: int = 150,
    down_episode_rate: float = 0.25,
    down_len_range: tuple[int, int] = (2, 12),
    up_run_range: tuple[int, int] = (3, 10),
    rtt_range: tuple[float, float] = (5.0, 40.0),
    down_after_missed: int = 3,
    tick_interval: float = 5.0,
) -> list[dict]:
    rng = random.Random(seed)
    hosts = []

    for i in range(n_hosts):
        ip = f"10.60.{i // 254}.{i % 254 + 1}"
        rtts: list[Optional[float]] = []
        t = 0
        while t < ticks:
            if rng.random() < down_episode_rate:
                length = rng.randint(*down_len_range)
                rtts.extend([None] * min(length, ticks - t))
                t += length
            else:
                run = rng.randint(*up_run_range)
                base = rng.uniform(*rtt_range)
                for _ in range(min(run, ticks - t)):
                    rtts.append(max(0.1, rng.gauss(base, base * 0.1)))
                t += run
        rtts = rtts[:ticks]

        expected_down = []
        miss = 0
        down = False
        for rtt in rtts:
            if rtt is None:
                miss += 1
                if miss >= down_after_missed:
                    down = True
            else:
                miss = 0
                down = False
            expected_down.append(down)

        hosts.append({"ip": ip, "rtts": rtts, "expected_down": expected_down, "interval": tick_interval})

    return hosts


def generate_arp(
    seed: int = 1337,
    n_ips: int = 200,
    scans: int = 30,
    malicious_rate: float = 0.25,
    benign_flap_rate: float = 0.04,
    malicious_slow_rate: float = 0.06,
    benign_reassign_rate: float = 0.3,
    flap_window: float = 60.0,
    scan_interval: float = 10.0,
) -> list[dict]:
    rng = random.Random(seed)
    records = []

    for i in range(n_ips):
        ip = f"10.50.{i // 254}.{i % 254 + 1}"
        mac_a = f"aa:aa:aa:aa:aa:{i:02x}"
        mac_b = f"bb:bb:bb:bb:bb:{i:02x}"
        malicious = rng.random() < malicious_rate

        if malicious:
            # Sustained flapping between two MACs -- the spoofing signature.
            # A "slow" spoofer flips less often than the flap window covers,
            # which the flap-window heuristic will genuinely miss.
            slow = rng.random() < malicious_slow_rate
            window_scans = max(1, int(flap_window / scan_interval))
            period = rng.randint(window_scans + 2, window_scans + 5) if slow else rng.randint(2, window_scans - 1)
            entries = []
            current = mac_a
            for s in range(scans):
                if s > 0 and s % period == 0:
                    current = mac_b if current == mac_a else mac_a
                entries.append((s * scan_interval, current))
        else:
            flappy = rng.random() < benign_flap_rate
            reassigns = rng.random() < benign_reassign_rate
            if flappy:
                # Rare benign case: a device switches MAC once, then flips
                # back shortly after (e.g. a NIC failover) -- lands inside
                # the flap window and looks identical to a real spoof.
                switch_at = rng.randint(scans // 3, 2 * scans // 3)
                window_scans = max(1, int(flap_window / scan_interval) - 1)
                entries = [(s * scan_interval, mac_a if s < switch_at else mac_b) for s in range(scans)]
                flap_back_at = min(scans - 1, switch_at + window_scans)
                entries[flap_back_at] = (flap_back_at * scan_interval, mac_a)
            elif reassigns:
                # One-time reassignment with no flap-back, e.g. a DHCP renewal.
                switch_at = rng.randint(scans // 3, 2 * scans // 3)
                entries = [(s * scan_interval, mac_a if s < switch_at else mac_b) for s in range(scans)]
            else:
                entries = [(s * scan_interval, mac_a) for s in range(scans)]

        records.append({"ip": ip, "scans": entries, "malicious": malicious})

    return records
