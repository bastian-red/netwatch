"""Heuristic alert detection over latency, bandwidth, and discovery events.

Each detector uses a simple sliding-window / rolling-baseline threshold, the
same explainable-not-production-IDS philosophy as the packet-analyzer
sibling's ``AnomalyDetector``. All thresholds live in :class:`DetectConfig` so
they can be tuned per environment. A single per-key cooldown map (mirroring
the same anti-spam pattern) prevents repeated alerts for the same target.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Callable, Optional

from core.config import DetectConfig
from core.models import Alert, BandwidthSample, Host, LatencySample


class AlertDetector:
    """Runs all heuristic detectors and emits :class:`Alert` objects."""

    def __init__(self, config: Optional[DetectConfig] = None, clock: Callable[[], float] = time.time) -> None:
        self.cfg = config or DetectConfig()
        self.clock = clock

        self._miss_count: dict[str, int] = defaultdict(int)
        self._down: dict[str, bool] = defaultdict(bool)
        self._latency_baseline: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self.cfg.latency_baseline_window)
        )
        self._bw_rx_baseline: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self.cfg.bandwidth_baseline_window)
        )
        self._bw_tx_baseline: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self.cfg.bandwidth_baseline_window)
        )
        self._mac_history: dict[str, deque] = defaultdict(lambda: deque(maxlen=20))
        self._last_alert: dict[str, float] = {}

    def is_down(self, ip: str) -> bool:
        return self._down[ip]

    def _maybe_alert(self, kind: str, severity: str, target: str, detail: str, ts: float) -> list[Alert]:
        # Severity is part of the cooldown key so an escalation (e.g. a low
        # one-time MAC change followed by a high-severity confirmed flap)
        # never gets swallowed by the cooldown of a lower-severity alert.
        key = f"{kind}:{severity}:{target}"
        last = self._last_alert.get(key)
        if last is not None and ts - last < self.cfg.alert_cooldown:
            return []
        self._last_alert[key] = ts
        return [Alert(kind=kind, severity=severity, target=target, detail=detail, ts=ts)]

    def on_latency_sample(self, sample: LatencySample) -> list[Alert]:
        alerts: list[Alert] = []
        ip = sample.ip

        if sample.rtt_ms is None:
            self._miss_count[ip] += 1
            if self._miss_count[ip] == self.cfg.down_after_missed and not self._down[ip]:
                self._down[ip] = True
                alerts += self._maybe_alert(
                    "host_down", "high", ip,
                    f"{ip} missed {self.cfg.down_after_missed} consecutive probes",
                    sample.ts,
                )
            return alerts

        was_down = self._down[ip]
        self._miss_count[ip] = 0
        if was_down:
            self._down[ip] = False
            alerts += self._maybe_alert(
                "host_recovered", "low", ip, f"{ip} responded again after being down", sample.ts
            )

        baseline = self._latency_baseline[ip]
        if len(baseline) >= self.cfg.latency_spike_min_samples:
            mean = sum(baseline) / len(baseline)
            if mean > 0 and sample.rtt_ms > mean * self.cfg.latency_spike_multiplier:
                alerts += self._maybe_alert(
                    "latency_spike", "medium", ip,
                    f"{ip} rtt {sample.rtt_ms:.1f}ms vs baseline {mean:.1f}ms",
                    sample.ts,
                )
        baseline.append(sample.rtt_ms)
        return alerts

    def on_bandwidth_sample(self, sample: BandwidthSample) -> list[Alert]:
        alerts: list[Alert] = []
        iface = sample.iface

        rx_baseline = self._bw_rx_baseline[iface]
        if len(rx_baseline) >= self.cfg.bandwidth_spike_min_samples:
            mean_rx = sum(rx_baseline) / len(rx_baseline)
            if mean_rx > 0 and sample.rx_bps > mean_rx * self.cfg.bandwidth_spike_multiplier:
                alerts += self._maybe_alert(
                    "bandwidth_spike", "medium", iface,
                    f"{iface} rx {sample.rx_bps:.0f}bps vs baseline {mean_rx:.0f}bps",
                    sample.ts,
                )

        tx_baseline = self._bw_tx_baseline[iface]
        if len(tx_baseline) >= self.cfg.bandwidth_spike_min_samples:
            mean_tx = sum(tx_baseline) / len(tx_baseline)
            if mean_tx > 0 and sample.tx_bps > mean_tx * self.cfg.bandwidth_spike_multiplier:
                alerts += self._maybe_alert(
                    "bandwidth_spike", "medium", iface,
                    f"{iface} tx {sample.tx_bps:.0f}bps vs baseline {mean_tx:.0f}bps",
                    sample.ts,
                )

        rx_baseline.append(sample.rx_bps)
        tx_baseline.append(sample.tx_bps)
        return alerts

    def on_discovery(self, hosts: list[Host]) -> list[Alert]:
        alerts: list[Alert] = []
        now = self.clock()

        for host in hosts:
            if not host.mac:
                continue
            history = self._mac_history[host.ip]

            if history:
                last_mac = history[-1][1]
                if last_mac != host.mac:
                    flapped_back = any(
                        mac == host.mac and (now - ts) <= self.cfg.arp_flap_window for ts, mac in history
                    )
                    if flapped_back:
                        alerts += self._maybe_alert(
                            "arp_spoof", "high", host.ip,
                            f"{host.ip} MAC flapped back to {host.mac} within "
                            f"{self.cfg.arp_flap_window:.0f}s (possible ARP spoofing)",
                            now,
                        )
                    else:
                        alerts += self._maybe_alert(
                            "arp_spoof", "low", host.ip,
                            f"{host.ip} MAC changed from {last_mac} to {host.mac}",
                            now,
                        )

            history.append((now, host.mac))

        return alerts
