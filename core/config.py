"""Tunable configuration for discovery, monitoring, and detection.

All thresholds live here (not scattered across modules) so a single
``NetwatchConfig`` fully determines one monitoring run's behavior, the same
convention ``SinkholeConfig`` follows in the dns-sinkhole sibling project.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

ROOT = os.path.dirname(os.path.abspath(__file__ + "/.."))


@dataclass
class DiscoveryConfig:
    network_cidr: Optional[str] = None  # e.g. "192.168.1.0/24"; None = static-only
    static_hosts: list[str] = field(default_factory=list)
    interval_seconds: float = 30.0
    timeout: float = 2.0


@dataclass
class MonitorConfig:
    method: str = "tcp"  # "tcp" (unprivileged default) | "icmp"
    tcp_port: int = 80
    interval_seconds: float = 5.0
    timeout: float = 1.0


@dataclass
class DetectConfig:
    down_after_missed: int = 3
    latency_baseline_window: int = 20
    latency_spike_multiplier: float = 3.0
    latency_spike_min_samples: int = 5
    bandwidth_baseline_window: int = 20
    bandwidth_spike_multiplier: float = 3.0
    bandwidth_spike_min_samples: int = 5
    arp_flap_window: float = 60.0
    alert_cooldown: float = 30.0


@dataclass
class NetwatchConfig:
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
    monitor: MonitorConfig = field(default_factory=MonitorConfig)
    detect: DetectConfig = field(default_factory=DetectConfig)
    bandwidth_interval: float = 2.0
    iface: Optional[str] = None
    data_dir: str = field(default_factory=lambda: os.path.join(ROOT, "data"))
    db_path: str = field(default_factory=lambda: os.path.join(ROOT, "data", "netwatch.db"))

    def ensure_dirs(self) -> None:
        os.makedirs(self.data_dir, exist_ok=True)
