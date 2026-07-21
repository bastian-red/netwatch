"""Normalized data shapes flowing between discovery, monitor, detect, storage, and UI.

Every producer (ARP scanner, latency prober, bandwidth sampler, alert detector)
emits one of these dataclasses; every consumer (the SQLite store, the Socket.IO
emitter) reads them via ``to_dict()``. This is the single shape contract that
keeps every module decoupled from the others.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from typing import Any, Optional


@dataclass
class Host:
    ip: str
    mac: str = ""
    hostname: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    status: str = "unknown"  # "up" | "down" | "unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LatencySample:
    ip: str
    ts: float
    rtt_ms: Optional[float]  # None = timeout / unreachable
    method: str  # "icmp" | "tcp"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BandwidthSample:
    iface: str
    ts: float
    rx_bytes: int
    tx_bytes: int
    rx_bps: float
    tx_bps: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Alert:
    kind: str  # host_down | host_recovered | latency_spike | bandwidth_spike | arp_spoof
    severity: str  # low | medium | high
    target: str  # ip or iface
    detail: str
    ts: float = 0.0

    def __post_init__(self) -> None:
        if not self.ts:
            self.ts = time.time()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
