"""Per-interface bandwidth sampling from psutil counters.

``psutil.net_io_counters`` is itself unprivileged, so unlike ARP/ICMP there is
no privileged/unprivileged split here. ``BandwidthMonitor`` still takes
``counters_fn`` and ``clock`` as injectable arguments so tests get exact,
deterministic rate math instead of depending on a real interface or a real
sleep.
"""

from __future__ import annotations

import time
from typing import Callable, Optional

from core.models import BandwidthSample

CountersFn = Callable[[], dict[str, tuple[int, int]]]


def psutil_counters() -> dict[str, tuple[int, int]]:
    """Real psutil snapshot: {iface: (rx_bytes, tx_bytes)}. No privileges needed."""
    import psutil

    return {
        iface: (counters.bytes_recv, counters.bytes_sent)
        for iface, counters in psutil.net_io_counters(pernic=True).items()
    }


class BandwidthMonitor:
    """Samples per-interface byte counters and derives rx/tx bits-per-second."""

    def __init__(
        self,
        counters_fn: CountersFn = psutil_counters,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.counters_fn = counters_fn
        self.clock = clock
        self._last: dict[str, tuple[float, int, int]] = {}  # iface -> (ts, rx_bytes, tx_bytes)

    def sample(self, only_iface: Optional[str] = None) -> list[BandwidthSample]:
        now = self.clock()
        counters = self.counters_fn()
        samples: list[BandwidthSample] = []

        for iface, (rx_bytes, tx_bytes) in counters.items():
            if only_iface and iface != only_iface:
                continue
            prev = self._last.get(iface)
            if prev is None:
                rx_bps = tx_bps = 0.0
            else:
                prev_ts, prev_rx, prev_tx = prev
                dt = now - prev_ts
                if dt <= 0:
                    rx_bps = tx_bps = 0.0
                else:
                    rx_bps = max(0, rx_bytes - prev_rx) * 8 / dt
                    tx_bps = max(0, tx_bytes - prev_tx) * 8 / dt
            self._last[iface] = (now, rx_bytes, tx_bytes)
            samples.append(
                BandwidthSample(
                    iface=iface, ts=now, rx_bytes=rx_bytes, tx_bytes=tx_bytes, rx_bps=rx_bps, tx_bps=tx_bps
                )
            )

        return samples
