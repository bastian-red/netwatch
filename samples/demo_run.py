#!/usr/bin/env python3
"""Scripted end-to-end demo: starts a NetWatch engine against static, purely
local hosts (no privileges, no internet) and prints discovery, latency
probing, a host-down alert, and final stats. Not a test -- a runnable demo,
the same role ``samples/demo_run.py`` plays in the dns-sinkhole sibling.

Run:  python samples/demo_run.py
"""

from __future__ import annotations

import os
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import DetectConfig, DiscoveryConfig, MonitorConfig, NetwatchConfig  # noqa: E402
from netwatch import NetWatch  # noqa: E402

DEMO_PORT = 8090
UP_HOST = "127.0.0.1"
DOWN_HOST = "127.0.0.2"  # nothing listens here -> demonstrates a host-down alert


def _start_listener(port: int) -> socket.socket:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((UP_HOST, port))
    server.listen(5)

    def accept_loop() -> None:
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            conn.close()

    threading.Thread(target=accept_loop, daemon=True).start()
    return server


def _print_alert(alert) -> None:
    print(f"  [ALERT/{alert.severity}] {alert.kind}: {alert.detail}")


def main() -> int:
    print("=== netwatch demo: fully offline, no privileges needed ===\n")
    listener = _start_listener(DEMO_PORT)

    db_path = os.path.join(tempfile.mkdtemp(prefix="netwatch-demo-"), "netwatch.db")
    config = NetwatchConfig(
        discovery=DiscoveryConfig(static_hosts=[UP_HOST, DOWN_HOST], interval_seconds=9999),
        monitor=MonitorConfig(method="tcp", tcp_port=DEMO_PORT, interval_seconds=0.2, timeout=0.3),
        detect=DetectConfig(down_after_missed=2),
        db_path=db_path,
    )
    engine = NetWatch(config, on_alert=_print_alert)

    print(f"Discovering static hosts: {config.discovery.static_hosts}")
    hosts = engine.discover()
    for host in hosts:
        print(f"  {host.ip:<15} status={host.status}")

    print("\nProbing latency for a few ticks (watch for the host-down alert)...")
    for i in range(4):
        engine.probe_all()
        time.sleep(0.2)

    print("\nFinal host status:")
    for host in engine.hosts.values():
        print(f"  {host.ip:<15} status={host.status}")

    print("\nStored stats:")
    import json

    print(json.dumps(engine.store.stats(), indent=2))

    engine.close()
    listener.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
