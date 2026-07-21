#!/usr/bin/env python3
"""Command-line interface for netwatch.

    cli.py discover [--cidr 192.168.1.0/24] [--static-hosts-file FILE] [--json OUT]
    cli.py monitor  [--cidr ..] [--static-hosts-file ..] [--method tcp|icmp]
                    [--tcp-port 80] [--interval 5] [--duration N] [--db PATH] [--stats]
    cli.py stats    [--db PATH]
    cli.py attack arp-spoof --target-ip IP --gateway-ip IP [--iface eth0]
                    [--duration N] [--i-understand-lab]

Live ARP discovery and ICMP probing need raw-socket privileges (sudo or
CAP_NET_RAW). The static-hosts + TCP-connect path needs neither.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Optional

from netwatch import NetWatch, build_config

_RED = "\033[31m"
_YELLOW = "\033[33m"
_GREEN = "\033[32m"
_RESET = "\033[0m"

_SEVERITY_COLOR = {"low": _GREEN, "medium": _YELLOW, "high": _RED}


def _color(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{_RESET}" if enabled else text


def _print_alert(alert, color: bool) -> None:
    code = _SEVERITY_COLOR.get(alert.severity, "")
    msg = f"[ALERT/{alert.severity}] {alert.kind}: {alert.detail}"
    print(_color(msg, code, color), file=sys.stderr)


def _cmd_discover(args: argparse.Namespace) -> int:
    config = build_config(args)
    engine = NetWatch(config)
    hosts = engine.discover()
    engine.close()

    print(f"{'IP':<18} {'MAC':<20} STATUS")
    for host in hosts:
        print(f"{host.ip:<18} {host.mac or '-':<20} {host.status}")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump([h.to_dict() for h in hosts], fh, indent=2)
        print(f"wrote {len(hosts)} hosts to {args.json}")
    return 0


def _cmd_monitor(args: argparse.Namespace) -> int:
    config = build_config(args)
    color = sys.stderr.isatty()
    engine = NetWatch(config, on_alert=lambda a: _print_alert(a, color))

    start = time.time()

    def stop_flag() -> bool:
        return args.duration is not None and (time.time() - start) >= args.duration

    try:
        engine.run_forever(stop_flag=stop_flag)
    except KeyboardInterrupt:
        pass

    if args.stats:
        stats = engine.store.stats()
        print("\n=== Statistics ===")
        print(json.dumps(stats, indent=2))

    engine.close()
    return 0


def _cmd_stats(args: argparse.Namespace) -> int:
    import os

    from core.config import NetwatchConfig
    from storage.store import NetwatchStore

    db_path = args.db or NetwatchConfig().db_path
    if not os.path.exists(db_path):
        print(f"No data yet at {db_path} (run 'monitor' first).")
        return 0

    store = NetwatchStore(db_path)
    print(json.dumps(store.stats(), indent=2))
    store.close()
    return 0


def _cmd_attack_arp_spoof(args: argparse.Namespace) -> int:
    from offensive.arp_spoof import spoof
    from offensive.guard import LabGuardError

    try:
        spoof(
            target_ip=args.target_ip,
            gateway_ip=args.gateway_ip,
            iface=args.iface,
            duration=args.duration,
            override=args.i_understand_lab,
        )
    except LabGuardError as exc:
        print(f"blocked: {exc}", file=sys.stderr)
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="netwatch: local network monitoring dashboard CLI.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_discover = sub.add_parser("discover", help="one-shot host discovery")
    p_discover.add_argument("--cidr", help="subnet to ARP-sweep, e.g. 192.168.1.0/24 (needs privileges)")
    p_discover.add_argument("--static-hosts-file", help="JSON file with a list of IPs (no privileges needed)")
    p_discover.add_argument("--json", help="write discovered hosts to this JSON file")
    p_discover.add_argument("--db", help="SQLite path to persist discovered hosts (default: data/netwatch.db)")
    p_discover.set_defaults(func=_cmd_discover)

    p_monitor = sub.add_parser("monitor", help="continuously discover, probe, and detect")
    p_monitor.add_argument("--cidr")
    p_monitor.add_argument("--static-hosts-file")
    p_monitor.add_argument("--discovery-interval", type=float, default=30.0)
    p_monitor.add_argument("--method", choices=["tcp", "icmp"], default="tcp")
    p_monitor.add_argument("--tcp-port", type=int, default=80)
    p_monitor.add_argument("--interval", type=float, default=5.0)
    p_monitor.add_argument("--iface", help="interface for bandwidth sampling; default is all")
    p_monitor.add_argument("--duration", type=float, default=None, help="stop after N seconds (default: forever)")
    p_monitor.add_argument("--db", help="SQLite path (default: data/netwatch.db)")
    p_monitor.add_argument("--stats", action="store_true", help="print summary stats on exit")
    p_monitor.set_defaults(func=_cmd_monitor)

    p_stats = sub.add_parser("stats", help="print stored statistics")
    p_stats.add_argument("--db", help="SQLite path (default: data/netwatch.db)")
    p_stats.set_defaults(func=_cmd_stats)

    p_attack = sub.add_parser("attack", help="lab offensive tools (own network only)")
    attack_sub = p_attack.add_subparsers(dest="attack_command", required=True)
    p_spoof = attack_sub.add_parser("arp-spoof", help="ARP cache-poisoning MITM demo")
    p_spoof.add_argument("--target-ip", required=True)
    p_spoof.add_argument("--gateway-ip", required=True)
    p_spoof.add_argument("--iface", default=None)
    p_spoof.add_argument("--duration", type=float, default=10.0)
    p_spoof.add_argument(
        "--i-understand-lab", action="store_true",
        help="allow targeting a non-lab host (authorized tests only)",
    )
    p_spoof.set_defaults(func=_cmd_attack_arp_spoof)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
