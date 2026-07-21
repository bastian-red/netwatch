#!/usr/bin/env python3
"""Precision/recall gate for detect.alerts.AlertDetector against seeded corpora.

Run:  python -m evals.run_detection --seed 2024 \
          --recall-down 0.99 --precision-down 0.99 \
          --recall-arp 0.90 --precision-arp 0.75

Two independent evaluations, at two different (and each individually natural)
grains: host-down/recovered is scored tick-by-tick against the exact
counting-rule ground truth (see corpus.py); ARP-spoof is scored per-IP across
the whole scan run, since "was this IP the target of a spoof campaign" is
inherently an episode-level judgment, not a per-tick one. Exits non-zero if
either sub-corpus falls under its threshold.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from core.config import DetectConfig
from core.models import Host, LatencySample
from detect.alerts import AlertDetector
from evals.corpus import generate_arp, generate_uptime

_OUT_PATH = os.path.join(os.path.dirname(__file__), "corpus", "dataset.jsonl")


class _Clock:
    """A settable fake clock so AlertDetector can be driven by corpus timestamps."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def _confusion(y_true: list[bool], y_pred: list[bool]) -> dict:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t and p)
    fp = sum(1 for t, p in zip(y_true, y_pred) if not t and p)
    tn = sum(1 for t, p in zip(y_true, y_pred) if not t and not p)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t and not p)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision, "recall": recall, "f1": f1}


def run_uptime_eval(seed: int, down_after_missed: int = 3) -> tuple[dict, list[dict]]:
    hosts = generate_uptime(seed=seed, down_after_missed=down_after_missed)
    y_true: list[bool] = []
    y_pred: list[bool] = []
    rows: list[dict] = []

    for host in hosts:
        detector = AlertDetector(DetectConfig(down_after_missed=down_after_missed))
        ip = host["ip"]
        for tick, rtt in enumerate(host["rtts"]):
            ts = tick * host["interval"]
            detector.on_latency_sample(LatencySample(ip=ip, ts=ts, rtt_ms=rtt, method="tcp"))
            predicted = detector.is_down(ip)
            expected = host["expected_down"][tick]
            y_true.append(expected)
            y_pred.append(predicted)
            rows.append({"kind": "uptime", "ip": ip, "tick": tick, "expected_down": expected, "predicted_down": predicted})

    return _confusion(y_true, y_pred), rows


def run_arp_eval(seed: int) -> tuple[dict, list[dict]]:
    records = generate_arp(seed=seed)
    clock = _Clock()
    detector = AlertDetector(DetectConfig(), clock=clock)
    flagged: dict[str, bool] = {record["ip"]: False for record in records}
    n_scans = max(len(record["scans"]) for record in records)

    for scan_idx in range(n_scans):
        hosts_at_tick = []
        for record in records:
            if scan_idx < len(record["scans"]):
                scan_ts, mac = record["scans"][scan_idx]
                clock.now = scan_ts
                hosts_at_tick.append(Host(ip=record["ip"], mac=mac, last_seen=scan_ts))
        for alert in detector.on_discovery(hosts_at_tick):
            if alert.kind == "arp_spoof" and alert.severity == "high":
                flagged[alert.target] = True

    y_true = [record["malicious"] for record in records]
    y_pred = [flagged[record["ip"]] for record in records]
    rows = [
        {"kind": "arp", "ip": record["ip"], "malicious": record["malicious"], "flagged": flagged[record["ip"]]}
        for record in records
    ]
    return _confusion(y_true, y_pred), rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Precision/recall gate for netwatch's detectors.")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--recall-down", type=float, default=0.99)
    parser.add_argument("--precision-down", type=float, default=0.99)
    parser.add_argument("--recall-arp", type=float, default=0.90)
    parser.add_argument("--precision-arp", type=float, default=0.75)
    args = parser.parse_args(argv)

    down_metrics, down_rows = run_uptime_eval(args.seed)
    arp_metrics, arp_rows = run_arp_eval(args.seed)

    os.makedirs(os.path.dirname(_OUT_PATH), exist_ok=True)
    with open(_OUT_PATH, "w") as fh:
        for row in down_rows + arp_rows:
            fh.write(json.dumps(row) + "\n")

    print("=== host-down / host-recovered detection ===")
    print(json.dumps(down_metrics, indent=2))
    print("\n=== ARP-spoof (MAC-flap) detection ===")
    print(json.dumps(arp_metrics, indent=2))

    down_pass = down_metrics["recall"] >= args.recall_down and down_metrics["precision"] >= args.precision_down
    arp_pass = arp_metrics["recall"] >= args.recall_arp and arp_metrics["precision"] >= args.precision_arp

    print(
        f"\nhost-down: {'PASS' if down_pass else 'FAIL'} "
        f"(recall={down_metrics['recall']:.4f} >= {args.recall_down}, "
        f"precision={down_metrics['precision']:.4f} >= {args.precision_down})"
    )
    print(
        f"arp-spoof: {'PASS' if arp_pass else 'FAIL'} "
        f"(recall={arp_metrics['recall']:.4f} >= {args.recall_arp}, "
        f"precision={arp_metrics['precision']:.4f} >= {args.precision_arp})"
    )

    return 0 if (down_pass and arp_pass) else 1


if __name__ == "__main__":
    sys.exit(main())
