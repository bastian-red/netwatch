"""SQLite-backed time-series store for hosts, samples, and alerts.

Every discovered host, latency probe, bandwidth sample, and detector alert is
written here. :meth:`NetwatchStore.stats` aggregates all four tables into the
summary the CLI prints and the dashboard streams. A single lock guards the
connection so the monitor thread and the dashboard thread can share one store
safely, the same pattern as the dns-sinkhole sibling's ``SinkholeStore``.
"""

from __future__ import annotations

import sqlite3
import threading

from core.models import Alert, BandwidthSample, Host, LatencySample

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    ip          TEXT PRIMARY KEY,
    mac         TEXT,
    hostname    TEXT,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    status      TEXT NOT NULL DEFAULT 'unknown'
);
CREATE TABLE IF NOT EXISTS latency_samples (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ip     TEXT NOT NULL,
    ts     REAL NOT NULL,
    rtt_ms REAL,
    method TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bandwidth_samples (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    iface    TEXT NOT NULL,
    ts       REAL NOT NULL,
    rx_bytes INTEGER NOT NULL,
    tx_bytes INTEGER NOT NULL,
    rx_bps   REAL NOT NULL,
    tx_bps   REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    kind     TEXT NOT NULL,
    severity TEXT NOT NULL,
    target   TEXT NOT NULL,
    detail   TEXT
);
CREATE INDEX IF NOT EXISTS idx_latency_ip_ts   ON latency_samples(ip, ts);
CREATE INDEX IF NOT EXISTS idx_bandwidth_if_ts ON bandwidth_samples(iface, ts);
CREATE INDEX IF NOT EXISTS idx_alerts_ts       ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_kind     ON alerts(kind);
"""


class NetwatchStore:
    """Thread-safe SQLite store for hosts, samples, and alerts."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def upsert_host(self, host: Host) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO hosts (ip, mac, hostname, first_seen, last_seen, status)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac=excluded.mac,
                    hostname=CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE hosts.hostname END,
                    last_seen=excluded.last_seen,
                    status=excluded.status
                """,
                (host.ip, host.mac, host.hostname, host.first_seen, host.last_seen, host.status),
            )
            self._conn.commit()

    def log_latency(self, sample: LatencySample) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO latency_samples (ip, ts, rtt_ms, method) VALUES (?, ?, ?, ?)",
                (sample.ip, sample.ts, sample.rtt_ms, sample.method),
            )
            self._conn.commit()

    def log_bandwidth(self, sample: BandwidthSample) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO bandwidth_samples (iface, ts, rx_bytes, tx_bytes, rx_bps, tx_bps)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (sample.iface, sample.ts, sample.rx_bytes, sample.tx_bytes, sample.rx_bps, sample.tx_bps),
            )
            self._conn.commit()

    def log_alert(self, alert: Alert) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO alerts (ts, kind, severity, target, detail) VALUES (?, ?, ?, ?, ?)",
                (alert.ts, alert.kind, alert.severity, alert.target, alert.detail),
            )
            self._conn.commit()

    def hosts(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM hosts ORDER BY ip").fetchall()
        return [dict(r) for r in rows]

    def latency_history(self, ip: str, limit: int = 200) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, rtt_ms, method FROM latency_samples WHERE ip = ? ORDER BY id DESC LIMIT ?",
                (ip, limit),
            ).fetchall()
        return [dict(r) for r in reversed(rows)]

    def bandwidth_history(self, iface: str, limit: int = 200) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, rx_bytes, tx_bytes, rx_bps, tx_bps FROM bandwidth_samples"
                " WHERE iface = ? ORDER BY id DESC LIMIT ?",
                (iface, limit),
            ).fetchall()
        return [dict(r) for r in reversed(rows)]

    def recent_alerts(self, limit: int = 20) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, kind, severity, target, detail FROM alerts ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict:
        """Aggregate the whole store into the dashboard/CLI summary dict."""
        with self._lock:
            host_rows = self._conn.execute(
                "SELECT status, COUNT(*) AS c FROM hosts GROUP BY status"
            ).fetchall()
            total_hosts = self._conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
            latency_count = self._conn.execute("SELECT COUNT(*) FROM latency_samples").fetchone()[0]
            avg_rtt = self._conn.execute(
                "SELECT AVG(rtt_ms) FROM latency_samples WHERE rtt_ms IS NOT NULL"
            ).fetchone()[0]
            alert_rows = self._conn.execute(
                "SELECT kind, COUNT(*) AS c FROM alerts GROUP BY kind"
            ).fetchall()
            alert_count = self._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        by_status = {r["status"]: r["c"] for r in host_rows}
        return {
            "total_hosts": total_hosts,
            "hosts_up": by_status.get("up", 0),
            "hosts_down": by_status.get("down", 0),
            "latency_samples": latency_count,
            "avg_rtt_ms": round(avg_rtt, 2) if avg_rtt is not None else None,
            "alert_count": alert_count,
            "alerts_by_kind": {r["kind"]: r["c"] for r in alert_rows},
            "recent_alerts": self.recent_alerts(10),
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()
