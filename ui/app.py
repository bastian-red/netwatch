#!/usr/bin/env python3
"""Flask + Socket.IO web dashboard for netwatch.

A background task drives the shared :class:`NetWatch` engine (discover, probe,
sample bandwidth, detect). Discovered hosts, latency/bandwidth samples, and
alerts are buffered by the engine's callbacks and pushed to the browser over
WebSockets by one background emitter loop, so we never call ``emit`` from the
monitor thread directly -- the same pattern the packet-analyzer sibling uses.

Run:  python ui/app.py
"""

from __future__ import annotations

import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, request  # noqa: E402
from flask import render_template  # noqa: E402
from flask_socketio import SocketIO  # noqa: E402

from core.config import DetectConfig, DiscoveryConfig, MonitorConfig, NetwatchConfig  # noqa: E402
from netwatch import NetWatch  # noqa: E402

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-netwatch")
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")


class Session:
    """Holds the current NetWatch engine and buffered outbound events."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.engine: NetWatch | None = None
        self.hosts_buf: list[dict] = []
        self.latency_buf: list[dict] = []
        self.bandwidth_buf: list[dict] = []
        self.alerts_buf: list[dict] = []
        self._stop = False
        self._thread: threading.Thread | None = None
        self.running = False

    def reset(self, config: NetwatchConfig) -> NetWatch:
        with self.lock:
            self.hosts_buf.clear()
            self.latency_buf.clear()
            self.bandwidth_buf.clear()
            self.alerts_buf.clear()
            self.engine = NetWatch(
                config,
                on_alert=lambda a: self._buffer(self.alerts_buf, a.to_dict()),
                on_hosts=lambda hosts: self._buffer(self.hosts_buf, [h.to_dict() for h in hosts]),
                on_latency=lambda s: self._buffer(self.latency_buf, s.to_dict()),
                on_bandwidth=lambda s: self._buffer(self.bandwidth_buf, s.to_dict()),
            )
            self._stop = False
            return self.engine

    def _buffer(self, buf: list, item) -> None:
        with self.lock:
            if len(buf) < 5000:
                buf.append(item)

    def drain(self) -> tuple[list, list, list, list]:
        with self.lock:
            h, l, b, a = self.hosts_buf, self.latency_buf, self.bandwidth_buf, self.alerts_buf
            self.hosts_buf, self.latency_buf, self.bandwidth_buf, self.alerts_buf = [], [], [], []
            return h, l, b, a

    def stop_requested(self) -> bool:
        return self._stop

    def stop(self) -> None:
        self._stop = True
        self.running = False


session = Session()
_emitter_started = False
_emitter_lock = threading.Lock()


def _emitter_loop() -> None:
    ticks = 0
    while True:
        socketio.sleep(0.25)
        hosts, latency, bandwidth, alerts = session.drain()
        if hosts:
            socketio.emit("hosts", hosts)
        if latency:
            socketio.emit("latency", latency)
        if bandwidth:
            socketio.emit("bandwidth", bandwidth)
        for alert in alerts:
            socketio.emit("alert", alert)
        ticks += 1
        if ticks % 4 == 0 and session.engine is not None:  # ~1s
            socketio.emit("stats", session.engine.store.stats())


def _ensure_emitter() -> None:
    global _emitter_started
    with _emitter_lock:
        if not _emitter_started:
            socketio.start_background_task(_emitter_loop)
            _emitter_started = True


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/hosts")
def api_hosts():
    if session.engine is None:
        return jsonify([])
    return jsonify(session.engine.store.hosts())


@app.route("/api/stats")
def api_stats():
    if session.engine is None:
        return jsonify({})
    return jsonify(session.engine.store.stats())


@app.route("/api/history/latency/<ip>")
def api_history_latency(ip: str):
    if session.engine is None:
        return jsonify([])
    return jsonify(session.engine.store.latency_history(ip))


@app.route("/api/history/bandwidth/<iface>")
def api_history_bandwidth(iface: str):
    if session.engine is None:
        return jsonify([])
    return jsonify(session.engine.store.bandwidth_history(iface))


@app.route("/monitor/start", methods=["POST"])
def monitor_start():
    data = request.get_json(silent=True) or {}
    config = NetwatchConfig(
        discovery=DiscoveryConfig(
            network_cidr=data.get("cidr") or None,
            static_hosts=data.get("static_hosts") or [],
            interval_seconds=float(data.get("discovery_interval", 30.0)),
        ),
        monitor=MonitorConfig(
            method=data.get("method", "tcp"),
            tcp_port=int(data.get("tcp_port", 80)),
            interval_seconds=float(data.get("interval", 5.0)),
        ),
        detect=DetectConfig(),
        iface=data.get("iface") or None,
    )
    if data.get("db"):
        config.db_path = data["db"]

    session.stop()
    engine = session.reset(config)
    session.running = True

    def worker() -> None:
        try:
            engine.run_forever(stop_flag=session.stop_requested)
        except PermissionError as exc:  # pragma: no cover - environment dependent
            session._buffer(session.alerts_buf, {"kind": "error", "severity": "high",
                                                  "target": "-", "detail": str(exc), "ts": 0.0})
        finally:
            session.running = False

    socketio.start_background_task(worker)
    return jsonify({"ok": True})


@app.route("/monitor/stop", methods=["POST"])
def monitor_stop():
    session.stop()
    return jsonify({"ok": True})


@socketio.on("connect")
def on_connect():
    _ensure_emitter()
    if session.engine is not None:
        socketio.emit("stats", session.engine.store.stats())
        socketio.emit("hosts", session.engine.store.hosts())


if __name__ == "__main__":
    _ensure_emitter()
    socketio.run(app, host="127.0.0.1", port=5000, debug=False, allow_unsafe_werkzeug=True)
