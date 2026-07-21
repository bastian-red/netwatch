#!/usr/bin/env python3
"""Engine assembly: wires discovery, monitoring, detection, and storage into one
:class:`NetWatch` instance. Both ``cli.py`` and ``ui/app.py`` import this module
so there is exactly one engine implementation, the same pattern
``dns_sinkhole.py`` uses in the dns-sinkhole sibling project.
"""

from __future__ import annotations

import json
import time
from typing import Callable, Optional

from core.config import DetectConfig, DiscoveryConfig, MonitorConfig, NetwatchConfig
from core.models import Alert, BandwidthSample, Host, LatencySample
from detect.alerts import AlertDetector
from discovery.arp_scan import ArpScanner
from monitor.bandwidth import BandwidthMonitor
from monitor.latency import Prober, icmp_ping, tcp_ping
from storage.store import NetwatchStore

AlertCallback = Callable[[Alert], None]
HostsCallback = Callable[[list[Host]], None]
LatencyCallback = Callable[[LatencySample], None]
BandwidthCallback = Callable[[BandwidthSample], None]


def build_config(args) -> NetwatchConfig:
    """Turn a parsed argparse namespace into a :class:`NetwatchConfig`."""
    static_hosts: list[str] = []
    static_hosts_file = getattr(args, "static_hosts_file", None)
    if static_hosts_file:
        with open(static_hosts_file) as fh:
            static_hosts = json.load(fh)

    discovery = DiscoveryConfig(
        network_cidr=getattr(args, "cidr", None),
        static_hosts=static_hosts,
        interval_seconds=getattr(args, "discovery_interval", 30.0),
    )
    monitor = MonitorConfig(
        method=getattr(args, "method", "tcp"),
        tcp_port=getattr(args, "tcp_port", 80),
        interval_seconds=getattr(args, "interval", 5.0),
    )
    config = NetwatchConfig(
        discovery=discovery,
        monitor=monitor,
        detect=DetectConfig(),
        iface=getattr(args, "iface", None),
    )
    db_path = getattr(args, "db", None)
    if db_path:
        config.db_path = db_path
    return config


def _make_send_fn(monitor: MonitorConfig) -> Callable[[str, float], Optional[float]]:
    if monitor.method == "icmp":
        return icmp_ping
    return lambda ip, timeout: tcp_ping(ip, timeout, port=monitor.tcp_port)


class NetWatch:
    """Wires discovery, latency/bandwidth monitoring, detection, and storage."""

    def __init__(
        self,
        config: NetwatchConfig,
        store: Optional[NetwatchStore] = None,
        scanner: Optional[ArpScanner] = None,
        prober: Optional[Prober] = None,
        bandwidth: Optional[BandwidthMonitor] = None,
        detector: Optional[AlertDetector] = None,
        on_alert: Optional[AlertCallback] = None,
        on_hosts: Optional[HostsCallback] = None,
        on_latency: Optional[LatencyCallback] = None,
        on_bandwidth: Optional[BandwidthCallback] = None,
    ) -> None:
        self.config = config
        config.ensure_dirs()
        self.store = store or NetwatchStore(config.db_path)
        self.scanner = scanner or ArpScanner(static_hosts=config.discovery.static_hosts)
        self.prober = prober or Prober(send_fn=_make_send_fn(config.monitor))
        self.bandwidth = bandwidth or BandwidthMonitor()
        self.detector = detector or AlertDetector(config.detect)
        self.on_alert = on_alert
        self.on_hosts = on_hosts
        self.on_latency = on_latency
        self.on_bandwidth = on_bandwidth
        self.hosts: dict[str, Host] = {}

    def _emit_alerts(self, alerts: list[Alert]) -> None:
        for alert in alerts:
            self.store.log_alert(alert)
            if self.on_alert is not None:
                self.on_alert(alert)

    def discover(self) -> list[Host]:
        hosts = self.scanner.scan(cidr=self.config.discovery.network_cidr, timeout=self.config.discovery.timeout)
        self._emit_alerts(self.detector.on_discovery(hosts))
        for host in hosts:
            self.hosts[host.ip] = host
            self.store.upsert_host(host)
        if self.on_hosts is not None:
            self.on_hosts(hosts)
        return hosts

    def probe_all(self) -> list[LatencySample]:
        samples = self.prober.probe_many(list(self.hosts.keys()), timeout=self.config.monitor.timeout)
        for sample in samples:
            self.store.log_latency(sample)
            self._emit_alerts(self.detector.on_latency_sample(sample))
            host = self.hosts.get(sample.ip)
            if host is not None:
                host.status = "down" if self.detector.is_down(sample.ip) else "up"
                host.last_seen = sample.ts
                self.store.upsert_host(host)
            if self.on_latency is not None:
                self.on_latency(sample)
        return samples

    def sample_bandwidth(self) -> list[BandwidthSample]:
        samples = self.bandwidth.sample(only_iface=self.config.iface)
        for sample in samples:
            self.store.log_bandwidth(sample)
            self._emit_alerts(self.detector.on_bandwidth_sample(sample))
            if self.on_bandwidth is not None:
                self.on_bandwidth(sample)
        return samples

    def tick(self) -> None:
        """One discovery-less monitoring pass: probe latency and sample bandwidth."""
        self.probe_all()
        self.sample_bandwidth()

    def run_forever(
        self,
        stop_flag: Optional[Callable[[], bool]] = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """Continuous loop: rediscover on the discovery interval, tick otherwise."""
        stop_flag = stop_flag or (lambda: False)
        last_discovery = 0.0
        while not stop_flag():
            now = clock()
            if not self.hosts or now - last_discovery >= self.config.discovery.interval_seconds:
                self.discover()
                last_discovery = now
            self.tick()
            sleep_fn(self.config.monitor.interval_seconds)

    def close(self) -> None:
        self.store.close()
