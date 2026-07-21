const socket = io();

const hostBody = document.getElementById("host-body");
const hostCount = document.getElementById("host-count");
const statusBadge = document.getElementById("status-badge");
const alertList = document.getElementById("alert-list");
const alertCount = document.getElementById("alert-count");
const mUp = document.getElementById("m-up");
const mDown = document.getElementById("m-down");
const mAvgRtt = document.getElementById("m-avg-rtt");

const hosts = new Map(); // ip -> {ip, mac, hostname, status, rtt}
const latencySeries = new Map(); // ip -> [{t, rtt}]
const bandwidthSeries = { t: [], rx: [], tx: [] };
let totalAlerts = 0;
const MAX_POINTS = 60;
const MAX_LINES = 5;

function renderHosts() {
  const rows = [...hosts.values()].sort((a, b) => a.ip.localeCompare(b.ip));
  hostCount.textContent = `${rows.length} hosts`;
  hostBody.innerHTML = rows.map((h) => `
    <tr>
      <td>${h.ip}</td>
      <td>${h.mac || "-"}</td>
      <td>${h.hostname || "-"}</td>
      <td class="status-${h.status}">${h.status}</td>
      <td>${h.rtt != null ? h.rtt.toFixed(1) + " ms" : "-"}</td>
    </tr>
  `).join("") || `<tr><td colspan="5" class="empty">No hosts yet. Start the monitor.</td></tr>`;
}

function upsertHost(h) {
  const existing = hosts.get(h.ip) || {};
  hosts.set(h.ip, { ...existing, ...h });
}

socket.on("hosts", (batch) => {
  for (const h of batch) upsertHost(h);
  renderHosts();
});

socket.on("latency", (batch) => {
  for (const s of batch) {
    const existing = hosts.get(s.ip);
    if (existing) existing.rtt = s.rtt_ms;

    if (!latencySeries.has(s.ip) && latencySeries.size >= MAX_LINES) continue;
    const series = latencySeries.get(s.ip) || [];
    series.push({ t: s.ts, rtt: s.rtt_ms });
    if (series.length > MAX_POINTS) series.shift();
    latencySeries.set(s.ip, series);
  }
  renderHosts();
  updateLatencyChart();
});

socket.on("bandwidth", (batch) => {
  for (const s of batch) {
    bandwidthSeries.t.push(s.ts);
    bandwidthSeries.rx.push(s.rx_bps);
    bandwidthSeries.tx.push(s.tx_bps);
  }
  if (bandwidthSeries.t.length > MAX_POINTS) {
    bandwidthSeries.t.splice(0, bandwidthSeries.t.length - MAX_POINTS);
    bandwidthSeries.rx.splice(0, bandwidthSeries.rx.length - MAX_POINTS);
    bandwidthSeries.tx.splice(0, bandwidthSeries.tx.length - MAX_POINTS);
  }
  updateBandwidthChart();
});

socket.on("alert", (alert) => {
  totalAlerts += 1;
  alertCount.textContent = totalAlerts;
  const li = document.createElement("li");
  li.className = `sev-${alert.severity}`;
  li.innerHTML = `<span class="a-kind">${alert.kind}</span><span class="a-detail">${alert.detail}</span>`;
  alertList.prepend(li);
  while (alertList.children.length > 100) alertList.removeChild(alertList.lastChild);
});

socket.on("stats", (stats) => {
  mUp.textContent = stats.hosts_up ?? 0;
  mDown.textContent = stats.hosts_down ?? 0;
  mAvgRtt.textContent = stats.avg_rtt_ms != null ? stats.avg_rtt_ms.toFixed(1) : "-";
});

const palette = ["#4f9cff", "#36d399", "#f5a524", "#f0556d", "#c792ea"];

const latencyChart = new Chart(document.getElementById("latency-chart"), {
  type: "line",
  data: { labels: [], datasets: [] },
  options: {
    animation: false,
    responsive: true,
    scales: { y: { beginAtZero: true, ticks: { color: "#8b97a7" } }, x: { display: false } },
    plugins: { legend: { labels: { color: "#8b97a7", boxWidth: 10 } } },
  },
});

function updateLatencyChart() {
  const ips = [...latencySeries.keys()];
  latencyChart.data.datasets = ips.map((ip, i) => ({
    label: ip,
    data: latencySeries.get(ip).map((p) => p.rtt),
    borderColor: palette[i % palette.length],
    backgroundColor: "transparent",
    tension: 0.25,
    pointRadius: 0,
  }));
  const longest = ips.reduce((max, ip) => Math.max(max, latencySeries.get(ip).length), 0);
  latencyChart.data.labels = Array.from({ length: longest }, (_, i) => i);
  latencyChart.update();
}

const bandwidthChart = new Chart(document.getElementById("bandwidth-chart"), {
  type: "line",
  data: { labels: [], datasets: [
    { label: "rx bps", data: [], borderColor: palette[0], backgroundColor: "transparent", tension: 0.25, pointRadius: 0 },
    { label: "tx bps", data: [], borderColor: palette[1], backgroundColor: "transparent", tension: 0.25, pointRadius: 0 },
  ] },
  options: {
    animation: false,
    responsive: true,
    scales: { y: { beginAtZero: true, ticks: { color: "#8b97a7" } }, x: { display: false } },
    plugins: { legend: { labels: { color: "#8b97a7", boxWidth: 10 } } },
  },
});

function updateBandwidthChart() {
  bandwidthChart.data.labels = bandwidthSeries.t.map((_, i) => i);
  bandwidthChart.data.datasets[0].data = bandwidthSeries.rx;
  bandwidthChart.data.datasets[1].data = bandwidthSeries.tx;
  bandwidthChart.update();
}

document.getElementById("btn-start").addEventListener("click", async () => {
  const staticHosts = document.getElementById("static-hosts").value
    .split(",").map((s) => s.trim()).filter(Boolean);
  const cidr = document.getElementById("cidr").value.trim() || null;
  const method = document.getElementById("method").value;

  const res = await fetch("/monitor/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ static_hosts: staticHosts, cidr, method }),
  });
  const data = await res.json();
  if (data.ok) {
    statusBadge.textContent = "monitoring";
    statusBadge.classList.add("active");
  }
});

document.getElementById("btn-stop").addEventListener("click", async () => {
  await fetch("/monitor/stop", { method: "POST" });
  statusBadge.textContent = "idle";
  statusBadge.classList.remove("active");
});

renderHosts();

fetch("/api/hosts").then((r) => r.json()).then((rows) => {
  for (const h of rows) upsertHost(h);
  renderHosts();
});
fetch("/api/stats").then((r) => r.json()).then((stats) => {
  if (stats && Object.keys(stats).length) {
    mUp.textContent = stats.hosts_up ?? 0;
    mDown.textContent = stats.hosts_down ?? 0;
    mAvgRtt.textContent = stats.avg_rtt_ms != null ? stats.avg_rtt_ms.toFixed(1) : "-";
  }
});
