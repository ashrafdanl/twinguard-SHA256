#!/usr/bin/env python3
"""
TwinGuard-SHA256: All-in-One Launcher
=======================================
Runs the detection engine + dashboard server in one command.

Usage:
    sudo python3 run.py
    sudo python3 run.py --interface wlan0mon
    sudo python3 run.py --sim          # force simulation mode

Then open: http://127.0.0.1:5000
"""

import os
import sys
import time
import json
import hashlib
import hashlib
import datetime
import argparse
import threading
import subprocess
import requests
from collections import defaultdict
from flask import Flask, request, jsonify, render_template_string

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = MAGENTA = ""
    class Style:
        BRIGHT = RESET_ALL = ""

# ─── CLI Args ─────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="TwinGuard-SHA256 Launcher")
parser.add_argument("--interface", default=None,    help="Wi-Fi interface (e.g. wlan0, wlan0mon)")
parser.add_argument("--sim",       action="store_true", help="Force simulation mode")
parser.add_argument("--port",      default=5000,    type=int, help="Dashboard port (default 5000)")
parser.add_argument("--interval",  default=10,      type=int, help="Scan interval in seconds (default 10)")
args = parser.parse_args()

# ─── Config ───────────────────────────────────────────────────────────────────
LOG_FILE       = "forensic_log.json"
RSSI_THRESHOLD = -49
DASHBOARD_PORT = args.port
SCAN_INTERVAL  = args.interval

def detect_interface():
    """Auto-detect the best available wireless interface."""
    try:
        result = subprocess.run(["iwconfig"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "IEEE" in line:
                iface = line.split()[0]
                return iface
    except Exception:
        pass
    return "wlan0"

INTERFACE = args.interface or detect_interface()
USE_SIM   = args.sim or (not os.path.exists(f"/sys/class/net/{INTERFACE}"))

# ─── Forensic Logger ──────────────────────────────────────────────────────────
class ForensicLogger:
    def __init__(self, log_file):
        self.log_file = log_file
        self.lock = threading.Lock()
        self.entries = []
        if os.path.exists(log_file):
            with open(log_file) as f:
                try:
                    self.entries = json.load(f)
                except json.JSONDecodeError:
                    self.entries = []

    def _sha256(self, data):
        raw = json.dumps(data, sort_keys=True).encode()
        return hashlib.sha256(raw).hexdigest()

    def log(self, event):
        entry = {"timestamp": datetime.datetime.utcnow().isoformat() + "Z", **event}
        entry["sha256_hash"] = self._sha256({k: v for k, v in entry.items()})
        with self.lock:
            self.entries.append(entry)
            with open(self.log_file, "w") as f:
                json.dump(self.entries, f, indent=2)
        return entry

    def get_all(self):
        with self.lock:
            return list(self.entries)

    def verify(self, entry):
        stored = entry.get("sha256_hash", "")
        payload = {k: v for k, v in entry.items() if k != "sha256_hash"}
        computed = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        return computed == stored


# ─── Scanner ──────────────────────────────────────────────────────────────────
def scan_with_iwlist(interface):
    networks = []
    try:
        result = subprocess.run(
            ["sudo", "iwlist", interface, "scan"],
            capture_output=True, text=True, timeout=15
        )
        raw = result.stdout
    except Exception as e:
        print(f"{Fore.RED}[ERROR] iwlist failed: {e}")
        return networks

    current = {}
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("Cell "):
            if current:
                networks.append(current)
            current = {}
            parts = line.split("Address:")
            if len(parts) > 1:
                current["bssid"] = parts[1].strip()
        elif "ESSID:" in line:
            current["ssid"] = line.split('"')[1] if '"' in line else ""
        elif "Signal level=" in line:
            try:
                sig_part = line.split("Signal level=")[1].split(" ")[0]
                current["signal"] = int(sig_part.split("/")[0])
            except (IndexError, ValueError):
                current["signal"] = -100
        elif "Encryption key:" in line:
            current["encryption"] = "WPA2" if "on" in line else "Open"
        elif "Channel:" in line:
            try:
                current["channel"] = int(line.split("Channel:")[1].strip())
            except (IndexError, ValueError):
                current["channel"] = 0
    if current:
        networks.append(current)
    return networks


def simulate_networks():
    import random
    base = [
        {"ssid": "GMI_WiFi",      "bssid": "AA:BB:CC:DD:EE:01", "signal": -65, "encryption": "WPA2", "channel": 6},
        {"ssid": "GMI_WiFi",      "bssid": "AA:BB:CC:DD:EE:02", "signal": -45, "encryption": "Open", "channel": 6},
        {"ssid": "Office_Net",    "bssid": "11:22:33:44:55:66", "signal": -72, "encryption": "WPA2", "channel": 11},
        {"ssid": "TP-Link_Guest", "bssid": "DE:AD:BE:EF:00:01", "signal": -80, "encryption": "WPA2", "channel": 1},
        {"ssid": "Hotspot_Free",  "bssid": "CA:FE:BA:BE:00:01", "signal": -90, "encryption": "Open", "channel": 3},
    ]
    for n in base:
        n["signal"] += random.randint(-3, 3)
    return base


# ─── Detection Engine ─────────────────────────────────────────────────────────
class DetectionEngine:
    def __init__(self, logger, simulate=False):
        self.logger    = logger
        self.simulate  = simulate
        self.known_bssids = {}

    def _scan(self):
        return simulate_networks() if self.simulate else scan_with_iwlist(INTERFACE)

    def _severity(self, reasons):
        if "Open encryption" in reasons and "Duplicate SSID" in reasons:
            return "HIGH"
        if any("Strong signal" in r for r in reasons):
            return "HIGH"
        if len(reasons) >= 2:
            return "MEDIUM"
        return "LOW"

    def analyze(self, networks):
        by_ssid = defaultdict(list)
        for n in networks:
            if n.get("ssid"):
                by_ssid[n["ssid"]].append(n)

        alerts = []
        for ssid, entries in by_ssid.items():
            if len(entries) < 2:
                if ssid not in self.known_bssids:
                    self.known_bssids[ssid] = entries[0].get("bssid", "")
                continue

            trusted = self.known_bssids.get(ssid)
            for ap in entries:
                reasons = ["Duplicate SSID"]
                bssid   = ap.get("bssid", "")
                signal  = ap.get("signal", -100)
                enc     = ap.get("encryption", "WPA2")

                if trusted and bssid != trusted:
                    reasons.append("BSSID mismatch (unknown AP)")
                if enc == "Open":
                    reasons.append("Open encryption")
                if signal > RSSI_THRESHOLD:
                    reasons.append(f"Strong signal anomaly ({signal} dBm)")

                if len(reasons) >= 2:
                    alert = {
                        "type": "ROGUE_AP_DETECTED",
                        "severity": self._severity(reasons),
                        "ssid": ssid,
                        "bssid": bssid,
                        "signal_dbm": signal,
                        "encryption": enc,
                        "reasons": reasons,
                        "trusted_bssid": trusted or "Unknown",
                    }
                    logged = self.logger.log(alert)
                    alerts.append(logged)
        return alerts

    def run_loop(self):
        scan_count = 0
        while True:
            scan_count += 1
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            networks = self._scan()
            print(f"{Fore.WHITE}[{ts}] Scan #{scan_count} — {len(networks)} network(s) found")

            for n in networks:
                sig_color = Fore.RED if n.get("signal", -100) > RSSI_THRESHOLD else Fore.GREEN
                print(f"  {sig_color}● {n.get('ssid','?'):<20} "
                      f"BSSID={n.get('bssid','?')}  "
                      f"Signal={n.get('signal','?')} dBm  "
                      f"Enc={n.get('encryption','?')}")

            alerts = self.analyze(networks)
            if alerts:
                for a in alerts:
                    sev_color = Fore.RED if a["severity"] == "HIGH" else Fore.YELLOW
                    print(f"\n  {sev_color}{Style.BRIGHT}⚠  [{a['severity']}] ROGUE AP: {a['ssid']} "
                          f"({a['bssid']}) — {', '.join(a['reasons'])}")
                    print(f"     SHA-256: {a['sha256_hash'][:40]}...")
            else:
                print(f"  {Fore.GREEN}✓  No rogue APs detected.\n")

            time.sleep(SCAN_INTERVAL)


# ─── Flask Dashboard ──────────────────────────────────────────────────────────
app    = Flask(__name__)
logger = ForensicLogger(LOG_FILE)

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TwinGuard-SHA256 | Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;500;700;900&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:      #060b14;
    --panel:   #0c1628;
    --border:  #1a2f55;
    --accent:  #00d4ff;
    --danger:  #ff3b5c;
    --warning: #ffaa00;
    --safe:    #00ff94;
    --text:    #c8dff5;
    --dim:     #4a6480;
    --mono:    'Share Tech Mono', monospace;
    --sans:    'Exo 2', sans-serif;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:var(--bg); color:var(--text); font-family:var(--sans); min-height:100vh; }
  body::before {
    content:''; position:fixed; inset:0; pointer-events:none; z-index:9999;
    background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,212,255,0.015) 2px,rgba(0,212,255,0.015) 4px);
  }
  header {
    display:flex; align-items:center; justify-content:space-between;
    padding:18px 32px; background:var(--panel);
    border-bottom:1px solid var(--border); position:sticky; top:0; z-index:100;
  }
  .logo { display:flex; align-items:center; gap:14px; }
  .logo-icon {
    width:38px; height:38px; border-radius:8px; font-size:20px;
    background:linear-gradient(135deg,var(--accent),#0056ff);
    display:flex; align-items:center; justify-content:center;
  }
  .logo-text { font-size:20px; font-weight:900; letter-spacing:2px; color:#fff; }
  .logo-sub  { font-family:var(--mono); font-size:10px; color:var(--dim); letter-spacing:3px; }
  .header-right { display:flex; align-items:center; gap:20px; }
  .mode-badge {
    font-family:var(--mono); font-size:11px; padding:4px 12px;
    border-radius:20px; border:1px solid var(--warning); color:var(--warning);
    letter-spacing:2px;
  }
  .mode-badge.live { border-color:var(--safe); color:var(--safe); }
  .status-badge { display:flex; align-items:center; gap:8px; font-family:var(--mono); font-size:12px; color:var(--safe); }
  .pulse { width:8px; height:8px; border-radius:50%; background:var(--safe); animation:pulse 2s infinite; }
  @keyframes pulse {
    0%,100% { box-shadow:0 0 0 0 rgba(0,255,148,0.5); }
    50%      { box-shadow:0 0 0 8px rgba(0,255,148,0); }
  }
  main { padding:32px; max-width:1280px; margin:0 auto; }
  .stats-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:24px; }
  .stat-card {
    background:var(--panel); border:1px solid var(--border);
    border-radius:12px; padding:24px; position:relative; overflow:hidden;
    transition:transform .2s, border-color .2s;
  }
  .stat-card:hover { transform:translateY(-2px); border-color:var(--accent); }
  .stat-card::after { content:''; position:absolute; bottom:0; left:0; right:0; height:3px; }
  .stat-card.total::after  { background:var(--accent); }
  .stat-card.high::after   { background:var(--danger); }
  .stat-card.medium::after { background:var(--warning); }
  .stat-card.low::after    { background:var(--safe); }
  .stat-label { font-size:11px; letter-spacing:3px; color:var(--dim); text-transform:uppercase; margin-bottom:10px; }
  .stat-value { font-size:42px; font-weight:900; line-height:1; }
  .stat-card.total  .stat-value { color:var(--accent); }
  .stat-card.high   .stat-value { color:var(--danger); }
  .stat-card.medium .stat-value { color:var(--warning); }
  .stat-card.low    .stat-value { color:var(--safe); }
  .refresh-bar { height:2px; background:var(--border); margin-bottom:20px; border-radius:2px; overflow:hidden; }
  .refresh-fill { height:100%; background:var(--accent); animation:refill 10s linear infinite; transform-origin:left; }
  @keyframes refill { from{transform:scaleX(1)} to{transform:scaleX(0)} }
  .controls { display:flex; gap:12px; margin-bottom:20px; align-items:center; flex-wrap:wrap; }
  .btn {
    padding:10px 20px; border-radius:8px; border:1px solid var(--border);
    background:var(--panel); color:var(--text); font-family:var(--sans);
    font-size:13px; font-weight:500; cursor:pointer; transition:all .2s; letter-spacing:1px;
  }
  .btn:hover     { border-color:var(--accent); color:var(--accent); }
  .btn.primary   { background:var(--accent); color:#000; border-color:var(--accent); font-weight:700; }
  .btn.primary:hover { background:#00aacc; }
  .search {
    flex:1; min-width:200px; padding:10px 16px; border-radius:8px;
    border:1px solid var(--border); background:var(--panel);
    color:var(--text); font-family:var(--mono); font-size:13px; outline:none;
  }
  .search:focus { border-color:var(--accent); }
  .search::placeholder { color:var(--dim); }
  .table-wrap { background:var(--panel); border:1px solid var(--border); border-radius:12px; overflow:hidden; }
  table { width:100%; border-collapse:collapse; }
  th {
    padding:14px 16px; text-align:left; font-family:var(--mono); font-size:11px;
    letter-spacing:2px; color:var(--dim); background:#0a1520;
    border-bottom:1px solid var(--border); text-transform:uppercase;
  }
  td { padding:14px 16px; font-size:13px; border-bottom:1px solid rgba(26,47,85,0.5); vertical-align:middle; }
  tr:last-child td { border-bottom:none; }
  tr:hover td { background:rgba(0,212,255,0.04); }
  tr.new-row td { animation:flashRow .8s ease; }
  @keyframes flashRow { from{background:rgba(255,59,92,0.2)} to{background:transparent} }
  .badge {
    display:inline-block; padding:3px 10px; border-radius:20px;
    font-family:var(--mono); font-size:11px; font-weight:700; letter-spacing:1px;
  }
  .badge.HIGH   { background:rgba(255,59,92,0.15); color:var(--danger); border:1px solid var(--danger); }
  .badge.MEDIUM { background:rgba(255,170,0,0.15);  color:var(--warning);border:1px solid var(--warning);}
  .badge.LOW    { background:rgba(0,255,148,0.1);   color:var(--safe);   border:1px solid var(--safe); }
  .bssid   { font-family:var(--mono); font-size:12px; color:var(--accent); }
  .hash    { font-family:var(--mono); font-size:10px; color:var(--dim); }
  .int-ok  { color:var(--safe);   font-family:var(--mono); font-size:12px; }
  .int-fail{ color:var(--danger); font-family:var(--mono); font-size:12px; }
  .reasons { font-size:12px; color:var(--dim); }
  .ts      { font-family:var(--mono); font-size:11px; color:var(--dim); }
  .empty-state { text-align:center; padding:80px 20px; color:var(--dim); font-family:var(--mono); }
  .empty-state .icon { font-size:48px; margin-bottom:16px; }
  footer { text-align:center; padding:24px; font-family:var(--mono); font-size:11px; color:var(--dim); border-top:1px solid var(--border); margin-top:40px; }
</style>
</head>
<body>
<header>
  <div class="logo">
    <div class="logo-icon">🛡</div>
    <div>
      <div class="logo-text">TWINGUARD-SHA256</div>
      <div class="logo-sub">ROGUE AP DETECTION &amp; FORENSIC DASHBOARD</div>
    </div>
  </div>
  <div class="header-right">
    <div class="mode-badge" id="mode-badge">SIMULATION</div>
    <div class="status-badge"><div class="pulse"></div>MONITORING ACTIVE</div>
  </div>
</header>

<main>
  <div class="stats-grid">
    <div class="stat-card total">
      <div class="stat-label">Total Alerts</div>
      <div class="stat-value" id="stat-total">0</div>
    </div>
    <div class="stat-card high">
      <div class="stat-label">High Severity</div>
      <div class="stat-value" id="stat-high">0</div>
    </div>
    <div class="stat-card medium">
      <div class="stat-label">Medium Severity</div>
      <div class="stat-value" id="stat-med">0</div>
    </div>
    <div class="stat-card low">
      <div class="stat-label">Low Severity</div>
      <div class="stat-value" id="stat-low">0</div>
    </div>
  </div>

  <div class="refresh-bar"><div class="refresh-fill" id="rfill"></div></div>

  <div class="controls">
    <button class="btn primary" onclick="loadData()">↻ Refresh</button>
    <input class="search" id="search" type="text" placeholder="Filter by SSID or BSSID..." oninput="filterTable()">
    <button class="btn" onclick="exportLogs()">⬇ Export JSON</button>
  </div>

  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Timestamp (UTC)</th>
          <th>Severity</th>
          <th>SSID</th>
          <th>Rogue BSSID</th>
          <th>Signal</th>
          <th>Encryption</th>
          <th>Detection Reasons</th>
          <th>SHA-256 Integrity</th>
        </tr>
      </thead>
      <tbody id="log-body">
        <tr><td colspan="8" class="empty-state">
          <div class="icon">📡</div>Waiting for detections...
        </td></tr>
      </tbody>
    </table>
  </div>
</main>

<footer>TwinGuard-SHA256 &nbsp;|&nbsp; GMI Final Year Project JAN 2026 &nbsp;|&nbsp; SEM 4 DCBS 6</footer>

<script>
let allLogs = [], prevCount = 0;

async function loadStats() {
  const r = await fetch('/api/stats');
  const d = await r.json();
  document.getElementById('stat-total').textContent = d.total_alerts;
  document.getElementById('stat-high').textContent  = d.high;
  document.getElementById('stat-med').textContent   = d.medium;
  document.getElementById('stat-low').textContent   = d.low;
  const mb = document.getElementById('mode-badge');
  mb.textContent = d.mode;
  mb.className = 'mode-badge' + (d.mode === 'LIVE' ? ' live' : '');
}

async function loadData() {
  try {
    await loadStats();
    const r = await fetch('/api/logs');
    allLogs = await r.json();
    renderTable(allLogs.slice().reverse(), allLogs.length > prevCount);
    prevCount = allLogs.length;
  } catch(e) {
    document.getElementById('log-body').innerHTML =
      '<tr><td colspan="8" class="empty-state"><div class="icon">⚠️</div>Backend not reachable.</td></tr>';
  }
}

function renderTable(logs, highlight=false) {
  const tbody = document.getElementById('log-body');
  if (!logs.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-state"><div class="icon">✅</div>No rogue APs detected yet.</td></tr>';
    return;
  }
  tbody.innerHTML = logs.map((l, i) => {
    const ts    = (l.timestamp||'').replace('T',' ').replace('Z','');
    const sev   = l.severity || 'LOW';
    const hash  = l.sha256_hash || '';
    const intOk = l.integrity_ok;
    const intStr = intOk === undefined ? '<span class="hash">—</span>'
                 : intOk ? '<span class="int-ok">✓ VALID</span>'
                          : '<span class="int-fail">✗ TAMPERED</span>';
    const newRow = (highlight && i === 0) ? ' class="new-row"' : '';
    return `<tr${newRow}>
      <td class="ts">${ts}</td>
      <td><span class="badge ${sev}">${sev}</span></td>
      <td><strong>${l.ssid||'?'}</strong></td>
      <td class="bssid">${l.bssid||'?'}</td>
      <td>${l.signal_dbm||'?'} dBm</td>
      <td>${l.encryption||'?'}</td>
      <td class="reasons">${(l.reasons||[]).join(' · ')}</td>
      <td>${intStr}<br><span class="hash">${hash.substring(0,20)}…</span></td>
    </tr>`;
  }).join('');
}

function filterTable() {
  const q = document.getElementById('search').value.toLowerCase();
  renderTable(allLogs.filter(l =>
    (l.ssid||'').toLowerCase().includes(q) || (l.bssid||'').toLowerCase().includes(q)
  ).slice().reverse());
}

function exportLogs() {
  const blob = new Blob([JSON.stringify(allLogs, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = 'twinguard_forensic_log.json'; a.click();
}

loadData();
setInterval(loadData, 10000);
setInterval(() => {
  const el = document.getElementById('rfill');
  el.style.animation = 'none'; el.offsetHeight; el.style.animation = '';
}, 10000);
</script>
</body>
</html>"""

@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML)

@app.route("/api/alert", methods=["POST"])
def receive_alert():
    data = request.get_json(force=True)
    logger.entries.append(data)
    return jsonify({"status": "received"}), 200

@app.route("/api/logs", methods=["GET"])
def get_logs():
    logs = logger.get_all()
    for e in logs:
        e["integrity_ok"] = logger.verify(e)
    return jsonify(logs)

@app.route("/api/stats", methods=["GET"])
def get_stats():
    logs = logger.get_all()
    return jsonify({
        "total_alerts": len(logs),
        "high":   sum(1 for l in logs if l.get("severity") == "HIGH"),
        "medium": sum(1 for l in logs if l.get("severity") == "MEDIUM"),
        "low":    sum(1 for l in logs if l.get("severity") == "LOW"),
        "mode":   "SIMULATION" if USE_SIM else "LIVE",
    })

@app.route("/api/verify/<sha256_hash>", methods=["GET"])
def verify_entry(sha256_hash):
    for e in logger.get_all():
        if e.get("sha256_hash") == sha256_hash:
            return jsonify({"found": True, "integrity_ok": logger.verify(e), "entry": e})
    return jsonify({"found": False}), 404


# ─── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'═'*55}")
    print(f"  TwinGuard-SHA256 — All-in-One Launcher")
    print(f"{'═'*55}{Style.RESET_ALL}")
    print(f"  Interface : {Fore.YELLOW}{INTERFACE}{Style.RESET_ALL}")
    print(f"  Mode      : {Fore.GREEN if not USE_SIM else Fore.YELLOW}{'LIVE' if not USE_SIM else 'SIMULATION'}{Style.RESET_ALL}")
    print(f"  Dashboard : {Fore.CYAN}http://127.0.0.1:{DASHBOARD_PORT}{Style.RESET_ALL}")
    print(f"  Interval  : {SCAN_INTERVAL}s")
    print(f"{'═'*55}\n")

    # Start detector in background thread
    engine = DetectionEngine(logger, simulate=USE_SIM)
    detector_thread = threading.Thread(target=engine.run_loop, daemon=True)
    detector_thread.start()

    # Small delay so first scan output appears before Flask banner
    time.sleep(1)

    # Start Flask dashboard (blocking)
    import logging as pylogging
    pylogging.getLogger("werkzeug").setLevel(pylogging.ERROR)  # suppress Flask request logs
    app.run(host="0.0.0.0", port=DASHBOARD_PORT, debug=False, use_reloader=False)