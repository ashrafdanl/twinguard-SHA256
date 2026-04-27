#!/usr/bin/env python3
"""
TwinGuard-SHA256: Dashboard Server
====================================
Flask backend that:
  - Receives alerts from the detection engine via POST /api/alert
  - Serves the web dashboard UI at GET /
  - Exposes forensic log data via GET /api/logs
  - Verifies SHA-256 integrity of each log entry

Install:
    pip install flask colorama

Run:
    python3 dashboard_server.py
Then open: http://127.0.0.1:5000
"""

import json
import hashlib
import os
from datetime import datetime, UTC

datetime.now(UTC)
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
LOG_FILE = "forensic_log.json"

# ─── Helpers ──────────────────────────────────────────────────────────────────
def load_logs():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE) as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

def verify_sha256(entry: dict) -> bool:
    stored_hash = entry.get("sha256_hash", "")
    check = {k: v for k, v in entry.items() if k != "sha256_hash"}
    raw = json.dumps(check, sort_keys=True).encode()
    computed = hashlib.sha256(raw).hexdigest()
    return computed == stored_hash

# ─── In-memory alert store (also backed to file by detector.py) ───────────────
alerts_in_memory = load_logs()

# ─── API Routes ───────────────────────────────────────────────────────────────
@app.route("/api/alert", methods=["POST"])
def receive_alert():
    data = request.get_json(force=True)
    alerts_in_memory.append(data)
    severity = data.get("severity", "LOW")
    ssid     = data.get("ssid", "?")
    print(f"[ALERT] [{severity}] Rogue AP detected — SSID: {ssid}")
    return jsonify({"status": "received"}), 200

@app.route("/api/logs", methods=["GET"])
def get_logs():
    logs = load_logs()
    for entry in logs:
        entry["integrity_ok"] = verify_sha256(entry)
    return jsonify(logs)

@app.route("/api/stats", methods=["GET"])
def get_stats():
    logs = load_logs()
    total   = len(logs)
    high    = sum(1 for l in logs if l.get("severity") == "HIGH")
    medium  = sum(1 for l in logs if l.get("severity") == "MEDIUM")
    low     = sum(1 for l in logs if l.get("severity") == "LOW")
    return jsonify({
        "total_alerts": total,
        "high": high,
        "medium": medium,
        "low": low,
        "last_updated": datetime.utcnow().isoformat() + "Z"
    })

@app.route("/api/verify/<sha256_hash>", methods=["GET"])
def verify_entry(sha256_hash):
    logs = load_logs()
    for entry in logs:
        if entry.get("sha256_hash") == sha256_hash:
            ok = verify_sha256(entry)
            return jsonify({"found": True, "integrity_ok": ok, "entry": entry})
    return jsonify({"found": False}), 404

# ─── Dashboard HTML (served at /) ─────────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TwinGuard-SHA256 | Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;500;700;900&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:       #060b14;
    --panel:    #0c1628;
    --border:   #1a2f55;
    --accent:   #00d4ff;
    --danger:   #ff3b5c;
    --warning:  #ffaa00;
    --safe:     #00ff94;
    --text:     #c8dff5;
    --dim:      #4a6480;
    --mono:     'Share Tech Mono', monospace;
    --sans:     'Exo 2', sans-serif;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
  }

  /* Scanline effect */
  body::before {
    content:'';
    position:fixed; inset:0;
    background: repeating-linear-gradient(0deg,
      transparent, transparent 2px,
      rgba(0,212,255,0.015) 2px, rgba(0,212,255,0.015) 4px);
    pointer-events: none;
    z-index: 9999;
  }

  header {
    display:flex; align-items:center; justify-content:space-between;
    padding: 18px 32px;
    background: var(--panel);
    border-bottom: 1px solid var(--border);
    position:sticky; top:0; z-index:100;
  }
  .logo { display:flex; align-items:center; gap:14px; }
  .logo-icon {
    width:38px; height:38px;
    background: linear-gradient(135deg, var(--accent), #0056ff);
    border-radius:8px;
    display:flex; align-items:center; justify-content:center;
    font-size:20px;
  }
  .logo-text { font-size:20px; font-weight:900; letter-spacing:2px; color:#fff; }
  .logo-sub  { font-family:var(--mono); font-size:10px; color:var(--dim); letter-spacing:3px; }
  .status-badge {
    display:flex; align-items:center; gap:8px;
    font-family:var(--mono); font-size:12px; color:var(--safe);
  }
  .pulse {
    width:8px; height:8px; border-radius:50%;
    background:var(--safe);
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0%,100% { box-shadow:0 0 0 0 rgba(0,255,148,0.5); }
    50%      { box-shadow:0 0 0 8px rgba(0,255,148,0); }
  }

  main { padding:32px; max-width:1280px; margin:0 auto; }

  /* Stat cards */
  .stats-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:32px; }
  .stat-card {
    background:var(--panel);
    border:1px solid var(--border);
    border-radius:12px;
    padding:24px;
    position:relative; overflow:hidden;
    transition:transform .2s, border-color .2s;
  }
  .stat-card:hover { transform:translateY(-2px); border-color:var(--accent); }
  .stat-card::after {
    content:''; position:absolute; bottom:0; left:0; right:0; height:3px;
  }
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

  /* Controls */
  .controls { display:flex; gap:12px; margin-bottom:24px; align-items:center; flex-wrap:wrap; }
  .btn {
    padding:10px 20px; border-radius:8px; border:1px solid var(--border);
    background:var(--panel); color:var(--text);
    font-family:var(--sans); font-size:13px; font-weight:500;
    cursor:pointer; transition:all .2s; letter-spacing:1px;
  }
  .btn:hover        { border-color:var(--accent); color:var(--accent); }
  .btn.primary      { background:var(--accent); color:#000; border-color:var(--accent); font-weight:700; }
  .btn.primary:hover{ background:#00aacc; }
  .btn.danger       { background:var(--danger); color:#fff; border-color:var(--danger); }
  .search {
    flex:1; min-width:200px;
    padding:10px 16px; border-radius:8px;
    border:1px solid var(--border); background:var(--panel);
    color:var(--text); font-family:var(--mono); font-size:13px;
    outline:none;
  }
  .search:focus { border-color:var(--accent); }
  .search::placeholder { color:var(--dim); }

  /* Log table */
  .table-wrap {
    background:var(--panel); border:1px solid var(--border);
    border-radius:12px; overflow:hidden;
  }
  table { width:100%; border-collapse:collapse; }
  th {
    padding:14px 16px; text-align:left;
    font-family:var(--mono); font-size:11px; letter-spacing:2px;
    color:var(--dim); background:#0a1520;
    border-bottom:1px solid var(--border);
    text-transform:uppercase;
  }
  td {
    padding:14px 16px; font-size:13px;
    border-bottom:1px solid rgba(26,47,85,0.5);
    vertical-align:middle;
  }
  tr:last-child td { border-bottom:none; }
  tr:hover td { background:rgba(0,212,255,0.04); }

  .badge {
    display:inline-block; padding:3px 10px; border-radius:20px;
    font-family:var(--mono); font-size:11px; font-weight:700; letter-spacing:1px;
  }
  .badge.HIGH   { background:rgba(255,59,92,0.15); color:var(--danger); border:1px solid var(--danger); }
  .badge.MEDIUM { background:rgba(255,170,0,0.15);  color:var(--warning); border:1px solid var(--warning); }
  .badge.LOW    { background:rgba(0,255,148,0.1);   color:var(--safe);    border:1px solid var(--safe); }

  .bssid    { font-family:var(--mono); font-size:12px; color:var(--accent); }
  .hash     { font-family:var(--mono); font-size:10px; color:var(--dim); }
  .int-ok   { color:var(--safe);   font-family:var(--mono); font-size:12px; }
  .int-fail { color:var(--danger); font-family:var(--mono); font-size:12px; }

  .reasons  { font-size:12px; color:var(--dim); }

  .empty-state {
    text-align:center; padding:80px 20px;
    color:var(--dim); font-family:var(--mono);
  }
  .empty-state .icon { font-size:48px; margin-bottom:16px; }

  .ts { font-family:var(--mono); font-size:11px; color:var(--dim); }

  /* Auto-refresh indicator */
  .refresh-bar {
    height:2px; background:var(--border); margin-bottom:24px; border-radius:2px; overflow:hidden;
  }
  .refresh-fill {
    height:100%; background:var(--accent); width:100%;
    animation: refill 10s linear infinite;
    transform-origin: left;
  }
  @keyframes refill {
    from { transform:scaleX(1); }
    to   { transform:scaleX(0); }
  }

  footer {
    text-align:center; padding:24px;
    font-family:var(--mono); font-size:11px; color:var(--dim);
    border-top:1px solid var(--border); margin-top:40px;
  }
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon">🛡</div>
    <div>
      <div class="logo-text">TWINGUARD</div>
      <div class="logo-sub">SHA-256 FORENSIC DASHBOARD</div>
    </div>
  </div>
  <div class="status-badge">
    <div class="pulse"></div>
    MONITORING ACTIVE
  </div>
</header>

<main>
  <div class="stats-grid">
    <div class="stat-card total">
      <div class="stat-label">Total Alerts</div>
      <div class="stat-value" id="stat-total">—</div>
    </div>
    <div class="stat-card high">
      <div class="stat-label">High Severity</div>
      <div class="stat-value" id="stat-high">—</div>
    </div>
    <div class="stat-card medium">
      <div class="stat-label">Medium Severity</div>
      <div class="stat-value" id="stat-med">—</div>
    </div>
    <div class="stat-card low">
      <div class="stat-label">Low Severity</div>
      <div class="stat-value" id="stat-low">—</div>
    </div>
  </div>

  <div class="refresh-bar"><div class="refresh-fill" id="refresh-fill"></div></div>

  <div class="controls">
    <button class="btn primary" onclick="loadData()">↻ Refresh Now</button>
    <input class="search" id="search" type="text" placeholder="Filter by SSID or BSSID..." oninput="filterTable()">
    <button class="btn" onclick="exportLogs()">⬇ Export JSON</button>
    <button class="btn danger" onclick="clearTable()">✕ Clear View</button>
  </div>

  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Severity</th>
          <th>SSID</th>
          <th>Rogue BSSID</th>
          <th>Signal</th>
          <th>Encryption</th>
          <th>Reasons</th>
          <th>SHA-256 Integrity</th>
        </tr>
      </thead>
      <tbody id="log-body">
        <tr><td colspan="8" class="empty-state">
          <div class="icon">📡</div>
          Loading forensic logs...
        </td></tr>
      </tbody>
    </table>
  </div>
</main>

<footer>
  TwinGuard-SHA256 &nbsp;|&nbsp; GMI Final Year Project JAN 2026 &nbsp;|&nbsp; SEM 4 DCBS 6
</footer>

<script>
let allLogs = [];

async function loadStats() {
  try {
    const r = await fetch('/api/stats');
    const d = await r.json();
    document.getElementById('stat-total').textContent = d.total_alerts;
    document.getElementById('stat-high').textContent  = d.high;
    document.getElementById('stat-med').textContent   = d.medium;
    document.getElementById('stat-low').textContent   = d.low;
  } catch(e) {}
}

async function loadData() {
  await loadStats();
  try {
    const r = await fetch('/api/logs');
    allLogs = await r.json();
    renderTable(allLogs.slice().reverse());  // newest first
  } catch(e) {
    document.getElementById('log-body').innerHTML =
      '<tr><td colspan="8" class="empty-state"><div class="icon">⚠️</div>Could not connect to backend.</td></tr>';
  }
}

function renderTable(logs) {
  const tbody = document.getElementById('log-body');
  if (!logs.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-state">' +
      '<div class="icon">✅</div>No rogue APs detected yet.</td></tr>';
    return;
  }
  tbody.innerHTML = logs.map(l => {
    const ts     = l.timestamp ? l.timestamp.replace('T',' ').replace('Z','') : '—';
    const sev    = l.severity || 'LOW';
    const hash   = l.sha256_hash || '';
    const intOk  = l.integrity_ok;
    const intStr = intOk === undefined ? '<span class="hash">N/A</span>'
                 : intOk ? '<span class="int-ok">✓ VALID</span>'
                          : '<span class="int-fail">✗ TAMPERED</span>';
    const reasons = (l.reasons || []).join(', ');
    return `<tr>
      <td class="ts">${ts}</td>
      <td><span class="badge ${sev}">${sev}</span></td>
      <td><strong>${l.ssid || '?'}</strong></td>
      <td class="bssid">${l.bssid || '?'}</td>
      <td>${l.signal_dbm || '?'} dBm</td>
      <td>${l.encryption || '?'}</td>
      <td class="reasons">${reasons}</td>
      <td>${intStr}<br><span class="hash">${hash.substring(0,16)}…</span></td>
    </tr>`;
  }).join('');
}

function filterTable() {
  const q = document.getElementById('search').value.toLowerCase();
  const filtered = allLogs.filter(l =>
    (l.ssid || '').toLowerCase().includes(q) ||
    (l.bssid || '').toLowerCase().includes(q)
  );
  renderTable(filtered.slice().reverse());
}

function exportLogs() {
  const blob = new Blob([JSON.stringify(allLogs, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'twinguard_forensic_log.json';
  a.click();
}

function clearTable() {
  document.getElementById('log-body').innerHTML =
    '<tr><td colspan="8" class="empty-state"><div class="icon">🧹</div>View cleared (logs preserved on disk).</td></tr>';
}

// Auto-refresh every 10 seconds
loadData();
setInterval(loadData, 10000);

// Restart animation
setInterval(() => {
  const el = document.getElementById('refresh-fill');
  el.style.animation = 'none';
  el.offsetHeight; // reflow
  el.style.animation = '';
}, 10000);
</script>
</body>
</html>"""

@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML)


if __name__ == "__main__":
    print("\n  TwinGuard-SHA256 — Dashboard Server")
    print("  ─────────────────────────────────────")
    print("  Open: http://127.0.0.1:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=False)