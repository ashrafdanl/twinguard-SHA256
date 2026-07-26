#!/usr/bin/env python3
"""
TwinGuard-SHA256: Dashboard Server
====================================
Features:
  - Receives alerts from detection engine via POST /api/alert
  - Serves web dashboard at GET /
  - Light / Dark mode toggle
  - Log retention: auto-delete entries older than X days
  - SHA-256 integrity verification fix (no more false TAMPERED)

Install:
    pip install flask

Run:
    python3 dashboard_server.py
Then open: http://127.0.0.1:5000
"""

import json, hashlib, os, threading, time
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify, render_template_string

app      = Flask(__name__)
LOG_FILE = "forensic_log.json"
CFG_FILE = "twinguard_config.json"
log_lock = threading.Lock()

# ── Config ────────────────────────────────────────────────────────────────────
def load_config():
    defaults = {"retention_days": 30}
    if not os.path.exists(CFG_FILE):
        return defaults
    try:
        with open(CFG_FILE) as f:
            return {**defaults, **json.load(f)}
    except Exception:
        return defaults

def save_config(cfg):
    with open(CFG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)

# ── Log helpers ───────────────────────────────────────────────────────────────
def load_logs():
    if not os.path.exists(LOG_FILE):
        return []
    with log_lock:
        try:
            with open(LOG_FILE) as f:
                return json.load(f)
        except Exception:
            return []

def save_logs(entries):
    with log_lock:
        with open(LOG_FILE, "w") as f:
            json.dump(entries, f, indent=2)

def verify_sha256(entry):
    """Verify integrity. Strip sha256_hash AND integrity_ok before recomputing."""
    stored  = entry.get("sha256_hash", "")
    payload = {k: v for k, v in entry.items()
               if k not in ("sha256_hash", "integrity_ok")}
    computed = hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode()
    ).hexdigest()
    return computed == stored

# ── Retention engine (runs every hour) ───────────────────────────────────────
def purge_old_logs():
    while True:
        try:
            cfg    = load_config()
            days   = int(cfg.get("retention_days", 30))
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            entries = load_logs()
            kept = []
            for e in entries:
                try:
                    ts = datetime.fromisoformat(e.get("timestamp","").replace("Z","+00:00"))
                    if ts >= cutoff:
                        kept.append(e)
                except Exception:
                    kept.append(e)
            removed = len(entries) - len(kept)
            if removed > 0:
                save_logs(kept)
                print(f"[Retention] Purged {removed} log(s) older than {days} day(s).")
        except Exception as ex:
            print(f"[Retention] Error: {ex}")
        time.sleep(3600)

threading.Thread(target=purge_old_logs, daemon=True).start()

# ── API ───────────────────────────────────────────────────────────────────────
@app.route("/api/alert", methods=["POST"])
def receive_alert():
    data = request.get_json(force=True)
    entries = load_logs()
    entries.append(data)
    save_logs(entries)
    print(f"[ALERT] [{data.get('severity','?')}] {data.get('ssid','?')}")
    return jsonify({"status": "received"}), 200

@app.route("/api/logs", methods=["GET"])
def get_logs():
    entries = load_logs()
    result  = []
    for e in entries:
        copy = dict(e)
        copy["integrity_ok"] = verify_sha256(e)  # verify ORIGINAL, attach to COPY
        result.append(copy)
    return jsonify(result)

@app.route("/api/stats", methods=["GET"])
def get_stats():
    logs = load_logs()
    cfg  = load_config()
    return jsonify({
        "total_alerts":   len(logs),
        "high":           sum(1 for l in logs if l.get("severity") == "HIGH"),
        "medium":         sum(1 for l in logs if l.get("severity") == "MEDIUM"),
        "low":            sum(1 for l in logs if l.get("severity") == "LOW"),
        "retention_days": cfg.get("retention_days", 30),
        "last_updated":   datetime.now(timezone.utc).isoformat(),
    })

@app.route("/api/retention", methods=["GET"])
def get_retention():
    return jsonify(load_config())

@app.route("/api/retention", methods=["POST"])
def set_retention():
    data = request.get_json(force=True)
    try:
        days = int(data.get("retention_days", 30))
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid value"}), 400
    if days < 1:
        return jsonify({"error": "Must be >= 1"}), 400
    cfg = load_config()
    cfg["retention_days"] = days
    save_config(cfg)
    print(f"[Config] Retention set to {days} day(s).")
    return jsonify({"status": "ok", "retention_days": days})

@app.route("/api/verify/<sha256_hash>", methods=["GET"])
def verify_entry(sha256_hash):
    for e in load_logs():
        if e.get("sha256_hash") == sha256_hash:
            return jsonify({"found": True, "integrity_ok": verify_sha256(e), "entry": e})
    return jsonify({"found": False}), 404

# ── Dashboard HTML ────────────────────────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TwinGuard-SHA256 | Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;500;700;900&display=swap" rel="stylesheet">
<style>
:root {
  --accent:#00d4ff; --danger:#ff3b5c; --warning:#ffaa00; --safe:#00ff94;
  --mono:'Share Tech Mono',monospace; --sans:'Exo 2',sans-serif;
  --radius:12px; --t:.25s ease;
}
[data-theme="dark"]  { --bg:#060b14; --panel:#0c1628; --panel2:#0a1520; --border:#1a2f55; --text:#c8dff5; --dim:#4a6480; --inp:#0c1628; }
[data-theme="light"] { --bg:#f0f4fa; --panel:#ffffff; --panel2:#e8eef8; --border:#c8d8ee; --text:#1a2a40; --dim:#7090b0; --inp:#f8faff; }

*{margin:0;padding:0;box-sizing:border-box;}
body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh;transition:background var(--t),color var(--t);}
[data-theme="dark"] body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:9999;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,212,255,.012) 2px,rgba(0,212,255,.012) 4px);}

header{display:flex;align-items:center;justify-content:space-between;padding:16px 32px;
  background:var(--panel);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100;
  transition:background var(--t),border-color var(--t);}
.logo{display:flex;align-items:center;gap:14px;}
.logo-icon{width:38px;height:38px;border-radius:8px;font-size:20px;
  background:linear-gradient(135deg,var(--accent),#0056ff);display:flex;align-items:center;justify-content:center;}
.logo-text{font-size:20px;font-weight:900;letter-spacing:2px;color:var(--text);}
.logo-sub{font-family:var(--mono);font-size:10px;color:var(--dim);letter-spacing:3px;}
.header-right{display:flex;align-items:center;gap:16px;}
.theme-toggle{background:var(--panel2);border:1px solid var(--border);border-radius:20px;
  padding:6px 14px;cursor:pointer;font-family:var(--mono);font-size:12px;color:var(--text);
  display:flex;align-items:center;gap:6px;transition:all var(--t);}
.theme-toggle:hover{border-color:var(--accent);color:var(--accent);}
.status-badge{display:flex;align-items:center;gap:8px;font-family:var(--mono);font-size:12px;color:var(--safe);}
.pulse{width:8px;height:8px;border-radius:50%;background:var(--safe);animation:pulse 2s infinite;}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(0,255,148,.5);}50%{box-shadow:0 0 0 8px rgba(0,255,148,0);}}

main{padding:32px;max-width:1280px;margin:0 auto;}

.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px;}
.stat-card{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);
  padding:24px;position:relative;overflow:hidden;transition:transform .2s,border-color .2s,background var(--t);}
.stat-card:hover{transform:translateY(-2px);border-color:var(--accent);}
.stat-card::after{content:'';position:absolute;bottom:0;left:0;right:0;height:3px;}
.stat-card.total::after{background:var(--accent);}  .stat-card.high::after{background:var(--danger);}
.stat-card.medium::after{background:var(--warning);} .stat-card.low::after{background:var(--safe);}
.stat-label{font-size:11px;letter-spacing:3px;color:var(--dim);text-transform:uppercase;margin-bottom:10px;}
.stat-value{font-size:42px;font-weight:900;line-height:1;}
.stat-card.total .stat-value{color:var(--accent);}   .stat-card.high .stat-value{color:var(--danger);}
.stat-card.medium .stat-value{color:var(--warning);} .stat-card.low .stat-value{color:var(--safe);}

/* Retention panel */
.retention-panel{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);
  padding:18px 24px;margin-bottom:24px;display:flex;align-items:center;gap:16px;flex-wrap:wrap;
  transition:background var(--t);}
.ret-label{font-family:var(--mono);font-size:11px;letter-spacing:2px;color:var(--dim);
  text-transform:uppercase;white-space:nowrap;}
.ret-desc{font-size:13px;color:var(--text);flex:1;min-width:180px;}
.ret-wrap{display:flex;align-items:center;gap:10px;}
.ret-input{width:72px;padding:8px 10px;border-radius:8px;border:1px solid var(--border);
  background:var(--inp);color:var(--text);font-family:var(--mono);font-size:14px;
  text-align:center;outline:none;transition:border-color .2s;}
.ret-input:focus{border-color:var(--accent);}
.ret-unit{font-family:var(--mono);font-size:12px;color:var(--dim);}
.ret-status{font-family:var(--mono);font-size:12px;}
.ret-status.ok{color:var(--safe);} .ret-status.err{color:var(--danger);}

.refresh-bar{height:2px;background:var(--border);margin-bottom:20px;border-radius:2px;overflow:hidden;}
.refresh-fill{height:100%;background:var(--accent);animation:refill 10s linear infinite;transform-origin:left;}
@keyframes refill{from{transform:scaleX(1)}to{transform:scaleX(0)}}

.controls{display:flex;gap:12px;margin-bottom:20px;align-items:center;flex-wrap:wrap;}
.btn{padding:10px 20px;border-radius:8px;border:1px solid var(--border);background:var(--panel);
  color:var(--text);font-family:var(--sans);font-size:13px;font-weight:500;cursor:pointer;
  transition:all .2s;letter-spacing:1px;}
.btn:hover{border-color:var(--accent);color:var(--accent);}
.btn.primary{background:var(--accent);color:#000;border-color:var(--accent);font-weight:700;}
.btn.primary:hover{opacity:.85;}
.btn.save{background:var(--safe);color:#000;border-color:var(--safe);font-weight:700;}
.btn.save:hover{opacity:.85;}
.search{flex:1;min-width:200px;padding:10px 16px;border-radius:8px;border:1px solid var(--border);
  background:var(--inp);color:var(--text);font-family:var(--mono);font-size:13px;outline:none;
  transition:border-color .2s,background var(--t);}
.search:focus{border-color:var(--accent);}
.search::placeholder{color:var(--dim);}

.table-wrap{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);
  overflow:hidden;transition:background var(--t);}
table{width:100%;border-collapse:collapse;}
th{padding:14px 16px;text-align:left;font-family:var(--mono);font-size:11px;letter-spacing:2px;
  color:var(--dim);background:var(--panel2);border-bottom:1px solid var(--border);text-transform:uppercase;}
td{padding:14px 16px;font-size:13px;border-bottom:1px solid rgba(100,120,160,.15);vertical-align:middle;}
tr:last-child td{border-bottom:none;}
tr:hover td{background:rgba(0,212,255,.04);}
tr.new-row td{animation:flashRow .8s ease;}
@keyframes flashRow{from{background:rgba(255,59,92,.2)}to{background:transparent}}

.badge{display:inline-block;padding:3px 10px;border-radius:20px;font-family:var(--mono);
  font-size:11px;font-weight:700;letter-spacing:1px;}
.badge.HIGH{background:rgba(255,59,92,.15);color:var(--danger);border:1px solid var(--danger);}
.badge.MEDIUM{background:rgba(255,170,0,.15);color:var(--warning);border:1px solid var(--warning);}
.badge.LOW{background:rgba(0,255,148,.1);color:var(--safe);border:1px solid var(--safe);}
.bssid{font-family:var(--mono);font-size:12px;color:var(--accent);}
.hash{font-family:var(--mono);font-size:10px;color:var(--dim);}
.int-ok{color:var(--safe);font-family:var(--mono);font-size:12px;}
.int-fail{color:var(--danger);font-family:var(--mono);font-size:12px;}
.reasons{font-size:12px;color:var(--dim);}
.ts{font-family:var(--mono);font-size:11px;color:var(--dim);}
.empty-state{text-align:center;padding:80px 20px;color:var(--dim);font-family:var(--mono);}
.empty-state .icon{font-size:48px;margin-bottom:16px;}
footer{text-align:center;padding:24px;font-family:var(--mono);font-size:11px;color:var(--dim);
  border-top:1px solid var(--border);margin-top:40px;}
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
    <button class="theme-toggle" onclick="toggleTheme()" id="theme-btn">☀️ Light Mode</button>
    <div class="status-badge"><div class="pulse"></div>MONITORING ACTIVE</div>
  </div>
</header>

<main>
  <div class="stats-grid">
    <div class="stat-card total"><div class="stat-label">Total Alerts</div><div class="stat-value" id="stat-total">0</div></div>
    <div class="stat-card high"><div class="stat-label">High Severity</div><div class="stat-value" id="stat-high">0</div></div>
    <div class="stat-card medium"><div class="stat-label">Medium Severity</div><div class="stat-value" id="stat-med">0</div></div>
    <div class="stat-card low"><div class="stat-label">Low Severity</div><div class="stat-value" id="stat-low">0</div></div>
  </div>

  <div class="retention-panel">
    <div class="ret-label">🗂 Log Retention</div>
    <div class="ret-desc">Logs older than this are automatically deleted every hour.</div>
    <div class="ret-wrap">
      <input class="ret-input" type="number" id="retention-days" min="1" max="365" value="30">
      <span class="ret-unit">days</span>
      <button class="btn save" onclick="saveRetention()">Save</button>
      <span class="ret-status" id="ret-status"></span>
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
      <thead><tr>
        <th>Timestamp (UTC)</th><th>Severity</th><th>SSID</th><th>Rogue BSSID</th>
        <th>Signal</th><th>Encryption</th><th>Detection Reasons</th><th>SHA-256 Integrity</th>
      </tr></thead>
      <tbody id="log-body">
        <tr><td colspan="8" class="empty-state"><div class="icon">📡</div>Waiting for detections...</td></tr>
      </tbody>
    </table>
  </div>
</main>

<footer>TwinGuard-SHA256 &nbsp;|&nbsp; GMI Final Year Project JAN 2026 &nbsp;|&nbsp; SEM 4 DCBS 6</footer>

<script>
let allLogs = [], prevCount = 0;

// ── Theme ──────────────────────────────────────
function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  localStorage.setItem('tg-theme', t);
  document.getElementById('theme-btn').textContent = t === 'dark' ? '☀️ Light Mode' : '🌙 Dark Mode';
}
function toggleTheme() {
  applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
}
applyTheme(localStorage.getItem('tg-theme') || 'dark');

// ── Retention ──────────────────────────────────
async function loadRetention() {
  try {
    const r = await fetch('/api/retention');
    const d = await r.json();
    document.getElementById('retention-days').value = d.retention_days || 30;
  } catch(e) {}
}
async function saveRetention() {
  const days = parseInt(document.getElementById('retention-days').value);
  const s = document.getElementById('ret-status');
  if (isNaN(days) || days < 1) { s.textContent='✗ Invalid'; s.className='ret-status err'; return; }
  try {
    const r = await fetch('/api/retention', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({retention_days: days})
    });
    const d = await r.json();
    if (d.status === 'ok') {
      s.textContent = `✓ Saved (${days} days)`; s.className = 'ret-status ok';
      setTimeout(() => { s.textContent = ''; }, 3000);
    }
  } catch(e) { s.textContent='✗ Failed'; s.className='ret-status err'; }
}

// ── Data ───────────────────────────────────────
async function loadData() {
  try {
    const [sr, lr] = await Promise.all([fetch('/api/stats'), fetch('/api/logs')]);
    const stats = await sr.json();
    allLogs     = await lr.json();
    document.getElementById('stat-total').textContent = stats.total_alerts;
    document.getElementById('stat-high').textContent  = stats.high;
    document.getElementById('stat-med').textContent   = stats.medium;
    document.getElementById('stat-low').textContent   = stats.low;
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
    tbody.innerHTML='<tr><td colspan="8" class="empty-state"><div class="icon">✅</div>No rogue APs detected yet.</td></tr>';
    return;
  }
  tbody.innerHTML = logs.map((l,i) => {
    const ts   = (l.timestamp||'').replace('T',' ').replace('Z','');
    const sev  = l.severity||'LOW';
    const hash = l.sha256_hash||'';
    const iok  = l.integrity_ok;
    const istr = iok===undefined ? '<span class="hash">—</span>'
               : iok ? '<span class="int-ok">✓ VALID</span>'
                     : '<span class="int-fail">✗ TAMPERED</span>';
    const nr   = (highlight && i===0) ? ' class="new-row"' : '';
    return `<tr${nr}>
      <td class="ts">${ts}</td>
      <td><span class="badge ${sev}">${sev}</span></td>
      <td><strong>${l.ssid||'?'}</strong></td>
      <td class="bssid">${l.bssid||'?'}</td>
      <td>${l.signal_dbm||'?'} dBm</td>
      <td>${l.encryption||'?'}</td>
      <td class="reasons">${(l.reasons||[]).join(' · ')}</td>
      <td>${istr}<br><span class="hash">${hash.substring(0,20)}…</span></td>
    </tr>`;
  }).join('');
}

function filterTable() {
  const q = document.getElementById('search').value.toLowerCase();
  renderTable(allLogs.filter(l =>
    (l.ssid||'').toLowerCase().includes(q)||(l.bssid||'').toLowerCase().includes(q)
  ).slice().reverse());
}

function exportLogs() {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(allLogs,null,2)],{type:'application/json'}));
  a.download = 'twinguard_forensic_log.json'; a.click();
}

loadRetention();
loadData();
setInterval(loadData, 10000);
setInterval(() => {
  const el = document.getElementById('rfill');
  el.style.animation='none'; el.offsetHeight; el.style.animation='';
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