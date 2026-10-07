#!/usr/bin/env python3
"""
TwinGuard-SHA256: Dashboard Server
====================================
Features:
  - Admin web dashboard at GET / (Firebase admin login)
  - Alerts and operator accounts live in Firebase (free Spark plan):
      Firebase Authentication  -> admin + operator accounts
      Cloud Firestore          -> operator profiles + sealed alerts
  - Light / Dark mode toggle
  - Log retention: auto-delete alerts older than X days
  - SHA-256 integrity verification of every alert

Install:
    pip install -r requirements.txt

Setup:
    see firebase/README.md (one-time Firebase project setup)

Run:
    python3 dashboard_server.py
Then open: http://127.0.0.1:5000
"""

import json, hashlib, os, re, secrets, sys, threading, time
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for
from firebase_store import FirebaseStore, FirebaseError, FirebaseNotConfigured

app      = Flask(__name__)
CFG_FILE = "twinguard_config.json"
SECRET_FILE = "twinguard_secret.key"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
EMAIL_RE    = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

store = None  # FirebaseStore, created in main()

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

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def verify_sha256(entry):
    """Verify integrity. Strip sha256_hash AND integrity_ok before recomputing."""
    stored  = entry.get("sha256_hash", "")
    payload = {k: v for k, v in entry.items()
               if k not in ("sha256_hash", "integrity_ok")}
    computed = hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode()
    ).hexdigest()
    return computed == stored

# ── Admin authentication ──────────────────────────────────────────────────────
LOOPBACK = ("127.0.0.1", "::1")
# Endpoints reachable without an admin session
PUBLIC_ENDPOINTS = {"login", "setup", "static"}

def load_secret_key():
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE) as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key)
    return key

app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

# Brute-force throttle: 5 failures per IP locks it for 5 minutes
failed_lock     = threading.Lock()
failed_attempts = {}
MAX_FAILS, LOCK_SECONDS = 5, 300

def is_locked(key):
    with failed_lock:
        fails = [t for t in failed_attempts.get(key, []) if time.time() - t < LOCK_SECONDS]
        failed_attempts[key] = fails
        return len(fails) >= MAX_FAILS

def record_failure(key):
    with failed_lock:
        failed_attempts.setdefault(key, []).append(time.time())

def clear_failures(key):
    with failed_lock:
        failed_attempts.pop(key, None)

@app.before_request
def require_admin():
    if request.endpoint in PUBLIC_ENDPOINTS:
        return None
    if not session.get("admin"):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Authentication required"}), 401
        return redirect(url_for("login" if store.admin_exists() else "setup"))
    # Session-authenticated writes must be real JSON requests (blocks cross-site form CSRF)
    if request.method == "POST" and request.path.startswith("/api/") and not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    return None

@app.errorhandler(FirebaseError)
def firebase_error(e):
    return jsonify({"error": str(e)}), 400

# ── Retention engine (runs every hour) ───────────────────────────────────────
def purge_old_logs():
    while True:
        try:
            days   = int(load_config().get("retention_days", 30))
            cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")
            removed = store.purge_alerts_before(cutoff)
            if removed > 0:
                print(f"[Retention] Purged {removed} alert(s) older than {days} day(s).")
        except Exception as ex:
            print(f"[Retention] Error: {ex}")
        time.sleep(3600)

# ── API ───────────────────────────────────────────────────────────────────────

@app.route("/api/logs", methods=["GET"])
def get_logs():
    result = []
    for e in store.alerts():
        copy = dict(e)
        copy["integrity_ok"] = verify_sha256(e)  # verify ORIGINAL, attach to COPY
        result.append(copy)
    return jsonify(result)

@app.route("/api/stats", methods=["GET"])
def get_stats():
    logs  = store.alerts()
    users = store.user_profiles().values()
    cfg   = load_config()
    return jsonify({
        "total_alerts":   len(logs),
        "high":           sum(1 for l in logs if l.get("severity") == "HIGH"),
        "medium":         sum(1 for l in logs if l.get("severity") == "MEDIUM"),
        "low":            sum(1 for l in logs if l.get("severity") == "LOW"),
        "total_users":    len(users),
        "active_users":   sum(1 for u in users if u.get("enabled")),
        "retention_days": cfg.get("retention_days", 30),
        "last_updated":   now_iso(),
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
    for e in store.alerts():
        if e.get("sha256_hash") == sha256_hash:
            return jsonify({"found": True, "integrity_ok": verify_sha256(e), "entry": e})
    return jsonify({"found": False}), 404


# ── User management (app operators under the admin) ──────────────────────────
@app.route("/api/users", methods=["GET"])
def list_users():
    return jsonify(store.users())

@app.route("/api/users", methods=["POST"])
def create_user():
    data      = request.get_json(force=True) or {}
    username  = str(data.get("username", "")).strip()
    full_name = str(data.get("full_name", "")).strip()
    email     = str(data.get("email", "")).strip()
    password  = str(data.get("password", ""))
    if not USERNAME_RE.match(username):
        return jsonify({"error": "Username must be 3-32 chars: letters, digits, . _ -"}), 400
    if not EMAIL_RE.match(email):
        return jsonify({"error": "A valid email is required (operators sign in with it)"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    uid = store.create_user(username, full_name, email, password, now_iso())
    print(f"[Users] Created user '{username}' ({email}).")
    return jsonify({"id": uid, "username": username}), 201

@app.route("/api/users/<user_id>/status", methods=["POST"])
def set_user_status(user_id):
    data = request.get_json(force=True) or {}
    if not isinstance(data.get("enabled"), bool):
        return jsonify({"error": "'enabled' must be true or false"}), 400
    try:
        username = store.set_user_enabled(user_id, data["enabled"])
    except KeyError:
        return jsonify({"error": "User not found"}), 404
    print(f"[Users] {'Enabled' if data['enabled'] else 'Disabled'} user '{username}'.")
    return jsonify({"id": user_id, "enabled": data["enabled"]})

# ── Dashboard HTML ────────────────────────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TwinGuard-SHA256 | Dashboard</title>
<link rel="icon" type="image/png" href="/static/favicon.png">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;500;700;900&display=swap" rel="stylesheet">
<style>
:root {
  --accent:#4fc3f7; --accent2:#2b8fe0; --cyan:#7ddcff;
  --danger:#ff5a76; --warning:#ffb547; --safe:#3ee6a8; --violet:#a78bfa;
  --mono:'Share Tech Mono',monospace; --sans:'Exo 2',sans-serif;
  --radius:10px; --t:.25s ease; --side:250px;
}
[data-theme="dark"]  { --bg:#0e1c33; --bg2:#0b172b; --panel:#14284a; --panel2:#18305a; --border:#264878;
  --text:#dcebff; --dim:#86a5cc; --inp:#0f2140; --glow:rgba(79,195,247,.18); --grid:rgba(79,195,247,.05); --onaccent:#06142a; }
[data-theme="light"] { --bg:#e8f1fb; --bg2:#dce9f8; --panel:#ffffff; --panel2:#f0f6fd; --border:#c3d7ef;
  --text:#0f2545; --dim:#5b7699; --inp:#f6faff; --glow:rgba(43,143,224,.15); --grid:rgba(43,143,224,.06);
  --accent:#1b8ad6; --cyan:#0e7fc2; --safe:#0fae74; --warning:#d98a00; --danger:#e23b5a; --violet:#7c5ce0; --onaccent:#fff; }

*{margin:0;padding:0;box-sizing:border-box;}
html{scroll-behavior:smooth;}
body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh;
  transition:background var(--t),color var(--t);
  background-image:linear-gradient(var(--grid) 1px,transparent 1px),linear-gradient(90deg,var(--grid) 1px,transparent 1px);
  background-size:32px 32px;}
[data-theme="dark"] body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:9999;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(79,195,247,.015) 2px,rgba(79,195,247,.015) 4px);}

/* ── Sidebar ───────────────────────────── */
.sidebar{position:fixed;top:0;left:0;bottom:0;width:var(--side);background:var(--bg2);
  border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:200;transition:background var(--t);}
.logo{display:flex;align-items:center;gap:12px;padding:22px 20px;border-bottom:1px solid var(--border);}
.logo-icon{width:44px;height:44px;flex-shrink:0;background:linear-gradient(135deg,var(--cyan),var(--accent2));
  -webkit-mask:url(/static/logo.png) center/contain no-repeat;mask:url(/static/logo.png) center/contain no-repeat;}
.logo-text{font-size:16px;font-weight:900;letter-spacing:2px;color:var(--text);}
.logo-sub{font-family:var(--mono);font-size:9px;color:var(--dim);letter-spacing:2px;margin-top:2px;}
.nav{padding:18px 12px;display:flex;flex-direction:column;gap:4px;flex:1;}
.nav-title{font-family:var(--mono);font-size:10px;letter-spacing:3px;color:var(--dim);padding:8px 12px 6px;}
.nav a{display:flex;align-items:center;gap:12px;padding:11px 14px;border-radius:8px;color:var(--dim);
  text-decoration:none;font-size:14px;font-weight:500;letter-spacing:.5px;border-left:3px solid transparent;transition:all .2s;}
.nav a:hover{color:var(--text);background:var(--glow);}
.nav a.active{color:var(--accent);background:var(--glow);border-left-color:var(--accent);}
.nav a .ico{width:20px;text-align:center;}
.side-foot{padding:16px 20px;border-top:1px solid var(--border);display:flex;flex-direction:column;gap:12px;}
.theme-toggle{background:var(--panel);border:1px solid var(--border);border-radius:8px;
  padding:8px 14px;cursor:pointer;font-family:var(--mono);font-size:12px;color:var(--text);
  display:flex;align-items:center;justify-content:center;gap:6px;transition:all var(--t);}
.theme-toggle:hover{border-color:var(--accent);color:var(--accent);}
.sys-line{font-family:var(--mono);font-size:10px;color:var(--dim);letter-spacing:1px;overflow-wrap:anywhere;}
.logout{width:100%;}

/* ── Topbar ────────────────────────────── */
.wrap{margin-left:var(--side);min-height:100vh;display:flex;flex-direction:column;}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;padding:16px 32px;
  background:color-mix(in srgb,var(--bg) 85%,transparent);backdrop-filter:blur(8px);
  border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100;}
.crumb{font-family:var(--mono);font-size:11px;letter-spacing:3px;color:var(--dim);}
.page-title{font-size:22px;font-weight:700;letter-spacing:1px;}
.page-title span{color:var(--accent);}
.top-right{display:flex;align-items:center;gap:14px;flex-wrap:wrap;}
.chip{font-family:var(--mono);font-size:12px;padding:7px 12px;border-radius:6px;border:1px solid var(--border);
  background:var(--panel);color:var(--dim);}
.chip b{color:var(--text);font-weight:400;}
.status-badge{display:flex;align-items:center;gap:8px;font-family:var(--mono);font-size:12px;color:var(--safe);
  padding:7px 12px;border-radius:6px;border:1px solid color-mix(in srgb,var(--safe) 40%,transparent);
  background:color-mix(in srgb,var(--safe) 8%,transparent);}
.pulse{width:8px;height:8px;border-radius:50%;background:var(--safe);animation:pulse 2s infinite;}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(62,230,168,.5);}50%{box-shadow:0 0 0 8px rgba(62,230,168,0);}}

main{padding:28px 32px;width:100%;max-width:1400px;}
section{margin-bottom:28px;scroll-margin-top:90px;}
.sec-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px;flex-wrap:wrap;}
.sec-title{font-family:var(--mono);font-size:13px;letter-spacing:3px;color:var(--accent);text-transform:uppercase;
  display:flex;align-items:center;gap:10px;}
.sec-title::before{content:'';width:8px;height:8px;background:var(--accent);box-shadow:0 0 10px var(--accent);transform:rotate(45deg);}
.sec-note{font-family:var(--mono);font-size:11px;color:var(--dim);}

.panel{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);position:relative;
  transition:background var(--t),border-color var(--t);}
.panel::before{content:'';position:absolute;top:-1px;left:16px;width:60px;height:2px;
  background:linear-gradient(90deg,var(--accent),transparent);}

/* ── Stats ─────────────────────────────── */
.stats-grid{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:14px;}
@media (max-width:1300px){.stats-grid{grid-template-columns:repeat(3,minmax(0,1fr));}}
@media (max-width:640px){.stats-grid{grid-template-columns:repeat(2,minmax(0,1fr));}}
.stat-card{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);
  padding:20px 22px;position:relative;overflow:hidden;transition:transform .2s,border-color .2s,background var(--t);}
.stat-card:hover{transform:translateY(-2px);border-color:var(--c);box-shadow:0 6px 24px -10px var(--c);}
.stat-card::after{content:'';position:absolute;top:0;left:0;bottom:0;width:3px;background:var(--c);}
.stat-card.total{--c:var(--accent);} .stat-card.high{--c:var(--danger);} .stat-card.medium{--c:var(--warning);}
.stat-card.low{--c:var(--safe);} .stat-card.users{--c:var(--violet);} .stat-card.active{--c:var(--cyan);}
.stat-label{font-family:var(--mono);font-size:10px;letter-spacing:2.5px;color:var(--dim);text-transform:uppercase;margin-bottom:10px;}
.stat-value{font-size:38px;font-weight:900;line-height:1;color:var(--c);}
.stat-sub{font-family:var(--mono);font-size:10px;color:var(--dim);margin-top:8px;}

/* ── Retention ─────────────────────────── */
.retention-panel{padding:18px 24px;display:flex;align-items:center;gap:16px;flex-wrap:wrap;}
.ret-label{font-family:var(--mono);font-size:11px;letter-spacing:2px;color:var(--dim);text-transform:uppercase;white-space:nowrap;}
.ret-desc{font-size:13px;color:var(--text);flex:1;min-width:180px;}
.ret-wrap{display:flex;align-items:center;gap:10px;}
.ret-input{width:72px;padding:8px 10px;border-radius:8px;border:1px solid var(--border);
  background:var(--inp);color:var(--text);font-family:var(--mono);font-size:14px;text-align:center;outline:none;transition:border-color .2s;}
.ret-input:focus{border-color:var(--accent);}
.ret-unit{font-family:var(--mono);font-size:12px;color:var(--dim);}
.ret-status,.form-status{font-family:var(--mono);font-size:12px;}
.ok{color:var(--safe);} .err{color:var(--danger);}

.refresh-bar{height:2px;background:var(--border);margin-bottom:16px;border-radius:2px;overflow:hidden;}
.refresh-fill{height:100%;background:linear-gradient(90deg,var(--accent2),var(--cyan));animation:refill 10s linear infinite;transform-origin:left;}
@keyframes refill{from{transform:scaleX(1)}to{transform:scaleX(0)}}

.controls{display:flex;gap:12px;margin-bottom:16px;align-items:center;flex-wrap:wrap;}
.btn{padding:9px 18px;border-radius:8px;border:1px solid var(--border);background:var(--panel2);
  color:var(--text);font-family:var(--sans);font-size:13px;font-weight:500;cursor:pointer;transition:all .2s;letter-spacing:1px;}
.btn:hover{border-color:var(--accent);color:var(--accent);}
.btn.primary{background:linear-gradient(135deg,var(--cyan),var(--accent2));color:var(--onaccent);border-color:transparent;font-weight:700;}
.btn.primary:hover{opacity:.88;color:var(--onaccent);}
.btn.save{background:var(--safe);color:#04201a;border-color:var(--safe);font-weight:700;}
.btn.save:hover{opacity:.85;color:#04201a;}
.btn.sm{padding:5px 12px;font-size:12px;}
.btn.danger{color:var(--danger);border-color:color-mix(in srgb,var(--danger) 50%,transparent);}
.btn.danger:hover{background:color-mix(in srgb,var(--danger) 12%,transparent);color:var(--danger);border-color:var(--danger);}
.btn.enable{color:var(--safe);border-color:color-mix(in srgb,var(--safe) 50%,transparent);}
.btn.enable:hover{background:color-mix(in srgb,var(--safe) 12%,transparent);color:var(--safe);border-color:var(--safe);}
.search,.field{flex:1;min-width:200px;padding:10px 14px;border-radius:8px;border:1px solid var(--border);
  background:var(--inp);color:var(--text);font-family:var(--mono);font-size:13px;outline:none;transition:border-color .2s,background var(--t);}
.search:focus,.field:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--glow);}
.search::placeholder,.field::placeholder{color:var(--dim);}

.table-wrap{overflow-x:auto;}
table{width:100%;border-collapse:collapse;}
th{padding:13px 16px;text-align:left;font-family:var(--mono);font-size:11px;letter-spacing:2px;white-space:nowrap;
  color:var(--dim);background:var(--panel2);border-bottom:1px solid var(--border);text-transform:uppercase;}
th:first-child{border-top-left-radius:var(--radius);} th:last-child{border-top-right-radius:var(--radius);}
td{padding:13px 16px;font-size:13px;border-bottom:1px solid color-mix(in srgb,var(--border) 55%,transparent);vertical-align:middle;}
tr:last-child td{border-bottom:none;}
tbody tr:hover td{background:var(--glow);}
tr.new-row td{animation:flashRow .8s ease;}
@keyframes flashRow{from{background:rgba(255,90,118,.22)}to{background:transparent}}

.badge{display:inline-block;padding:3px 10px;border-radius:4px;font-family:var(--mono);font-size:11px;font-weight:700;letter-spacing:1px;}
.badge.HIGH{background:color-mix(in srgb,var(--danger) 15%,transparent);color:var(--danger);border:1px solid var(--danger);}
.badge.MEDIUM{background:color-mix(in srgb,var(--warning) 15%,transparent);color:var(--warning);border:1px solid var(--warning);}
.badge.LOW{background:color-mix(in srgb,var(--safe) 12%,transparent);color:var(--safe);border:1px solid var(--safe);}
.badge.on{background:color-mix(in srgb,var(--safe) 12%,transparent);color:var(--safe);border:1px solid var(--safe);}
.badge.off{background:color-mix(in srgb,var(--dim) 15%,transparent);color:var(--dim);border:1px solid var(--dim);}
.badge.role{background:color-mix(in srgb,var(--violet) 14%,transparent);color:var(--violet);border:1px solid var(--violet);}
.bssid{font-family:var(--mono);font-size:12px;color:var(--accent);}
.hash{font-family:var(--mono);font-size:10px;color:var(--dim);}
.int-ok{color:var(--safe);font-family:var(--mono);font-size:12px;}
.int-fail{color:var(--danger);font-family:var(--mono);font-size:12px;}
.reasons{font-size:12px;color:var(--dim);}
.ts{font-family:var(--mono);font-size:11px;color:var(--dim);}
.empty-state{text-align:center;padding:70px 20px;color:var(--dim);font-family:var(--mono);}
.empty-state .icon{font-size:44px;margin-bottom:14px;}

/* ── Charts ────────────────────────────── */
.stat-card.recent{--c:var(--warning);}
.stat-card.integrity{--c:var(--safe);} .stat-card.integrity.bad{--c:var(--danger);}
.chart-grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.6fr);gap:14px;margin-top:14px;}
.chart-grid.even{grid-template-columns:minmax(0,1fr) minmax(0,1fr);}
.chart-card{padding:18px 20px;min-width:0;}
.chart-title{font-family:var(--mono);font-size:11px;letter-spacing:2.5px;color:var(--dim);text-transform:uppercase;
  margin-bottom:16px;display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;}
.chart-title b{color:var(--text);font-weight:400;letter-spacing:1px;}
.donut-wrap{display:flex;align-items:center;gap:24px;flex-wrap:wrap;}
.donut{width:180px;height:180px;flex-shrink:0;}
.donut .ring{fill:none;stroke:color-mix(in srgb,var(--border) 55%,transparent);stroke-width:26;}
.donut .seg{fill:none;stroke-width:26;cursor:pointer;transition:opacity .15s;}
.donut .seg:hover,.donut .seg:focus{opacity:.78;outline:none;}
.donut-total{font-family:var(--sans);font-size:36px;font-weight:900;fill:var(--text);}
.donut-cap{font-family:var(--mono);font-size:10px;letter-spacing:2px;fill:var(--dim);}
.legend{display:flex;flex-direction:column;gap:12px;flex:1;min-width:160px;}
.lg-row{display:grid;grid-template-columns:12px 1fr auto 44px;gap:10px;align-items:center;font-size:13px;}
.lg-sw{width:12px;height:12px;border-radius:3px;}
.lg-val{font-weight:700;} .lg-pct{font-family:var(--mono);font-size:11px;color:var(--dim);text-align:right;}
.legend.inline{flex-direction:row;flex-wrap:wrap;gap:18px;margin-top:10px;}
.legend.inline .lg-row{display:flex;gap:8px;font-size:12px;color:var(--dim);}
.svg-chart{width:100%;height:220px;display:block;overflow:visible;}
.svg-chart .grid{stroke:color-mix(in srgb,var(--border) 70%,transparent);stroke-width:1;}
.svg-chart .base{stroke:var(--border);stroke-width:1;}
.svg-chart .axis{font-family:var(--mono);font-size:10px;fill:var(--dim);}
.svg-chart .hit{fill:transparent;cursor:pointer;outline:none;}
.svg-chart .hit:hover,.svg-chart .hit:focus{fill:var(--glow);}
.hbars{display:flex;flex-direction:column;gap:13px;}
.hb-row{display:grid;grid-template-columns:minmax(90px,40%) minmax(0,1fr) 36px;gap:12px;align-items:center;font-size:13px;}
.hb-label{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.hb-track{height:10px;background:color-mix(in srgb,var(--border) 45%,transparent);border-radius:5px;overflow:hidden;}
.hb-fill{height:100%;border-radius:5px;background:var(--accent);transition:width .4s ease;}
.hb-val{font-family:var(--mono);text-align:right;}
.chart-empty{font-family:var(--mono);font-size:12px;color:var(--dim);padding:36px 0;text-align:center;}
.tip{position:fixed;pointer-events:none;z-index:500;background:var(--panel2);border:1px solid var(--border);
  border-radius:6px;padding:9px 12px;min-width:120px;box-shadow:0 10px 30px rgba(0,0,0,.35);}
.tip-title{font-family:var(--mono);font-size:10px;letter-spacing:1.5px;color:var(--dim);margin-bottom:6px;}
.tip-row{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--dim);margin-top:3px;}
.tip-row b{color:var(--text);font-size:14px;min-width:22px;}
.tip-key{width:10px;height:2px;border-radius:1px;}
.user-tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;}
.utab{display:inline-flex;align-items:center;gap:8px;padding:8px 14px;border-radius:8px;border:1px solid var(--border);
  background:var(--panel);color:var(--dim);font-family:var(--sans);font-size:13px;font-weight:500;cursor:pointer;transition:all .2s;}
.utab:hover{color:var(--text);border-color:var(--accent);}
.utab.active{color:var(--accent);border-color:var(--accent);background:var(--glow);box-shadow:inset 0 -2px 0 var(--accent);}
.utab.off .uname-t{text-decoration:line-through;opacity:.7;}
.utab .cnt{font-family:var(--mono);font-size:11px;padding:1px 7px;border-radius:10px;
  background:color-mix(in srgb,var(--danger) 15%,transparent);color:var(--danger);}
.utab .cnt.zero{background:color-mix(in srgb,var(--dim) 15%,transparent);color:var(--dim);}
.log-owner{font-family:var(--mono);font-size:12px;color:var(--dim);margin-bottom:10px;}
.log-owner b{color:var(--text);font-weight:400;}
@media (max-width:1000px){.chart-grid,.chart-grid.even{grid-template-columns:minmax(0,1fr);}}

/* ── Users ─────────────────────────────── */
.user-form{padding:20px 24px;display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;align-items:end;
  border-bottom:1px solid var(--border);}
.user-form label{display:flex;flex-direction:column;gap:6px;font-family:var(--mono);font-size:10px;letter-spacing:2px;
  color:var(--dim);text-transform:uppercase;}
.user-form .field{min-width:0;width:100%;}
.form-actions{display:flex;align-items:center;gap:12px;flex-wrap:wrap;}
.uname{font-weight:700;} .umeta{font-size:12px;color:var(--dim);}
tr.disabled td{opacity:.6;} tr.disabled td:last-child{opacity:1;}
.row-actions{white-space:nowrap;} .row-actions .btn+.btn{margin-left:6px;}

footer{text-align:center;padding:22px;font-family:var(--mono);font-size:11px;color:var(--dim);
  border-top:1px solid var(--border);margin-top:auto;}

@media (max-width:900px){
  .sidebar{position:static;width:auto;flex-direction:column;}
  .nav{flex-direction:row;flex-wrap:wrap;padding:10px 12px;}
  .nav-title,.sys-line{display:none;}
  .side-foot{flex-direction:row;padding:10px 16px;}
  .wrap{margin-left:0;}
  .topbar,main{padding-left:16px;padding-right:16px;}
}
</style>
</head>
<body>

<aside class="sidebar">
  <div class="logo">
    <div class="logo-icon" role="img" aria-label="TwinGuard logo"></div>
    <div>
      <div class="logo-text">TWINGUARD</div>
      <div class="logo-sub">SHA-256 // ROGUE AP DEFENSE</div>
    </div>
  </div>
  <nav class="nav" id="nav">
    <div class="nav-title" aria-hidden="true">&nbsp;</div>
    <a href="#overview" class="active"><span class="ico">◈</span>Overview</a>
    <a href="#threats"><span class="ico">⚠</span>Threat Log</a>
    <a href="#users"><span class="ico">👥</span>User Management</a>
    <a href="#settings"><span class="ico">⚙</span>Settings</a>
  </nav>
  <div class="side-foot">
    <button class="theme-toggle" onclick="toggleTheme()" id="theme-btn">☀️ Light Mode</button>
    <div class="sys-line">SIGNED IN: {{ admin }}<br>ROLE: ADMINISTRATOR</div>
    <form method="post" action="/logout"><button class="btn sm danger logout" type="submit">⏻ Log Out</button></form>
  </div>
</aside>

<div class="wrap">
<header class="topbar">
  <div>
    <div class="crumb">ADMIN CONSOLE / SECURITY OPERATIONS</div>
    <div class="page-title">Rogue AP <span>Detection</span> &amp; Forensics</div>
  </div>
  <div class="top-right">
    <div class="chip">KUALA LUMPUR (GMT+8) <b id="clock">--:--:--</b></div>
    <div class="status-badge"><div class="pulse"></div>MONITORING ACTIVE</div>
  </div>
</header>

<main>
  <section id="overview">
    <div class="sec-head"><div class="sec-title">Threat Overview</div><div class="sec-note">auto-refresh 10s</div></div>
    <div class="stats-grid">
      <div class="stat-card total"><div class="stat-label">Total Alerts</div><div class="stat-value" id="stat-total">0</div><div class="stat-sub">in retention window</div></div>
      <div class="stat-card recent"><div class="stat-label">Alerts (24h)</div><div class="stat-value" id="stat-24h">0</div><div class="stat-sub">last 24 hours</div></div>
      <div class="stat-card integrity" id="card-integrity" title="Share of forensic log entries whose SHA-256 hash still matches their contents. Below 100% means an entry was edited after it was recorded."><div class="stat-label">Log Integrity</div><div class="stat-value" id="stat-integrity">—</div><div class="stat-sub" id="stat-integrity-sub">no entries</div></div>
      <div class="stat-card high"><div class="stat-label">High Severity</div><div class="stat-value" id="stat-high">0</div><div class="stat-sub">shown in threat log</div></div>
      <div class="stat-card users"><div class="stat-label">Total Users</div><div class="stat-value" id="stat-users">0</div><div class="stat-sub">registered operators</div></div>
      <div class="stat-card active"><div class="stat-label">Active Users</div><div class="stat-value" id="stat-active">0</div><div class="stat-sub">accounts enabled</div></div>
    </div>

    <div class="chart-grid">
      <div class="panel chart-card">
        <div class="chart-title">Severity Distribution</div>
        <div class="donut-wrap">
          <svg class="donut" id="sev-donut" viewBox="0 0 200 200" role="img" aria-label="Alerts by severity"></svg>
          <div class="legend" id="sev-legend"></div>
        </div>
      </div>
      <div class="panel chart-card">
        <div class="chart-title">Alerts · Last 14 Days (GMT+8) <b id="trend-sum"></b></div>
        <svg class="svg-chart" id="trend-chart" role="img" aria-label="Daily alerts by severity over the last 14 days"></svg>
        <div class="legend inline" id="trend-legend"></div>
      </div>
    </div>

    <div class="chart-grid even">
      <div class="panel chart-card">
        <div class="chart-title">Detection Reasons <b>alerts triggering each rule</b></div>
        <div class="hbars" id="reason-bars"></div>
      </div>
      <div class="panel chart-card">
        <div class="chart-title">Most Targeted SSIDs <b>top 6</b></div>
        <div class="hbars" id="ssid-bars"></div>
      </div>
    </div>
  </section>

  <section id="threats">
    <div class="sec-head"><div class="sec-title">Threat Log</div><div class="sec-note">HIGH severity only · one log per user · SHA-256 sealed</div></div>
    <div class="refresh-bar"><div class="refresh-fill" id="rfill"></div></div>
    <div class="controls">
      <button class="btn primary" onclick="loadData()">↻ Refresh</button>
      <input class="search" id="search" type="text" placeholder="Filter by SSID or BSSID..." oninput="filterTable()">
      <button class="btn" onclick="exportLogs()">⬇ Export JSON</button>
    </div>
    <div class="user-tabs" id="user-tabs" role="tablist" aria-label="Threat log by user"></div>
    <div class="log-owner" id="log-owner"></div>
    <div class="panel table-wrap">
      <table>
        <thead><tr>
          <th>Timestamp (GMT+8)</th><th>Severity</th><th>SSID</th><th>Rogue BSSID</th>
          <th>Signal</th><th>Encryption</th><th>Detection Reasons</th><th>SHA-256 Integrity</th>
        </tr></thead>
        <tbody id="log-body">
          <tr><td colspan="8" class="empty-state"><div class="icon">📡</div>Waiting for detections...</td></tr>
        </tbody>
      </table>
    </div>
  </section>

  <section id="users">
    <div class="sec-head"><div class="sec-title">User Management</div><div class="sec-note">operator accounts for the TwinGuard app</div></div>
    <div class="panel">
      <form class="user-form" id="user-form" onsubmit="addUser(event)">
        <label>Username<input class="field" id="u-username" required minlength="3" maxlength="32" placeholder="operator01"></label>
        <label>Full Name<input class="field" id="u-fullname" maxlength="80" placeholder="Ali Ahmad"></label>
        <label>Email (app sign-in)<input class="field" id="u-email" type="email" required maxlength="120" placeholder="ali@example.com"></label>
        <label>Password<input class="field" id="u-password" type="password" required minlength="8" placeholder="min. 8 characters"></label>
        <div class="form-actions">
          <button class="btn primary" type="submit">＋ Add User</button>
          <span class="form-status" id="user-status"></span>
        </div>
      </form>
      <div class="table-wrap">
        <table>
          <thead><tr><th>User</th><th>Email</th><th>Role</th><th>Status</th><th>Created (GMT+8)</th><th>Last Login (GMT+8)</th><th>Action</th></tr></thead>
          <tbody id="user-body">
            <tr><td colspan="7" class="empty-state"><div class="icon">👥</div>Loading users...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </section>

  <section id="settings">
    <div class="sec-head"><div class="sec-title">Settings</div></div>
    <div class="panel retention-panel">
      <div class="ret-label">🗂 Log Retention</div>
      <div class="ret-desc">Logs older than this are automatically deleted every hour.</div>
      <div class="ret-wrap">
        <input class="ret-input" type="number" id="retention-days" min="1" max="365" value="30">
        <span class="ret-unit">days</span>
        <button class="btn save" onclick="saveRetention()">Save</button>
        <span class="ret-status" id="ret-status"></span>
      </div>
    </div>
  </section>
</main>

<div class="tip" id="tip" hidden></div>

<footer>TwinGuard-SHA256 &nbsp;|&nbsp; GMI Final Year Project JAN 2026 &nbsp;|&nbsp; SEM 4 DCBS 6</footer>
</div>

<script>
let allLogs = [], allUsers = [], activeTab = null, prevCounts = {};

// ── Session guard: any 401 means the admin session expired ──
const _fetch = window.fetch.bind(window);
window.fetch = async (...args) => {
  const r = await _fetch(...args);
  if (r.status === 401) location.href = '/login';
  return r;
};

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

// ── Sidebar nav + clock ────────────────────────
const navLinks = document.querySelectorAll('#nav a');
navLinks.forEach(a => a.addEventListener('click', () => {
  navLinks.forEach(x => x.classList.remove('active')); a.classList.add('active');
}));
// Logs are stored in UTC; everything shown is Kuala Lumpur time (GMT+8, no DST)
const KL_OFFSET_MS = 8 * 3600e3;
function toKL(v) {
  if (!v) return null;
  let s = String(v);
  if (!/(Z|[+-][0-9][0-9]:?[0-9][0-9])$/.test(s)) s += 'Z';   // untagged timestamps are UTC
  const t = Date.parse(s);
  return isNaN(t) ? null : new Date(t + KL_OFFSET_MS).toISOString();  // KL wall-clock as ISO text
}
function tick() { document.getElementById('clock').textContent = toKL(new Date().toISOString()).substring(11,19); }
tick(); setInterval(tick, 1000);

function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function fmtTs(v) { const k = toKL(v); return k ? k.replace('T',' ').substring(0,19) : '—'; }

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
    document.getElementById('stat-total').textContent  = stats.total_alerts;
    document.getElementById('stat-high').textContent   = stats.high;
    document.getElementById('stat-users').textContent  = stats.total_users;
    document.getElementById('stat-active').textContent = stats.active_users;
    renderThreatLog();
    renderCharts(allLogs);
  } catch(e) {
    document.getElementById('log-body').innerHTML =
      '<tr><td colspan="8" class="empty-state"><div class="icon">⚠️</div>Backend not reachable.</td></tr>';
  }
}

function renderTable(logs, highlight=false, emptyMsg='No high-severity alerts.') {
  const tbody = document.getElementById('log-body');
  if (!logs.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty-state"><div class="icon">✅</div>${esc(emptyMsg)}</td></tr>`;
    return;
  }
  tbody.innerHTML = logs.map((l,i) => {
    const ts   = esc(fmtTs(l.timestamp));
    const sev  = ['HIGH','MEDIUM','LOW'].includes(l.severity) ? l.severity : 'LOW';
    const hash = esc(String(l.sha256_hash||''));
    const iok  = l.integrity_ok;
    const istr = iok===undefined ? '<span class="hash">—</span>'
               : iok ? '<span class="int-ok">✓ VALID</span>'
                     : '<span class="int-fail">✗ TAMPERED</span>';
    const nr   = (highlight && i===0) ? ' class="new-row"' : '';
    return `<tr${nr}>
      <td class="ts">${ts}</td>
      <td><span class="badge ${sev}">${sev}</span></td>
      <td><strong>${esc(l.ssid||'?')}</strong></td>
      <td class="bssid">${esc(l.bssid||'?')}</td>
      <td>${esc(l.signal_dbm||'?')} dBm</td>
      <td>${esc(l.encryption||'?')}</td>
      <td class="reasons">${(Array.isArray(l.reasons) ? l.reasons : []).map(esc).join(' · ')}</td>
      <td>${istr}<br><span class="hash">${hash.substring(0,20)}…</span></td>
    </tr>`;
  }).join('');
}

// Each alert carries the Firebase uid of the operator whose detector sealed it;
// alerts without a registered user are not shown in any user's log.
const ownerKey = l => String(l.uid || '');

function renderThreatLog() {
  const groups = {};
  allLogs.filter(l => l.severity === 'HIGH').forEach(l => (groups[ownerKey(l)] ||= []).push(l));

  const tabs = allUsers.map(u => ({key: u.id, label: u.username, enabled: u.enabled}));
  const bar = document.getElementById('user-tabs'), owner = document.getElementById('log-owner');
  if (!tabs.length) {
    bar.replaceChildren();
    owner.textContent = '';
    renderTable([], false, 'No users yet. Add a user in User Management to see their log.');
    return;
  }
  if (!tabs.some(t => t.key === activeTab)) activeTab = tabs[0].key;

  bar.replaceChildren(...tabs.map(t => {
    const n = (groups[t.key] || []).length;
    const btn = htmlEl('button', 'utab' + (t.key === activeTab ? ' active' : '') + (t.enabled ? '' : ' off'));
    btn.type = 'button';
    btn.setAttribute('role', 'tab');
    btn.setAttribute('aria-selected', t.key === activeTab);
    btn.append(htmlEl('span', 'uname-t', '👤 ' + t.label), htmlEl('span', 'cnt' + (n ? '' : ' zero'), n));
    btn.addEventListener('click', () => { activeTab = t.key; renderThreatLog(); });
    return btn;
  }));

  const current = tabs.find(t => t.key === activeTab);
  const mine    = groups[activeTab] || [];
  owner.replaceChildren(document.createTextNode('Viewing log of '), htmlEl('b', '', current.label),
    document.createTextNode(` · ${mine.length} high-severity alert${mine.length === 1 ? '' : 's'}` +
      (current.enabled ? '' : ' · account disabled')));

  const q = document.getElementById('search').value.toLowerCase();
  const rows = mine.filter(l => String(l.ssid || '').toLowerCase().includes(q) || String(l.bssid || '').toLowerCase().includes(q));
  const highlight = prevCounts[activeTab] !== undefined && mine.length > prevCounts[activeTab];
  prevCounts = Object.fromEntries(tabs.map(t => [t.key, (groups[t.key] || []).length]));
  renderTable(rows.slice().reverse(), highlight,
    q ? 'No matching alerts.' : `No high-severity alerts for ${current.label}.`);
}

function filterTable() { renderThreatLog(); }

function openUserLog(key) {
  activeTab = key;
  renderThreatLog();
  document.getElementById('threats').scrollIntoView();
}

function exportLogs() {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(allLogs,null,2)],{type:'application/json'}));
  a.download = 'twinguard_forensic_log.json'; a.click();
}

// ── Charts ─────────────────────────────────────
const SEV = [
  {key:'HIGH',   label:'High',   color:'var(--danger)'},
  {key:'MEDIUM', label:'Medium', color:'var(--warning)'},
  {key:'LOW',    label:'Low',    color:'var(--safe)'},
];
const KNOWN_REASONS = ['Unknown BSSID','Open encryption','Multiple APs with same SSID','Signal anomaly','Channel mismatch'];
const NS = 'http://www.w3.org/2000/svg';
const sevOf = l => ['HIGH','MEDIUM','LOW'].includes(l.severity) ? l.severity : 'LOW';

function svgEl(tag, attrs = {}) {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
}
function htmlEl(tag, cls, text) {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  if (text !== undefined) el.textContent = text;
  return el;
}

// Tooltip: rows = [{color, value, label}], built with textContent only
const tip = document.getElementById('tip');
function showTip(x, y, title, rows) {
  tip.replaceChildren();
  if (title) tip.append(htmlEl('div', 'tip-title', title));
  rows.forEach(r => {
    const row = htmlEl('div', 'tip-row'), key = htmlEl('span', 'tip-key');
    key.style.background = r.color;
    row.append(key, htmlEl('b', '', r.value), document.createTextNode(r.label));
    tip.append(row);
  });
  tip.hidden = false;
  const b = tip.getBoundingClientRect();
  tip.style.left = Math.min(x + 14, innerWidth - b.width - 8) + 'px';
  tip.style.top  = Math.min(y + 14, innerHeight - b.height - 8) + 'px';
}
function hideTip() { tip.hidden = true; }
function bindTip(el, title, rows) {
  el.setAttribute('tabindex', '0');
  el.addEventListener('pointermove', e => showTip(e.clientX, e.clientY, title, rows));
  el.addEventListener('pointerleave', hideTip);
  el.addEventListener('focus', () => { const r = el.getBoundingClientRect(); showTip(r.right, r.top, title, rows); });
  el.addEventListener('blur', hideTip);
}

function renderDonut(logs) {
  const svg = document.getElementById('sev-donut'), legend = document.getElementById('sev-legend');
  const counts = SEV.map(s => logs.filter(l => sevOf(l) === s.key).length);
  const total  = counts.reduce((a, b) => a + b, 0);
  const R = 80, C = 2 * Math.PI * R, GAP = 3, nonZero = counts.filter(Boolean).length;
  svg.replaceChildren(svgEl('circle', {cx:100, cy:100, r:R, class:'ring'}));
  legend.replaceChildren();
  let offset = 0;
  SEV.forEach((s, i) => {
    const pct = total ? Math.round(counts[i] / total * 100) : 0;
    if (counts[i]) {
      const len  = counts[i] / total * C;
      const draw = nonZero > 1 ? Math.max(len - GAP, 1) : len;
      const seg  = svgEl('circle', {cx:100, cy:100, r:R, class:'seg',
        'stroke-dasharray': `${draw} ${C - draw}`, 'stroke-dashoffset': -offset,
        transform: 'rotate(-90 100 100)', 'aria-label': `${s.label}: ${counts[i]}`});
      seg.style.stroke = s.color;
      bindTip(seg, null, [{color:s.color, value:counts[i], label:`${s.label} severity · ${pct}%`}]);
      svg.append(seg);
      offset += len;
    }
    const row = htmlEl('div', 'lg-row'), sw = htmlEl('span', 'lg-sw');
    sw.style.background = s.color;
    row.append(sw, htmlEl('span', '', s.label), htmlEl('span', 'lg-val', counts[i]), htmlEl('span', 'lg-pct', total ? pct + '%' : '—'));
    legend.append(row);
  });
  const t = svgEl('text', {x:100, y:104, 'text-anchor':'middle', class:'donut-total'}); t.textContent = total;
  const c = svgEl('text', {x:100, y:126, 'text-anchor':'middle', class:'donut-cap'}); c.textContent = 'ALERTS';
  svg.append(t, c);
}

function barPath(x, y, w, h, r) {
  r = Math.min(r, h, w / 2);
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}

function renderTrend(logs) {
  const svg = document.getElementById('trend-chart');
  const W = Math.max(svg.clientWidth, 280), H = 220, pad = {l:32, r:6, t:10, b:24};
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  svg.replaceChildren();

  const today = new Date(toKL(new Date().toISOString())), days = [];
  for (let i = 13; i >= 0; i--)
    days.push(new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate() - i)).toISOString().slice(0, 10));
  const buckets = Object.fromEntries(days.map(d => [d, {HIGH:0, MEDIUM:0, LOW:0}]));
  logs.forEach(l => { const d = (toKL(l.timestamp) || '').slice(0, 10); if (buckets[d]) buckets[d][sevOf(l)]++; });
  const totals = days.map(d => SEV.reduce((a, s) => a + buckets[d][s.key], 0));
  const sum = totals.reduce((a, b) => a + b, 0);
  document.getElementById('trend-sum').textContent = `${sum} total`;

  const max = Math.max(...totals), top = max <= 4 ? 4 : Math.ceil(max / 4) * 4;
  const pw = W - pad.l - pad.r, ph = H - pad.t - pad.b, base = pad.t + ph;
  [0, top / 2, top].forEach(v => {
    const y = base - v / top * ph;
    svg.append(svgEl('line', {x1:pad.l, x2:W - pad.r, y1:y, y2:y, class: v ? 'grid' : 'base'}));
    const lbl = svgEl('text', {x:pad.l - 8, y:y + 3, 'text-anchor':'end', class:'axis'}); lbl.textContent = v;
    svg.append(lbl);
  });

  const step = pw / days.length, bw = Math.max(4, Math.min(26, step * 0.58));
  const labelEvery = step < 34 ? 3 : 2;
  days.forEach((d, i) => {
    const x = pad.l + i * step + (step - bw) / 2;
    const segs = SEV.filter(s => buckets[d][s.key]);
    let y = base;
    segs.forEach((s, j) => {
      const h = buckets[d][s.key] / top * ph, gap = j ? 2 : 0;
      y -= h;
      const p = svgEl('path', {d: barPath(x, y + gap, bw, Math.max(h - gap, 1), j === segs.length - 1 ? 4 : 0)});
      p.style.fill = s.color;
      svg.append(p);
    });
    if ((days.length - 1 - i) % labelEvery === 0) {
      const lbl = svgEl('text', {x:pad.l + i * step + step / 2, y:H - 6, 'text-anchor':'middle', class:'axis'});
      lbl.textContent = d.slice(5);
      svg.append(lbl);
    }
    // Whole-column hit target: one tooltip lists every severity for that day
    const hit = svgEl('rect', {x:pad.l + i * step, y:pad.t, width:step, height:ph, class:'hit', 'aria-label': `${d}: ${totals[i]} alerts`});
    bindTip(hit, `${d} · ${totals[i]} alert${totals[i] === 1 ? '' : 's'}`,
      SEV.map(s => ({color:s.color, value:buckets[d][s.key], label:s.label})));
    svg.append(hit);
  });

  const legend = document.getElementById('trend-legend');
  legend.replaceChildren(...SEV.map(s => {
    const row = htmlEl('div', 'lg-row'), sw = htmlEl('span', 'lg-sw');
    sw.style.background = s.color;
    row.append(sw, document.createTextNode(s.label));
    return row;
  }));
}

function renderHBars(id, entries, emptyMsg) {
  const box = document.getElementById(id);
  box.replaceChildren();
  const max = Math.max(0, ...entries.map(e => e[1]));
  if (!max) { box.append(htmlEl('div', 'chart-empty', emptyMsg)); return; }
  entries.forEach(([label, n]) => {
    const row = htmlEl('div', 'hb-row'), track = htmlEl('div', 'hb-track'), fill = htmlEl('div', 'hb-fill');
    fill.style.width = (n / max * 100) + '%';
    track.append(fill);
    const lbl = htmlEl('span', 'hb-label', label); lbl.title = label;
    row.append(lbl, track, htmlEl('span', 'hb-val', n));
    box.append(row);
  });
}

function renderStats(logs) {
  const dayAgo = Date.now() - 864e5;
  document.getElementById('stat-24h').textContent =
    logs.filter(l => { const t = Date.parse(l.timestamp); return !isNaN(t) && t >= dayAgo; }).length;
  const valid = logs.filter(l => l.integrity_ok === true).length, bad = logs.length - valid;
  document.getElementById('stat-integrity').textContent = logs.length ? Math.floor(valid / logs.length * 100) + '%' : '—';
  document.getElementById('stat-integrity-sub').textContent = logs.length ? `${valid} valid · ${bad} tampered` : 'no entries';
  document.getElementById('card-integrity').classList.toggle('bad', bad > 0);
}

function renderCharts(logs) {
  hideTip();
  renderStats(logs);
  renderDonut(logs);
  renderTrend(logs);

  const reasons = Object.fromEntries(KNOWN_REASONS.map(r => [r, 0]));
  logs.forEach(l => (Array.isArray(l.reasons) ? l.reasons : []).forEach(r => { r = String(r); reasons[r] = (reasons[r] || 0) + 1; }));
  renderHBars('reason-bars', Object.entries(reasons).sort((a, b) => b[1] - a[1]), 'No detections yet');

  const ssids = {};
  logs.forEach(l => { const k = String(l.ssid || '?'); ssids[k] = (ssids[k] || 0) + 1; });
  renderHBars('ssid-bars', Object.entries(ssids).sort((a, b) => b[1] - a[1]).slice(0, 6), 'No targeted SSIDs yet');
}

let resizeTimer;
window.addEventListener('resize', () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => renderTrend(allLogs), 150); });

// ── Users ──────────────────────────────────────
async function loadUsers() {
  const tbody = document.getElementById('user-body');
  try {
    const users = await (await fetch('/api/users')).json();
    allUsers = users;
    renderThreatLog();
    document.getElementById('stat-users').textContent  = users.length;
    document.getElementById('stat-active').textContent = users.filter(u => u.enabled).length;
    if (!users.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty-state"><div class="icon">👥</div>No users yet. Add one above.</td></tr>';
      return;
    }
    tbody.innerHTML = users.map(u => `<tr class="${u.enabled ? '' : 'disabled'}">
      <td><div class="uname">${esc(u.username)}</div><div class="umeta">${esc(u.full_name) || '—'}</div></td>
      <td class="umeta">${esc(u.email) || '—'}</td>
      <td><span class="badge role">${esc(u.role).toUpperCase()}</span></td>
      <td><span class="badge ${u.enabled ? 'on' : 'off'}">${u.enabled ? 'ENABLED' : 'DISABLED'}</span></td>
      <td class="ts">${fmtTs(u.created_at)}</td>
      <td class="ts">${fmtTs(u.last_login)}</td>
      <td class="row-actions">
        <button class="btn sm" data-user="${esc(u.id)}" onclick="openUserLog(this.dataset.user)">📄 View Log</button>
        ${u.enabled
        ? `<button class="btn sm danger" onclick="setUserStatus('${esc(u.id)}', false)">Disable</button>`
        : `<button class="btn sm enable" onclick="setUserStatus('${esc(u.id)}', true)">Enable</button>`}</td>
    </tr>`).join('');
  } catch(e) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state"><div class="icon">⚠️</div>Backend not reachable.</td></tr>';
  }
}

async function addUser(ev) {
  ev.preventDefault();
  const s = document.getElementById('user-status');
  const body = {
    username:  document.getElementById('u-username').value.trim(),
    full_name: document.getElementById('u-fullname').value.trim(),
    email:     document.getElementById('u-email').value.trim(),
    password:  document.getElementById('u-password').value,
  };
  try {
    const r = await fetch('/api/users', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
    const d = await r.json();
    if (!r.ok) { s.textContent = '✗ ' + (d.error || 'Failed'); s.className = 'form-status err'; return; }
    s.textContent = `✓ Added ${d.username}`; s.className = 'form-status ok';
    document.getElementById('user-form').reset();
    setTimeout(() => { s.textContent = ''; }, 3000);
    loadUsers();
  } catch(e) { s.textContent = '✗ Failed'; s.className = 'form-status err'; }
}

async function setUserStatus(id, enabled) {
  try {
    await fetch(`/api/users/${encodeURIComponent(id)}/status`, {
      method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({enabled})
    });
  } catch(e) {}
  loadUsers();
}

loadRetention();
loadData();
loadUsers();
setInterval(loadData, 10000);
setInterval(() => {
  const el = document.getElementById('rfill');
  el.style.animation='none'; el.offsetHeight; el.style.animation='';
}, 10000);
</script>
</body>
</html>"""

# ── Login / first-run setup page ──────────────────────────────────────────────
LOGIN_HTML = """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TwinGuard-SHA256 | {{ 'Admin Setup' if mode == 'setup' else 'Admin Login' }}</title>
<link rel="icon" type="image/png" href="/static/favicon.png">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;500;700;900&display=swap" rel="stylesheet">
<style>
:root{--accent:#4fc3f7;--accent2:#2b8fe0;--cyan:#7ddcff;--danger:#ff5a76;--safe:#3ee6a8;
  --mono:'Share Tech Mono',monospace;--sans:'Exo 2',sans-serif;}
[data-theme="dark"]{--bg:#0e1c33;--panel:#14284a;--border:#264878;--text:#dcebff;--dim:#86a5cc;--inp:#0f2140;
  --glow:rgba(79,195,247,.18);--grid:rgba(79,195,247,.05);--onaccent:#06142a;}
[data-theme="light"]{--bg:#e8f1fb;--panel:#ffffff;--border:#c3d7ef;--text:#0f2545;--dim:#5b7699;--inp:#f6faff;
  --glow:rgba(43,143,224,.15);--grid:rgba(43,143,224,.06);--accent:#1b8ad6;--cyan:#0e7fc2;--danger:#e23b5a;--onaccent:#fff;}
*{margin:0;padding:0;box-sizing:border-box;}
body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh;display:flex;align-items:center;
  justify-content:center;padding:24px 16px;
  background-image:linear-gradient(var(--grid) 1px,transparent 1px),linear-gradient(90deg,var(--grid) 1px,transparent 1px);
  background-size:32px 32px;}
.card{width:100%;max-width:400px;background:var(--panel);border:1px solid var(--border);border-radius:12px;
  padding:32px 28px;position:relative;box-shadow:0 20px 60px -30px var(--accent);}
.card::before{content:'';position:absolute;top:-1px;left:20px;width:80px;height:2px;
  background:linear-gradient(90deg,var(--accent),transparent);}
.logo{display:flex;align-items:center;gap:12px;margin-bottom:26px;}
.logo-icon{width:52px;height:52px;flex-shrink:0;background:linear-gradient(135deg,var(--cyan),var(--accent2));
  -webkit-mask:url(/static/logo.png) center/contain no-repeat;mask:url(/static/logo.png) center/contain no-repeat;}
.logo-text{font-size:17px;font-weight:900;letter-spacing:2px;}
.logo-sub{font-family:var(--mono);font-size:9px;color:var(--dim);letter-spacing:2px;margin-top:2px;}
h1{font-family:var(--mono);font-size:13px;letter-spacing:3px;color:var(--accent);text-transform:uppercase;margin-bottom:6px;}
.hint{font-size:13px;color:var(--dim);margin-bottom:20px;line-height:1.5;}
label{display:flex;flex-direction:column;gap:6px;font-family:var(--mono);font-size:10px;letter-spacing:2px;
  color:var(--dim);text-transform:uppercase;margin-bottom:14px;}
input{padding:11px 14px;border-radius:8px;border:1px solid var(--border);background:var(--inp);color:var(--text);
  font-family:var(--mono);font-size:14px;outline:none;transition:border-color .2s;}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--glow);}
button{width:100%;margin-top:6px;padding:12px;border:none;border-radius:8px;cursor:pointer;font-family:var(--sans);
  font-size:14px;font-weight:700;letter-spacing:1px;color:var(--onaccent);
  background:linear-gradient(135deg,var(--cyan),var(--accent2));}
button:hover{opacity:.88;}
.error{font-family:var(--mono);font-size:12px;color:var(--danger);border:1px solid var(--danger);border-radius:6px;
  padding:9px 12px;margin-bottom:16px;background:rgba(255,90,118,.08);}
.foot{font-family:var(--mono);font-size:10px;color:var(--dim);text-align:center;margin-top:20px;letter-spacing:1px;}
</style>
<script>
try { document.documentElement.setAttribute('data-theme', localStorage.getItem('tg-theme') || 'dark'); } catch(e) {}
</script>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="logo-icon" role="img" aria-label="TwinGuard logo"></div>
    <div><div class="logo-text">TWINGUARD</div><div class="logo-sub">SHA-256 // ROGUE AP DEFENSE</div></div>
  </div>
  {% if mode == 'setup' %}
    <h1>First-Run Setup</h1>
    {% if locked %}
      <p class="hint">No admin account exists yet. For security, the admin account can only be created from the machine running the dashboard. Open <b>http://127.0.0.1:5000</b> on that machine.</p>
    {% else %}
      <p class="hint">Create the administrator account for this dashboard. It is stored in Firebase Authentication.</p>
      {% if error %}<div class="error">✗ {{ error }}</div>{% endif %}
      <form method="post">
        <label>Admin Email<input name="email" type="email" required maxlength="120" autocomplete="username" autofocus></label>
        <label>Password<input name="password" type="password" required minlength="10" autocomplete="new-password" placeholder="min. 10 characters"></label>
        <label>Confirm Password<input name="confirm" type="password" required minlength="10" autocomplete="new-password"></label>
        <button type="submit">Create Admin Account</button>
      </form>
    {% endif %}
  {% else %}
    <h1>Admin Login</h1>
    <p class="hint">Authorized personnel only. Access attempts are logged.</p>
    {% if error %}<div class="error">✗ {{ error }}</div>{% endif %}
    <form method="post">
      <label>Email<input name="email" type="email" required autocomplete="username" autofocus></label>
      <label>Password<input name="password" type="password" required autocomplete="current-password"></label>
      <button type="submit">Log In</button>
    </form>
  {% endif %}
  <div class="foot">TWINGUARD-SHA256 // ADMIN CONSOLE</div>
</div>
</body>
</html>"""

@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML, admin=session.get("admin"))

@app.route("/setup", methods=["GET", "POST"])
def setup():
    """First-run admin account creation. Only allowed from this machine."""
    if store.admin_exists():
        return redirect(url_for("login"))
    if request.remote_addr not in LOOPBACK:
        return render_template_string(LOGIN_HTML, mode="setup", locked=True, error=None), 403
    error = None
    if request.method == "POST":
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")
        if not EMAIL_RE.match(email):
            error = "Enter a valid email address"
        elif len(password) < 10:
            error = "Password must be at least 10 characters"
        elif password != confirm:
            error = "Passwords do not match"
        else:
            try:
                store.create_admin(email, password, now_iso())
            except FirebaseError as e:
                error = str(e)
            else:
                print(f"[Auth] Admin account '{email}' created in Firebase.")
                session.clear()
                session.permanent = True
                session["admin"] = email
                return redirect(url_for("dashboard"))
    return render_template_string(LOGIN_HTML, mode="setup", locked=False, error=error)

@app.route("/login", methods=["GET", "POST"])
def login():
    if not store.admin_exists():
        return redirect(url_for("setup"))
    if session.get("admin"):
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        key = f"admin:{request.remote_addr}"
        if is_locked(key):
            error = "Too many failed attempts. Try again in a few minutes."
        else:
            try:
                _uid, admin_email = store.sign_in_admin(email, password)
            except FirebaseError as e:
                record_failure(key)
                print(f"[Auth] Failed admin login from {request.remote_addr}.")
                error = str(e)
            else:
                clear_failures(key)
                session.clear()
                session.permanent = True
                session["admin"] = admin_email
                print(f"[Auth] Admin '{admin_email}' logged in from {request.remote_addr}.")
                return redirect(url_for("dashboard"))
    return render_template_string(LOGIN_HTML, mode="login", locked=False, error=error)

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

def main():
    global store
    try:
        store = FirebaseStore()
    except FirebaseNotConfigured as e:
        print(f"\n  [Firebase] Not configured: {e}\n  See firebase/README.md for the one-time setup.\n")
        sys.exit(1)
    threading.Thread(target=purge_old_logs, daemon=True).start()
    print("\n  TwinGuard-SHA256 — Dashboard Server (Firebase)")
    print("  ───────────────────────────────────────────────")
    print("  Open: http://127.0.0.1:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=False)

if __name__ == "__main__":
    main()
