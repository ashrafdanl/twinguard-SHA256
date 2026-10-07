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

import json, hashlib, os, re, secrets, threading, time, uuid
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

app      = Flask(__name__)
LOG_FILE = "forensic_log.json"
CFG_FILE = "twinguard_config.json"
USERS_FILE = "twinguard_users.json"
ADMIN_FILE = "twinguard_admin.json"
SECRET_FILE = "twinguard_secret.key"
log_lock = threading.Lock()
users_lock = threading.Lock()
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


networks_lock = threading.Lock()
latest_networks = []
last_scan_time = None

# ── Live network state ───────────────────────────────────────────────────────
networks_lock = threading.Lock()
latest_networks = []
last_scan_time = None

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


# ── User helpers (call while holding users_lock) ─────────────────────────────
def load_users():
    if not os.path.exists(USERS_FILE):
        return []
    try:
        with open(USERS_FILE) as f:
            return json.load(f)
    except Exception:
        return []

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

def public_user(u):
    return {k: v for k, v in u.items() if k != "password_hash"}

# ── Admin authentication ──────────────────────────────────────────────────────
LOOPBACK = ("127.0.0.1", "::1")
# Endpoints reachable without an admin session
PUBLIC_ENDPOINTS = {"login", "setup", "user_login", "static"}
# Ingest endpoints used by the local detection engine: no session, localhost only
INGEST_ENDPOINTS = {"receive_alert", "receive_networks"}

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

def load_admin():
    if not os.path.exists(ADMIN_FILE):
        return None
    try:
        with open(ADMIN_FILE) as f:
            return json.load(f)
    except Exception:
        return None

def save_admin(admin):
    fd = os.open(ADMIN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(admin, f, indent=2)

# Brute-force throttle: 5 failures per IP+account locks it for 5 minutes
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
    ep = request.endpoint
    if ep in INGEST_ENDPOINTS:
        if request.remote_addr not in LOOPBACK:
            return jsonify({"error": "Forbidden"}), 403
        return None
    if ep in PUBLIC_ENDPOINTS:
        return None
    if not session.get("admin"):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Authentication required"}), 401
        return redirect(url_for("setup" if load_admin() is None else "login"))
    # Session-authenticated writes must be real JSON requests (blocks cross-site form CSRF)
    if request.method == "POST" and request.path.startswith("/api/") and not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    return None

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

@app.route("/api/networks", methods=["POST"])
def receive_networks():
    global latest_networks, last_scan_time

    data = request.get_json(force=True)

    if not isinstance(data, list):
        return jsonify({"error": "Expected a list of networks"}), 400

    with networks_lock:
        latest_networks = data
        last_scan_time = datetime.now(timezone.utc).isoformat()

    print(f"[SCAN] Received {len(data)} network(s)")

    return jsonify({
        "status": "received",
        "count": len(data)
    }), 200


@app.route("/api/networks", methods=["GET"])
def get_networks():
    with networks_lock:
        return jsonify({
            "networks": latest_networks,
            "last_scan": last_scan_time
        })



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
    with users_lock:
        users = load_users()
    return jsonify({
        "total_alerts":   len(logs),
        "high":           sum(1 for l in logs if l.get("severity") == "HIGH"),
        "medium":         sum(1 for l in logs if l.get("severity") == "MEDIUM"),
        "low":            sum(1 for l in logs if l.get("severity") == "LOW"),
        "total_users":    len(users),
        "active_users":   sum(1 for u in users if u.get("enabled")),
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


# ── User management (app operators under the admin) ──────────────────────────
@app.route("/api/users", methods=["GET"])
def list_users():
    with users_lock:
        return jsonify([public_user(u) for u in load_users()])

@app.route("/api/users", methods=["POST"])
def create_user():
    data      = request.get_json(force=True) or {}
    username  = str(data.get("username", "")).strip()
    full_name = str(data.get("full_name", "")).strip()
    email     = str(data.get("email", "")).strip()
    password  = str(data.get("password", ""))
    if not USERNAME_RE.match(username):
        return jsonify({"error": "Username must be 3-32 chars: letters, digits, . _ -"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    with users_lock:
        users = load_users()
        if any(u["username"].lower() == username.lower() for u in users):
            return jsonify({"error": "Username already exists"}), 409
        user = {
            "id":            uuid.uuid4().hex[:12],
            "username":      username,
            "full_name":     full_name,
            "email":         email,
            "role":          "operator",
            "enabled":       True,
            "created_at":    datetime.now(timezone.utc).isoformat(),
            "last_login":    None,
            "password_hash": generate_password_hash(password),
        }
        users.append(user)
        save_users(users)
    print(f"[Users] Created user '{username}'.")
    return jsonify(public_user(user)), 201

@app.route("/api/users/<user_id>/status", methods=["POST"])
def set_user_status(user_id):
    data = request.get_json(force=True) or {}
    if not isinstance(data.get("enabled"), bool):
        return jsonify({"error": "'enabled' must be true or false"}), 400
    with users_lock:
        users = load_users()
        for u in users:
            if u["id"] == user_id:
                u["enabled"] = data["enabled"]
                save_users(users)
                print(f"[Users] {'Enabled' if u['enabled'] else 'Disabled'} user '{u['username']}'.")
                return jsonify(public_user(u))
    return jsonify({"error": "User not found"}), 404

@app.route("/api/users/login", methods=["POST"])
def user_login():
    """Login endpoint for the operator app. Disabled accounts are rejected."""
    data     = request.get_json(force=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    key = f"user:{request.remote_addr}:{username.lower()}"
    if is_locked(key):
        return jsonify({"error": "Too many failed attempts, try again later"}), 429
    with users_lock:
        users = load_users()
        for u in users:
            if u["username"].lower() == username.lower() and check_password_hash(u["password_hash"], password):
                clear_failures(key)
                if not u.get("enabled"):
                    return jsonify({"error": "Account disabled"}), 403
                u["last_login"] = datetime.now(timezone.utc).isoformat()
                save_users(users)
                return jsonify({"status": "ok", "user": public_user(u)})
    record_failure(key)
    return jsonify({"error": "Invalid credentials"}), 401

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
.logo-icon{width:40px;height:40px;border-radius:10px;font-size:20px;flex-shrink:0;
  background:linear-gradient(135deg,var(--cyan),var(--accent2));display:flex;align-items:center;justify-content:center;
  box-shadow:0 0 18px var(--glow);}
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
.sys-line{font-family:var(--mono);font-size:10px;color:var(--dim);letter-spacing:1px;}
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
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;}
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

/* ── Users ─────────────────────────────── */
.user-form{padding:20px 24px;display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;align-items:end;
  border-bottom:1px solid var(--border);}
.user-form label{display:flex;flex-direction:column;gap:6px;font-family:var(--mono);font-size:10px;letter-spacing:2px;
  color:var(--dim);text-transform:uppercase;}
.user-form .field{min-width:0;width:100%;}
.form-actions{display:flex;align-items:center;gap:12px;flex-wrap:wrap;}
.uname{font-weight:700;} .umeta{font-size:12px;color:var(--dim);}
tr.disabled td{opacity:.6;} tr.disabled td:last-child{opacity:1;}

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
    <div class="logo-icon">🛡</div>
    <div>
      <div class="logo-text">TWINGUARD</div>
      <div class="logo-sub">SHA-256 // ROGUE AP DEFENSE</div>
    </div>
  </div>
  <nav class="nav" id="nav">
    <div class="nav-title">// CONSOLE</div>
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
    <div class="chip">UTC <b id="clock">--:--:--</b></div>
    <div class="status-badge"><div class="pulse"></div>MONITORING ACTIVE</div>
  </div>
</header>

<main>
  <section id="overview">
    <div class="sec-head"><div class="sec-title">Threat Overview</div><div class="sec-note">auto-refresh 10s</div></div>
    <div class="stats-grid">
      <div class="stat-card total"><div class="stat-label">Total Alerts</div><div class="stat-value" id="stat-total">0</div></div>
      <div class="stat-card high"><div class="stat-label">High Severity</div><div class="stat-value" id="stat-high">0</div></div>
      <div class="stat-card medium"><div class="stat-label">Medium Severity</div><div class="stat-value" id="stat-med">0</div></div>
      <div class="stat-card low"><div class="stat-label">Low Severity</div><div class="stat-value" id="stat-low">0</div></div>
      <div class="stat-card users"><div class="stat-label">Total Users</div><div class="stat-value" id="stat-users">0</div><div class="stat-sub">registered operators</div></div>
      <div class="stat-card active"><div class="stat-label">Active Users</div><div class="stat-value" id="stat-active">0</div><div class="stat-sub">accounts enabled</div></div>
    </div>
  </section>

  <section id="threats">
    <div class="sec-head"><div class="sec-title">Threat Log</div><div class="sec-note">SHA-256 sealed forensic entries</div></div>
    <div class="refresh-bar"><div class="refresh-fill" id="rfill"></div></div>
    <div class="controls">
      <button class="btn primary" onclick="loadData()">↻ Refresh</button>
      <input class="search" id="search" type="text" placeholder="Filter by SSID or BSSID..." oninput="filterTable()">
      <button class="btn" onclick="exportLogs()">⬇ Export JSON</button>
    </div>
    <div class="panel table-wrap">
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
  </section>

  <section id="users">
    <div class="sec-head"><div class="sec-title">User Management</div><div class="sec-note">operator accounts for the TwinGuard app</div></div>
    <div class="panel">
      <form class="user-form" id="user-form" onsubmit="addUser(event)">
        <label>Username<input class="field" id="u-username" required minlength="3" maxlength="32" placeholder="operator01"></label>
        <label>Full Name<input class="field" id="u-fullname" maxlength="80" placeholder="Ali Ahmad"></label>
        <label>Email<input class="field" id="u-email" type="email" maxlength="120" placeholder="ali@example.com"></label>
        <label>Password<input class="field" id="u-password" type="password" required minlength="8" placeholder="min. 8 characters"></label>
        <div class="form-actions">
          <button class="btn primary" type="submit">＋ Add User</button>
          <span class="form-status" id="user-status"></span>
        </div>
      </form>
      <div class="table-wrap">
        <table>
          <thead><tr><th>User</th><th>Email</th><th>Role</th><th>Status</th><th>Created (UTC)</th><th>Last Login (UTC)</th><th>Action</th></tr></thead>
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

<footer>TwinGuard-SHA256 &nbsp;|&nbsp; GMI Final Year Project JAN 2026 &nbsp;|&nbsp; SEM 4 DCBS 6</footer>
</div>

<script>
let allLogs = [], prevCount = 0;

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
function tick() { document.getElementById('clock').textContent = new Date().toISOString().substring(11,19); }
tick(); setInterval(tick, 1000);

function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function fmtTs(v) { return v ? v.replace('T',' ').substring(0,19) : '—'; }

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
    document.getElementById('stat-med').textContent    = stats.medium;
    document.getElementById('stat-low').textContent    = stats.low;
    document.getElementById('stat-users').textContent  = stats.total_users;
    document.getElementById('stat-active').textContent = stats.active_users;
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
    const ts   = esc((l.timestamp||'').replace('T',' ').replace('Z',''));
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

// ── Users ──────────────────────────────────────
async function loadUsers() {
  const tbody = document.getElementById('user-body');
  try {
    const users = await (await fetch('/api/users')).json();
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
      <td>${u.enabled
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
.logo-icon{width:44px;height:44px;border-radius:10px;font-size:22px;display:flex;align-items:center;justify-content:center;
  background:linear-gradient(135deg,var(--cyan),var(--accent2));box-shadow:0 0 18px var(--glow);}
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
    <div class="logo-icon">🛡</div>
    <div><div class="logo-text">TWINGUARD</div><div class="logo-sub">SHA-256 // ROGUE AP DEFENSE</div></div>
  </div>
  {% if mode == 'setup' %}
    <h1>First-Run Setup</h1>
    {% if locked %}
      <p class="hint">No admin account exists yet. For security, the admin account can only be created from the machine running the dashboard. Open <b>http://127.0.0.1:5000</b> on that machine.</p>
    {% else %}
      <p class="hint">Create the administrator account for this dashboard.</p>
      {% if error %}<div class="error">✗ {{ error }}</div>{% endif %}
      <form method="post">
        <label>Admin Username<input name="username" required minlength="3" maxlength="32" autocomplete="username" autofocus></label>
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
      <label>Username<input name="username" required autocomplete="username" autofocus></label>
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
    if load_admin() is not None:
        return redirect(url_for("login"))
    if request.remote_addr not in LOOPBACK:
        return render_template_string(LOGIN_HTML, mode="setup", locked=True, error=None), 403
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")
        if not USERNAME_RE.match(username):
            error = "Username must be 3-32 chars: letters, digits, . _ -"
        elif len(password) < 10:
            error = "Password must be at least 10 characters"
        elif password != confirm:
            error = "Passwords do not match"
        else:
            save_admin({"username": username,
                        "password_hash": generate_password_hash(password),
                        "created_at": datetime.now(timezone.utc).isoformat()})
            print(f"[Auth] Admin account '{username}' created.")
            session.clear()
            session.permanent = True
            session["admin"] = username
            return redirect(url_for("dashboard"))
    return render_template_string(LOGIN_HTML, mode="setup", locked=False, error=error)

@app.route("/login", methods=["GET", "POST"])
def login():
    admin = load_admin()
    if admin is None:
        return redirect(url_for("setup"))
    if session.get("admin"):
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        key = f"admin:{request.remote_addr}"
        if is_locked(key):
            error = "Too many failed attempts. Try again in a few minutes."
        elif username.lower() == admin["username"].lower() and check_password_hash(admin["password_hash"], password):
            clear_failures(key)
            session.clear()
            session.permanent = True
            session["admin"] = admin["username"]
            print(f"[Auth] Admin '{admin['username']}' logged in from {request.remote_addr}.")
            return redirect(url_for("dashboard"))
        else:
            record_failure(key)
            print(f"[Auth] Failed admin login from {request.remote_addr}.")
            error = "Invalid username or password"
    return render_template_string(LOGIN_HTML, mode="login", locked=False, error=error)

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    print("\n  TwinGuard-SHA256 — Dashboard Server")
    print("  ─────────────────────────────────────")
    print("  Open: http://127.0.0.1:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=False)