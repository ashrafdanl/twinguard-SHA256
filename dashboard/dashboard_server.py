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

Security (LAN):
  - HTTPS only (TLS 1.2+), served by cheroot; certificates from make_certs.py
  - Admin login = Firebase password + authenticator-app code (TOTP 2FA)
  - CSRF tokens, strict Content-Security-Policy, secure cookies, idle timeout

Run:
    python3 dashboard/make_certs.py        # once, and when the IP changes
    python3 dashboard/dashboard_server.py
Then open: http://127.0.0.1:5000   (or https:// when started with --https)
"""

import argparse, hmac, json, hashlib, ipaddress, os, re, secrets, socket, ssl, sys, threading, time
from datetime import datetime, timezone, timedelta
import pyotp, qrcode, qrcode.image.svg
from cheroot import wsgi
from cheroot.ssl.builtin import BuiltinSSLAdapter
from cryptography import x509
from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for, g
from markupsafe import Markup
from firebase_store import FirebaseStore, FirebaseError, FirebaseNotConfigured
import make_certs

app      = Flask(__name__)
CFG_FILE = "twinguard_config.json"
SECRET_FILE = "twinguard_secret.key"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
EMAIL_RE    = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRV_CRT  = os.path.join(BASE_DIR, "certs", "server.crt")
SRV_KEY  = os.path.join(BASE_DIR, "certs", "server.key")

IDLE_TIMEOUT     = 30 * 60      # log out after 30 min without admin activity
ABSOLUTE_TIMEOUT = 8 * 3600     # and always after 8 h
RECHECK_SECONDS  = 5 * 60       # re-verify the admin account with Firebase
PENDING_SECONDS  = 5 * 60       # time allowed between password and 2FA code
MAX_2FA_TRIES    = 5

store = None  # FirebaseStore, created in main()

# ── Config ────────────────────────────────────────────────────────────────────
def load_config():
    defaults = {"retention_days": 30, "scan_retention_days": 30}
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
    """Verify integrity. Strip sha256_hash AND integrity_ok before recomputing.
    Two accepted canonical forms (see firebase/README.md, "Sealing a detection"):
      v1  Python detector: json.dumps(sort_keys=True)                 -> '{"a": 1, "b": "x"}'
      v2  phone app:       sorted keys, no spaces, UTF-8 (no \\u escapes) -> '{"a":1,"b":"x"}'"""
    stored  = entry.get("sha256_hash", "")
    payload = {k: v for k, v in entry.items()
               if k not in ("sha256_hash", "integrity_ok")}
    for canonical in (json.dumps(payload, sort_keys=True),
                      json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)):
        if hmac.compare_digest(hashlib.sha256(canonical.encode("utf-8")).hexdigest(), stored):
            return True
    return False

# ── Admin authentication & web security ──────────────────────────────────────
LOOPBACK = ("127.0.0.1", "::1")
# Pages reachable without a full admin session (they check their own state)
PUBLIC_ENDPOINTS = {"login", "setup", "two_factor", "two_factor_setup", "logout", "static"}

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
    SESSION_COOKIE_NAME="twinguard_session",  # --https switches to a Secure "__Host-" cookie
    SESSION_COOKIE_SECURE=False,
    USE_HTTPS=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=timedelta(seconds=ABSOLUTE_TIMEOUT),
    MAX_CONTENT_LENGTH=64 * 1024,
)

# Brute-force throttle: 5 failures (password or 2FA) per IP locks it for 5 minutes
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

def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]

@app.context_processor
def template_security():
    return {"csrf_token": csrf_token, "csp_nonce": g.get("csp_nonce", "")}

# ── Session states: pending (password OK, 2FA not yet) -> full admin session ──
def start_pending(kind, uid, email):
    session.clear()
    session["pending"] = {"kind": kind, "uid": uid, "email": email, "at": time.time(), "tries": 0}

def get_pending(kind):
    p = session.get("pending")
    if not p or p.get("kind") != kind or time.time() - p.get("at", 0) > PENDING_SECONDS:
        return None
    return p

def start_admin_session(uid, email):
    session.clear()                      # new CSRF token, no pending state
    session.permanent = True
    now = time.time()
    session.update(admin=email, admin_uid=uid, login_at=now, last_active=now, checked_at=now)

def admin_session_valid():
    if not session.get("admin"):
        return False
    now = time.time()
    if now - session.get("login_at", 0) > ABSOLUTE_TIMEOUT or now - session.get("last_active", 0) > IDLE_TIMEOUT:
        return False
    if now - session.get("checked_at", 0) > RECHECK_SECONDS:
        # disabled, admin claim removed, or sessions revoked (password reset) -> out
        if not store.admin_account_ok(session.get("admin_uid", ""), session.get("login_at", 0) + 120):
            return False
        session["checked_at"] = now
    if not request.headers.get("X-Background"):   # the 10 s auto-refresh is not admin activity
        session["last_active"] = now
    return True

def verify_totp(secret, code):
    """Return the matching TOTP time-step (current +/- 1), or None."""
    code = re.sub(r"\s", "", code or "")
    if not re.fullmatch(r"[0-9]{6}", code):
        return None
    totp, step = pyotp.TOTP(secret), int(time.time()) // 30
    for counter in (step - 1, step, step + 1):
        if hmac.compare_digest(totp.generate_otp(counter), code):
            return counter
    return None

def qr_svg(data):
    img = qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
    return Markup(img.to_string(encoding="unicode"))

@app.before_request
def security_checks():
    g.csp_nonce = secrets.token_urlsafe(16)
    request.host                  # raises 400 Bad Request if the Host isn't in TRUSTED_HOSTS
    if request.method == "POST":
        sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
        if not sent or not hmac.compare_digest(sent, session.get("csrf", "")):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Security token expired. Reload the page."}), 403
            return redirect(request.path)          # stale form: show it again with a fresh token
    if request.endpoint in PUBLIC_ENDPOINTS:
        return None
    if not admin_session_valid():
        if request.path.startswith("/api/"):
            session.clear()
            return jsonify({"error": "Authentication required"}), 401
        for kind, page in (("enroll", "two_factor_setup"), ("2fa", "two_factor")):
            if get_pending(kind):              # mid-login: continue where they left off
                return redirect(url_for(page))
        session.clear()
        return redirect(url_for("login" if store.admin_exists() else "setup"))
    # Session-authenticated API writes must be JSON (defence in depth with the CSRF token)
    if request.method == "POST" and request.path.startswith("/api/") and not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    return None

@app.after_request
def security_headers(resp):
    n = g.get("csp_nonce", "")
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'nonce-{n}'; "
        f"style-src 'self' 'nonce-{n}' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; "
        "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
    if app.config["USE_HTTPS"]:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    if request.endpoint != "static":
        resp.headers["Cache-Control"] = "no-store"
    return resp

@app.errorhandler(FirebaseError)
def firebase_error(e):
    return jsonify({"error": str(e)}), 400

# ── Retention engine (runs every hour) ───────────────────────────────────────
def purge_old_logs():
    while True:
        try:
            cfg    = load_config()
            days   = int(cfg.get("retention_days", 30))
            cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")
            removed = store.purge_alerts_before(cutoff)
            if removed > 0:
                print(f"[Retention] Purged {removed} alert(s) older than {days} day(s).")
        except Exception as ex:
            print(f"[Retention] Error (alerts): {ex}")
        try:
            sdays   = int(cfg.get("scan_retention_days", 30))
            scutoff = (datetime.now(timezone.utc) - timedelta(days=sdays)).isoformat().replace("+00:00", "Z")
            sremoved = store.purge_scans_before(scutoff)
            if sremoved > 0:
                print(f"[Retention] Purged {sremoved} scan(s) older than {sdays} day(s).")
        except Exception as ex:
            print(f"[Retention] Error (scans): {ex}")
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

@app.route("/api/logs/low", methods=["GET"])
def get_low_logs():
    result = []
    for e in store.low_detections():
        copy = dict(e)
        copy["integrity_ok"] = verify_sha256(e)
        result.append(copy)
    return jsonify(result)

@app.route("/api/scans", methods=["GET"])
def get_scans():
    result = []
    for e in store.scans():
        copy = dict(e)
        copy["integrity_ok"] = verify_sha256(e)   # verify ORIGINAL, attach to COPY
        result.append(copy)
    return jsonify(result)

@app.route("/api/stats", methods=["GET"])
def get_stats():
    logs   = store.alerts()
    counts = store.severity_counts()
    users  = store.user_profiles().values()
    cfg    = load_config()
    return jsonify({
        "total_alerts":   sum(counts.values()),        # every detection in all operators' spaces
        "high":           counts["HIGH"],
        "medium":         counts["MEDIUM"],
        "low":            counts["LOW"],
        "critical_shown": len(logs),                    # HIGH + MEDIUM detections delivered to the dashboard
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
    data = request.get_json(force=True) or {}
    cfg, out = load_config(), {}
    for key in ("retention_days", "scan_retention_days"):
        if key not in data:
            continue
        try:
            days = int(data[key])
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid value"}), 400
        if days < 1 or days > 3650:
            return jsonify({"error": "Must be between 1 and 3650"}), 400
        cfg[key] = days
        out[key] = days
    if not out:
        return jsonify({"error": "Nothing to update"}), 400
    save_config(cfg)
    print(f"[Config] Retention updated: {out}")
    return jsonify({"status": "ok", **out})

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

@app.route("/api/users/<user_id>/delete", methods=["POST"])
def delete_user(user_id):
    try:
        username = store.delete_user(user_id)
    except KeyError:
        return jsonify({"error": "User not found"}), 404
    print(f"[Users] Deleted user '{username}' and all their data.")
    return jsonify({"id": user_id, "deleted": True})


# ── Admin account (self-service from Settings) ───────────────────────────────
def _reauth_admin(current_password):
    """Re-verify the signed-in admin's own password. Returns (uid, email) or
    raises FirebaseError (wrong password, etc.)."""
    email, uid = session.get("admin"), session.get("admin_uid")
    if not email or not uid:
        raise FirebaseError("Not signed in")
    vuid, _ = store.sign_in_admin(email, current_password or "")
    if vuid != uid:
        raise FirebaseError("Password check failed")
    return uid, email

@app.route("/api/admin/account", methods=["GET"])
def admin_account():
    return jsonify({"email": session.get("admin", "")})

@app.route("/api/admin/password", methods=["POST"])
def admin_change_password():
    data = request.get_json(force=True) or {}
    new = str(data.get("new_password", ""))
    if len(new) < 8:
        return jsonify({"error": "New password must be at least 8 characters"}), 400
    uid, _ = _reauth_admin(data.get("current_password"))
    store.update_admin_password(uid, new)
    print("[Auth] Admin password changed from Settings.")
    return jsonify({"status": "ok"})

@app.route("/api/admin/email", methods=["POST"])
def admin_change_email():
    data = request.get_json(force=True) or {}
    new_email = str(data.get("new_email", "")).strip()
    if not EMAIL_RE.match(new_email):
        return jsonify({"error": "Enter a valid email address"}), 400
    uid, old = _reauth_admin(data.get("current_password"))
    if new_email == old:
        return jsonify({"error": "That is already your email"}), 400
    store.update_admin_email(uid, new_email)
    session["admin"] = new_email        # keep the live session; show the new email
    print(f"[Auth] Admin email changed from '{old}' to '{new_email}'.")
    return jsonify({"status": "ok", "email": new_email})

@app.route("/api/admin/2fa/reset", methods=["POST"])
def admin_reset_2fa():
    """Re-verify the password, then hand off to the existing 2FA enrolment page."""
    data = request.get_json(force=True) or {}
    uid, email = _reauth_admin(data.get("current_password"))
    start_pending("enroll", uid, email)   # clears the session; enrolment page takes over
    print(f"[Auth] Admin '{email}' started 2FA re-enrolment from Settings.")
    return jsonify({"status": "ok", "redirect": url_for("two_factor_setup")})


# ── Dashboard HTML ────────────────────────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TwinGuard-SHA256 | Dashboard</title>
<meta name="csrf-token" content="{{ csrf_token() }}">
<link rel="icon" type="image/png" href="/static/favicon.png">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;500;700;900&display=swap" rel="stylesheet">
<style nonce="{{ csp_nonce }}">
:root {
  --accent:#4fc3f7; --accent2:#2b8fe0; --cyan:#7ddcff;
  --danger:#ff5a76; --warning:#ffb547; --safe:#3ee6a8; --violet:#a78bfa;
  --mono:'Share Tech Mono',monospace; --sans:'Exo 2',sans-serif;
  --radius:10px; --t:.25s ease; --side:250px;
}
[data-theme="dark"]  { --bg:#0e1c33; --bg2:#0b172b; --panel:#14284a; --panel2:#18305a; --border:#264878;
  --text:#dcebff; --dim:#86a5cc; --inp:#0f2140; --inp-border:#264878; --glow:rgba(79,195,247,.18); --grid:rgba(79,195,247,.05); --onaccent:#06142a; }
[data-theme="light"] { --bg:#e8f1fb; --bg2:#dce9f8; --panel:#ffffff; --panel2:#f0f6fd; --border:#c3d7ef;
  --text:#0f2545; --dim:#5b7699; --inp:#eef4fb; --inp-border:#6a8ab3; --glow:rgba(43,143,224,.15); --grid:rgba(43,143,224,.06);
  --accent:#1b8ad6; --cyan:#0e7fc2; --safe:#0fae74; --warning:#d98a00; --danger:#e23b5a; --violet:#7c5ce0; --onaccent:#fff; }

*{margin:0;padding:0;box-sizing:border-box;}
[hidden]{display:none!important;}
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
.logo{display:flex;align-items:center;gap:10px;padding:22px 16px;border-bottom:1px solid var(--border);}
.logo-icon{width:58px;height:58px;flex-shrink:0;background:linear-gradient(135deg,var(--cyan),var(--accent2));
  -webkit-mask:url(/static/logo.png) center/contain no-repeat;mask:url(/static/logo.png) center/contain no-repeat;}
.logo-text{font-size:23px;font-weight:900;letter-spacing:1.5px;line-height:1.1;color:var(--text);}
.logo-sub{font-family:var(--mono);font-size:11px;color:var(--dim);letter-spacing:2px;margin-top:4px;}
.nav{padding:18px 12px;display:flex;flex-direction:column;gap:4px;flex:1;}
.nav-title{font-family:var(--mono);font-size:13px;letter-spacing:3px;color:var(--dim);padding:8px 12px 6px;}
.nav a{display:flex;align-items:center;gap:12px;padding:11px 14px;border-radius:8px;color:var(--dim);
  text-decoration:none;font-size:17px;font-weight:500;letter-spacing:.5px;border-left:3px solid transparent;transition:all .2s;}
.nav a:hover{color:var(--text);background:var(--glow);}
.nav a.active{color:var(--accent);background:var(--glow);border-left-color:var(--accent);}
.nav a .ico{width:20px;text-align:center;}
/* PNG icons painted in the link's current colour, so they follow the
   dim / hover / active theme states just like the glyph icons. */
.ico.img{display:inline-block;width:20px;height:20px;background:currentColor;vertical-align:middle;
  -webkit-mask-position:center;mask-position:center;-webkit-mask-size:contain;mask-size:contain;
  -webkit-mask-repeat:no-repeat;mask-repeat:no-repeat;}
.ico-radar{-webkit-mask-image:url(/static/radar.png);mask-image:url(/static/radar.png);}
.ico-users{-webkit-mask-image:url(/static/users.png);mask-image:url(/static/users.png);}
.side-foot{padding:16px 20px;border-top:1px solid var(--border);display:flex;flex-direction:column;gap:12px;}
.theme-toggle{position:relative;width:64px;height:32px;padding:0;flex:none;border:none;border-radius:16px;cursor:pointer;
  background:linear-gradient(145deg,#1b2a4a,#0c1424);box-shadow:inset 0 1px 3px rgba(0,0,0,.55);transition:box-shadow var(--t);}
.theme-toggle:focus-visible{outline:none;box-shadow:inset 0 1px 3px rgba(0,0,0,.55),0 0 0 3px var(--glow);}
.theme-toggle .knob{position:absolute;top:3px;left:3px;width:26px;height:26px;border-radius:50%;color:#0b1b33;
  background:radial-gradient(circle at 35% 30%,#e4f3ff,#8fcbf2 58%,#4e93d1);
  display:flex;align-items:center;justify-content:center;box-shadow:0 2px 6px rgba(0,0,0,.45);
  transition:transform var(--t),background var(--t),box-shadow var(--t);}
.theme-toggle .knob svg{width:15px;height:15px;}
.theme-toggle .ic-sun{display:block;}
.theme-toggle .ic-moon{display:none;}
[data-theme="light"] .theme-toggle{background:linear-gradient(145deg,#e4edf9,#c4d5ec);box-shadow:inset 0 1px 3px rgba(120,140,170,.45);}
[data-theme="light"] .theme-toggle .knob{color:#1766b0;background:radial-gradient(circle at 35% 30%,#ffffff,#eaf3ff 60%,#cfe3f8);box-shadow:0 2px 5px rgba(60,90,130,.35);}
[data-theme="dark"] .theme-toggle{box-shadow:inset 0 1px 3px rgba(0,0,0,.55),0 0 16px rgba(52,205,224,.3);}
[data-theme="dark"] .theme-toggle .knob{transform:translateX(32px);
  background:radial-gradient(circle at 35% 30%,#ecf9ff,#a6e6ff 55%,#4ac2d8);
  box-shadow:0 0 14px 2px rgba(74,220,240,.6),0 2px 6px rgba(0,0,0,.4);}
[data-theme="dark"] .theme-toggle .ic-sun{display:none;}
[data-theme="dark"] .theme-toggle .ic-moon{display:block;}
.sys-line{font-family:var(--mono);font-size:13px;color:var(--dim);letter-spacing:1px;overflow-wrap:anywhere;}
.logout{width:100%;}

/* ── Topbar ────────────────────────────── */
.wrap{margin-left:var(--side);min-height:100vh;display:flex;flex-direction:column;}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;padding:16px 32px;
  background:color-mix(in srgb,var(--bg) 85%,transparent);backdrop-filter:blur(8px);
  border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100;}
.crumb{font-family:var(--mono);font-size:14px;letter-spacing:3px;color:var(--dim);}
.page-title{font-size:24px;font-weight:700;letter-spacing:1px;}
.page-title span{color:var(--accent);}
.top-right{display:flex;align-items:center;gap:14px;flex-wrap:wrap;}
.chip{font-family:var(--mono);font-size:15px;padding:7px 12px;border-radius:6px;border:1px solid var(--border);
  background:var(--panel);color:var(--dim);}
.chip b{color:var(--text);font-weight:400;}
.status-badge{display:flex;align-items:center;gap:8px;font-family:var(--mono);font-size:15px;color:var(--safe);
  padding:7px 12px;border-radius:6px;border:1px solid color-mix(in srgb,var(--safe) 40%,transparent);
  background:color-mix(in srgb,var(--safe) 8%,transparent);}
.pulse{width:8px;height:8px;border-radius:50%;background:var(--safe);animation:pulse 2s infinite;}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(62,230,168,.5);}50%{box-shadow:0 0 0 8px rgba(62,230,168,0);}}

main{padding:28px 32px;width:100%;max-width:1400px;}
section{margin-bottom:28px;scroll-margin-top:90px;}
.sec-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px;flex-wrap:wrap;}
.sec-title{font-family:var(--mono);font-size:16px;letter-spacing:3px;color:var(--accent);text-transform:uppercase;
  display:flex;align-items:center;gap:10px;}
.sec-title::before{content:'';width:8px;height:8px;background:var(--accent);box-shadow:0 0 10px var(--accent);transform:rotate(45deg);}
.sec-note{font-family:var(--mono);font-size:14px;color:var(--dim);}

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
.stat-label{font-family:var(--mono);font-size:13px;letter-spacing:2.5px;color:var(--dim);text-transform:uppercase;margin-bottom:10px;}
.stat-value{font-size:38px;font-weight:900;line-height:1;color:var(--c);}
.stat-sub{font-family:var(--mono);font-size:13px;color:var(--dim);margin-top:8px;}

/* ── Retention ─────────────────────────── */
.retention-panel{padding:18px 24px;display:flex;align-items:center;gap:16px;flex-wrap:wrap;}
.ret-label{font-family:var(--mono);font-size:14px;letter-spacing:2px;color:var(--dim);text-transform:uppercase;white-space:nowrap;}
.ret-desc{font-size:16px;color:var(--text);flex:1;min-width:180px;}
.ret-wrap{display:flex;align-items:center;gap:10px;}
.ret-input{width:72px;padding:8px 10px;border-radius:8px;border:1px solid var(--inp-border);
  background:var(--inp);color:var(--text);font-family:var(--mono);font-size:17px;text-align:center;outline:none;transition:border-color .2s;}
.ret-input:focus{border-color:var(--accent);}
.fs-wrap{display:flex;align-items:center;gap:16px;flex:1;min-width:240px;}
.fs-a{font-family:var(--sans);font-weight:700;color:var(--text);line-height:1;cursor:pointer;user-select:none;}
.fs-a-sm{font-size:15px;} .fs-a-lg{font-size:27px;}
.fs-track{position:relative;flex:1;max-width:320px;height:28px;display:flex;align-items:center;}
.fs-line{position:absolute;left:1px;right:1px;top:50%;height:2px;transform:translateY(-1px);background:var(--inp-border);border-radius:1px;pointer-events:none;}
.fs-tick{position:absolute;top:50%;width:2px;height:9px;transform:translate(-50%,-50%);background:var(--inp-border);border-radius:1px;pointer-events:none;}
.fs-ticks{position:absolute;left:0;right:0;top:0;bottom:0;pointer-events:none;}
.fs-ticks .fs-tick:nth-child(1){left:0;}
.fs-ticks .fs-tick:nth-child(2){left:16.667%;}
.fs-ticks .fs-tick:nth-child(3){left:33.333%;}
.fs-ticks .fs-tick:nth-child(4){left:50%;}
.fs-ticks .fs-tick:nth-child(5){left:66.667%;}
.fs-ticks .fs-tick:nth-child(6){left:83.333%;}
.fs-ticks .fs-tick:nth-child(7){left:100%;}
.fs-ticks .fs-tick:first-child,.fs-ticks .fs-tick:last-child{height:13px;}
.fs-slider{position:relative;z-index:2;-webkit-appearance:none;appearance:none;width:100%;height:28px;background:transparent;outline:none;cursor:pointer;margin:0;}
.fs-slider::-webkit-slider-runnable-track{background:transparent;height:28px;}
.fs-slider::-webkit-slider-thumb{-webkit-appearance:none;appearance:none;width:24px;height:24px;margin-top:2px;border-radius:50%;
  background:#fff;border:1px solid rgba(0,0,0,.18);box-shadow:0 1px 5px rgba(0,0,0,.4);cursor:pointer;}
.fs-slider::-moz-range-track{background:transparent;height:28px;}
.fs-slider::-moz-range-thumb{width:24px;height:24px;border-radius:50%;background:#fff;border:1px solid rgba(0,0,0,.18);box-shadow:0 1px 5px rgba(0,0,0,.4);cursor:pointer;}
.fs-slider:focus-visible::-webkit-slider-thumb{box-shadow:0 0 0 3px var(--glow),0 1px 5px rgba(0,0,0,.4);}
.fs-slider:focus-visible::-moz-range-thumb{box-shadow:0 0 0 3px var(--glow),0 1px 5px rgba(0,0,0,.4);}
.fs-reset{margin-left:10px;padding:4px;flex:none;display:inline-flex;align-items:center;justify-content:center;
  background:none;border:none;color:var(--text);cursor:pointer;transition:color .15s;}
.fs-reset:hover{color:var(--accent);}
.fs-reset:focus-visible{outline:none;border-radius:6px;box-shadow:0 0 0 3px var(--glow);}
.fs-reset-ic{width:21px;height:21px;display:block;background:currentColor;
  -webkit-mask:url(/static/reset.png) center/contain no-repeat;mask:url(/static/reset.png) center/contain no-repeat;}
.ret-unit{font-family:var(--mono);font-size:15px;color:var(--dim);}
.ret-status,.form-status{font-family:var(--mono);font-size:15px;}
.ok{color:var(--safe);} .err{color:var(--danger);}
.ret-select{padding:8px 12px;border-radius:8px;border:1px solid var(--inp-border);background:var(--inp);
  color:var(--text);font-family:var(--mono);font-size:16px;outline:none;cursor:pointer;transition:border-color .2s;min-width:120px;}
.ret-select:focus{border-color:var(--accent);}
.export-wrap{flex-wrap:wrap;}
/* Admin account */
.acct-panel{flex-direction:column;align-items:stretch;}
.acct-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px;width:100%;}
.acct-card{display:flex;flex-direction:column;gap:12px;padding:16px;border:1px solid var(--border);border-radius:10px;background:var(--panel2);}
.acct-title{font-family:var(--mono);font-size:14px;letter-spacing:2px;color:var(--accent);text-transform:uppercase;}
.acct-card label{display:flex;flex-direction:column;gap:6px;font-family:var(--mono);font-size:12px;letter-spacing:1.5px;
  color:var(--dim);text-transform:uppercase;}
.acct-card .field{width:100%;min-width:0;}
.acct-note{font-size:14px;color:var(--dim);line-height:1.5;}
.acct-foot{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:auto;}

.refresh-bar{height:2px;background:var(--border);margin-bottom:16px;border-radius:2px;overflow:hidden;}
.refresh-fill{height:100%;background:linear-gradient(90deg,var(--accent2),var(--cyan));animation:refill 10s linear infinite;transform-origin:left;}
@keyframes refill{from{transform:scaleX(1)}to{transform:scaleX(0)}}

.controls{display:flex;gap:12px;margin-bottom:16px;align-items:center;flex-wrap:wrap;}
.btn{padding:9px 18px;border-radius:8px;border:1px solid var(--border);background:var(--panel2);
  color:var(--text);font-family:var(--sans);font-size:16px;font-weight:500;cursor:pointer;transition:all .2s;letter-spacing:1px;}
.btn:hover{border-color:var(--accent);color:var(--accent);}
.btn.primary{background:linear-gradient(135deg,var(--cyan),var(--accent2));color:var(--onaccent);border-color:transparent;font-weight:700;}
.btn.primary:hover{opacity:.88;color:var(--onaccent);}
.btn.save{background:var(--safe);color:#04201a;border-color:var(--safe);font-weight:700;}
.btn.save:hover{opacity:.85;color:#04201a;}
.btn.sm{padding:5px 12px;font-size:15px;}
.btn.danger{color:var(--danger);border-color:color-mix(in srgb,var(--danger) 50%,transparent);}
.btn.danger:hover{background:color-mix(in srgb,var(--danger) 12%,transparent);color:var(--danger);border-color:var(--danger);}
.search,.field{flex:1;min-width:200px;padding:10px 14px;border-radius:8px;border:1px solid var(--inp-border);
  background:var(--inp);color:var(--text);font-family:var(--mono);font-size:16px;outline:none;transition:border-color .2s,background var(--t);}
.search:focus,.field:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--glow);}
.search::placeholder,.field::placeholder{color:var(--dim);}

.table-wrap{overflow-x:auto;}
table{width:100%;border-collapse:collapse;}
th{padding:13px 12px;text-align:left;font-family:var(--mono);font-size:14px;letter-spacing:1px;line-height:1.4;
  color:var(--dim);background:var(--panel2);border-bottom:1px solid var(--border);text-transform:uppercase;}
th:first-child{border-top-left-radius:var(--radius);} th:last-child{border-top-right-radius:var(--radius);}
td{padding:13px 12px;font-size:16px;border-bottom:1px solid color-mix(in srgb,var(--border) 55%,transparent);vertical-align:middle;}
tr:last-child td{border-bottom:none;}
tbody tr:hover td{background:var(--glow);}
tr.new-row td{animation:flashRow .8s ease;}
@keyframes flashRow{from{background:rgba(255,90,118,.22)}to{background:transparent}}
/* Scans: clickable summary row that expands to the networks it saw */
tr.scan-row{cursor:pointer;}
tr.scan-row .caret{display:inline-block;width:14px;color:var(--dim);transition:transform .15s;}
tr.scan-row.open .caret{transform:rotate(90deg);color:var(--accent);}
tr.scan-detail > td{padding:0;background:var(--panel2);}
tr.scan-detail[hidden]{display:none;}
.net-table{width:100%;border-collapse:collapse;}
.net-table th{background:transparent;font-size:12px;padding:9px 12px;}
.net-table td{padding:9px 12px;font-size:14px;border-bottom:1px solid color-mix(in srgb,var(--border) 40%,transparent);}
.net-table tr:hover td{background:transparent;}
.badge.CLEAN{background:color-mix(in srgb,var(--dim) 14%,transparent);color:var(--dim);border:1px solid var(--dim);}
.badge.CLEAR{background:color-mix(in srgb,var(--safe) 10%,transparent);color:var(--safe);border:1px solid color-mix(in srgb,var(--safe) 60%,transparent);}
.badge.BASELINE,.badge.TRUSTED{background:color-mix(in srgb,var(--accent) 12%,transparent);color:var(--accent);border:1px solid color-mix(in srgb,var(--accent) 55%,transparent);}
.pager{display:flex;align-items:center;justify-content:center;gap:16px;margin-top:16px;}
.pager:empty{display:none;}
.pager .pager-ind{font-family:var(--mono);font-size:14px;color:var(--dim);letter-spacing:1px;}
.pager .btn[disabled]{opacity:.4;cursor:not-allowed;}

.badge{display:inline-block;padding:3px 10px;border-radius:4px;font-family:var(--mono);font-size:14px;font-weight:700;letter-spacing:1px;}
.badge.HIGH{background:color-mix(in srgb,var(--danger) 15%,transparent);color:var(--danger);border:1px solid var(--danger);}
.badge.MEDIUM{background:color-mix(in srgb,var(--warning) 15%,transparent);color:var(--warning);border:1px solid var(--warning);}
.badge.LOW{background:color-mix(in srgb,var(--safe) 12%,transparent);color:var(--safe);border:1px solid var(--safe);}
.badge.on{background:color-mix(in srgb,var(--safe) 12%,transparent);color:var(--safe);border:1px solid var(--safe);}
.badge.off{background:color-mix(in srgb,var(--dim) 15%,transparent);color:var(--dim);border:1px solid var(--dim);}
.badge.sim{background:color-mix(in srgb,var(--violet) 14%,transparent);color:var(--violet);border:1px dashed var(--violet);}
.badge.role{background:color-mix(in srgb,var(--violet) 14%,transparent);color:var(--violet);border:1px solid var(--violet);}
.bssid{font-family:var(--mono);font-size:15px;color:var(--accent);}
.hash{font-family:var(--mono);font-size:13px;color:var(--dim);}
.int-ok{color:var(--safe);font-family:var(--mono);font-size:15px;}
.int-fail{color:var(--danger);font-family:var(--mono);font-size:15px;}
.reasons{font-size:15px;color:var(--dim);}
.ts{font-family:var(--mono);font-size:14px;color:var(--dim);}
.empty-state{text-align:center;padding:70px 20px;color:var(--dim);font-family:var(--mono);}
.empty-state .icon{font-size:44px;margin-bottom:14px;}
.empty-state .icon img.check{width:52px;height:52px;display:inline-block;vertical-align:middle;}

/* ── Charts ────────────────────────────── */
.stat-card.recent{--c:var(--warning);}
.stat-card.integrity{--c:var(--safe);} .stat-card.integrity.bad{--c:var(--danger);}
.chart-grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.6fr);gap:14px;margin-top:14px;}
.chart-grid.even{grid-template-columns:minmax(0,1fr) minmax(0,1fr);}
.chart-card{padding:18px 20px;min-width:0;}
.chart-title{font-family:var(--mono);font-size:14px;letter-spacing:2.5px;color:var(--dim);text-transform:uppercase;
  margin-bottom:16px;display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;}
.chart-title b{color:var(--text);font-weight:400;letter-spacing:1px;}
.donut-wrap{display:flex;align-items:center;gap:24px;flex-wrap:wrap;}
.donut{width:180px;height:180px;flex-shrink:0;}
.donut .ring{fill:none;stroke:color-mix(in srgb,var(--border) 55%,transparent);stroke-width:26;}
.donut .seg{fill:none;stroke-width:26;cursor:pointer;filter:drop-shadow(0 0 2.5px currentColor);transition:opacity .15s,filter .15s;}
.donut .seg:hover,.donut .seg:focus{opacity:.9;filter:drop-shadow(0 0 5px currentColor);outline:none;}
.donut-total{font-family:var(--sans);font-size:36px;font-weight:900;fill:var(--text);}
.donut-cap{font-family:var(--mono);font-size:13px;letter-spacing:2px;fill:var(--dim);}
.legend{display:flex;flex-direction:column;gap:12px;flex:1;min-width:160px;}
.lg-row{display:grid;grid-template-columns:12px 1fr auto 44px;gap:10px;align-items:center;font-size:16px;}
.lg-sw{width:12px;height:12px;border-radius:3px;}
.lg-val{font-weight:700;} .lg-pct{font-family:var(--mono);font-size:14px;color:var(--dim);text-align:right;}
.legend.inline{flex-direction:row;flex-wrap:wrap;gap:18px;margin-top:10px;}
.legend.inline .lg-row{display:flex;gap:8px;font-size:15px;color:var(--dim);}
.legend.inline .lg-btn{background:none;border:none;padding:4px 6px;margin:-4px -2px;border-radius:7px;cursor:pointer;
  align-items:center;font:inherit;color:var(--dim);transition:opacity .15s,background .15s;}
.legend.inline .lg-btn:hover{background:var(--glow);}
.legend.inline .lg-btn:focus-visible{outline:2px solid var(--accent);outline-offset:1px;}
.legend.inline .lg-btn.off{opacity:.38;}
.legend.inline .lg-btn[aria-pressed="true"]{color:var(--text);}
.svg-chart{width:100%;height:220px;display:block;overflow:visible;}
.svg-chart .grid{stroke:color-mix(in srgb,var(--border) 70%,transparent);stroke-width:1;}
.svg-chart .vgrid{stroke:color-mix(in srgb,var(--border) 50%,transparent);stroke-width:1;filter:blur(.6px);}
.svg-chart .base{stroke:var(--border);stroke-width:1;}
.svg-chart .axis{font-family:var(--mono);font-size:13px;fill:var(--dim);}
.svg-chart .trend-line{fill:none;stroke-width:2.5;stroke-linecap:round;stroke-linejoin:round;
  filter:drop-shadow(0 1px 3px color-mix(in srgb,currentColor 40%,transparent));}
.svg-chart .trend-area{opacity:.12;stroke:none;}
.svg-chart .trend-dot{stroke:var(--panel);stroke-width:1.5;}
.svg-chart .hit{fill:transparent;cursor:pointer;outline:none;}
.svg-chart .hit:hover,.svg-chart .hit:focus{fill:var(--glow);}
.hbars{display:flex;flex-direction:column;gap:13px;}
.hb-row{display:grid;grid-template-columns:minmax(90px,40%) minmax(0,1fr) 36px;gap:12px;align-items:center;font-size:16px;}
.hb-label{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.hb-track{height:10px;background:color-mix(in srgb,var(--border) 45%,transparent);border-radius:5px;overflow:hidden;}
.hb-fill{height:100%;border-radius:5px;background:var(--accent);transition:width .4s ease;}
.hb-val{font-family:var(--mono);text-align:right;}
.chart-empty{font-family:var(--mono);font-size:15px;color:var(--dim);padding:36px 0;text-align:center;}
.modal-overlay{position:fixed;inset:0;z-index:600;display:flex;align-items:center;justify-content:center;padding:20px;
  background:rgba(4,10,22,.62);backdrop-filter:blur(3px);}
.modal-overlay[hidden]{display:none;}
.modal{width:100%;max-width:420px;background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);
  padding:22px 24px;box-shadow:0 20px 60px -15px rgba(0,0,0,.7);animation:modalIn .15s ease;}
@keyframes modalIn{from{opacity:0;transform:translateY(8px) scale(.98);}to{opacity:1;transform:none;}}
.modal-title{font-size:18px;font-weight:700;color:var(--danger);margin-bottom:12px;}
.modal-body{font-size:15px;color:var(--text);line-height:1.55;margin-bottom:20px;}
.modal-body b{color:var(--text);}
.modal-actions{display:flex;justify-content:flex-end;gap:10px;}
.tip{position:fixed;pointer-events:none;z-index:500;background:var(--panel2);border:1px solid var(--border);
  border-radius:6px;padding:9px 12px;min-width:120px;box-shadow:0 10px 30px rgba(0,0,0,.35);}
.tip-title{font-family:var(--mono);font-size:13px;letter-spacing:1.5px;color:var(--dim);margin-bottom:6px;}
.tip-row{display:flex;align-items:center;gap:8px;font-size:15px;color:var(--dim);margin-top:3px;}
.tip-row b{color:var(--text);font-size:17px;min-width:22px;}
.tip-key{width:10px;height:2px;border-radius:1px;}
.user-tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;}
.utab{display:inline-flex;align-items:center;gap:8px;padding:8px 14px;border-radius:8px;border:1px solid var(--border);
  background:var(--panel);color:var(--dim);font-family:var(--sans);font-size:16px;font-weight:500;cursor:pointer;transition:all .2s;}
.utab:hover{color:var(--text);border-color:var(--accent);}
.utab.active{color:var(--accent);border-color:var(--accent);background:var(--glow);box-shadow:inset 0 -2px 0 var(--accent);}
.utab .tab-ava{flex:none;display:inline-block;width:17px;height:17px;background:currentColor;
  -webkit-mask:url(/static/user.png) center/contain no-repeat;mask:url(/static/user.png) center/contain no-repeat;}
.utab.off .uname-t{text-decoration:line-through;opacity:.7;}
.utab .cnt{font-family:var(--mono);font-size:14px;padding:1px 7px;border-radius:10px;
  background:color-mix(in srgb,var(--danger) 15%,transparent);color:var(--danger);}
.utab .cnt.zero{background:color-mix(in srgb,var(--dim) 15%,transparent);color:var(--dim);}
.log-owner{font-family:var(--mono);font-size:15px;color:var(--dim);margin-bottom:10px;}
.log-owner b{color:var(--text);font-weight:400;}
@media (max-width:1000px){.chart-grid,.chart-grid.even{grid-template-columns:minmax(0,1fr);}}

/* ── Users ─────────────────────────────── */
.user-form{padding:20px 24px;display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;align-items:end;
  border-bottom:1px solid var(--border);}
.user-form label{display:flex;flex-direction:column;gap:6px;font-family:var(--mono);font-size:13px;letter-spacing:2px;
  color:var(--dim);text-transform:uppercase;}
.user-form .field{min-width:0;width:100%;}
.form-actions{display:flex;align-items:center;gap:12px;flex-wrap:wrap;}
.uname{font-weight:700;} .umeta{font-size:15px;color:var(--dim);}
.user-cell{display:flex;align-items:center;gap:12px;}
.user-ava{flex:none;display:inline-block;width:34px;height:34px;color:var(--accent);background:currentColor;
  -webkit-mask:url(/static/user.png) center/contain no-repeat;mask:url(/static/user.png) center/contain no-repeat;}
tr.disabled .user-ava{color:var(--dim);}
tr.disabled td{opacity:.6;} tr.disabled td:nth-child(4),tr.disabled td:last-child{opacity:1;}
.row-actions{white-space:nowrap;} .row-actions .btn+.btn{margin-left:6px;}
.btn.icon-btn{padding:5px 9px;font-size:15px;line-height:1;}
.btn.trash-btn{display:inline-flex;align-items:center;justify-content:center;border-color:color-mix(in srgb,var(--danger) 45%,transparent);}
.btn.trash-btn:hover{border-color:var(--danger);background:color-mix(in srgb,var(--danger) 12%,transparent);}
.btn.trash-btn img{width:16px;height:16px;display:block;}
.status-cell{display:flex;align-items:center;gap:10px;}
.tswitch{position:relative;flex:none;width:52px;height:30px;padding:0;border-radius:15px;border:1px solid var(--inp-border);
  background:var(--inp);cursor:pointer;transition:background .25s,border-color .25s;}
.tswitch::before{content:'';position:absolute;top:50%;right:9px;width:8px;height:8px;margin-top:-6px;
  border:2px solid var(--dim);border-radius:50%;transition:opacity .2s;}
.tswitch::after{content:'';position:absolute;top:50%;left:12px;width:2px;height:11px;margin-top:-5.5px;
  background:#fff;border-radius:1px;opacity:0;transition:opacity .2s;}
.tswitch .knob{position:absolute;top:2px;left:2px;width:24px;height:24px;border-radius:50%;background:#fff;
  border:1px solid rgba(0,0,0,.12);box-shadow:0 1px 3px rgba(0,0,0,.35);transition:transform .25s;z-index:1;}
.tswitch[aria-checked="true"]{background:var(--safe);border-color:color-mix(in srgb,var(--safe) 65%,#000);}
.tswitch[aria-checked="true"]::before{opacity:0;}
.tswitch[aria-checked="true"]::after{opacity:1;}
.tswitch[aria-checked="true"] .knob{transform:translateX(22px);}
.tswitch:focus-visible{outline:none;box-shadow:0 0 0 3px var(--glow);}
.tswitch:disabled{cursor:wait;opacity:.6;}
.tswitch-lbl{font-family:var(--mono);font-size:14px;font-weight:700;letter-spacing:1px;color:var(--dim);}
.tswitch-lbl.on{color:var(--safe);}
.user-err{font-family:var(--mono);font-size:15px;color:var(--danger);padding:12px 24px;border-bottom:1px solid var(--border);}
.user-err:empty{display:none;}

footer{text-align:center;padding:22px;font-family:var(--mono);font-size:14px;color:var(--dim);
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
      <div class="logo-sub">ROGUE AP DEFENSE</div>
    </div>
  </div>
  <nav class="nav" id="nav">
    <div class="nav-title" aria-hidden="true">&nbsp;</div>
    <a href="#overview" class="active"><span class="ico">◈</span>Overview</a>
    <a href="#threats"><span class="ico">⚠</span>Threat Log</a>
    <a href="#scans"><span class="ico img ico-radar"></span>Scans</a>
    <a href="#users"><span class="ico img ico-users"></span>User Management</a>
    <a href="#settings"><span class="ico">⚙</span>Settings</a>
  </nav>
  <div class="side-foot">
    <button class="theme-toggle" id="theme-btn" type="button" role="switch" aria-checked="true" aria-label="Switch to light mode" title="Dark mode — click for light"><span class="knob"><svg class="ic-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4" fill="currentColor" stroke="none"></circle><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M19.1 4.9l-1.4 1.4M6.3 17.7l-1.4 1.4"></path></svg><svg class="ic-moon" viewBox="0 0 24 24" fill="currentColor"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"></path></svg></span></button>
    <div class="sys-line">SIGNED IN: <span id="signed-in-email">{{ admin }}</span><br>ROLE: SUPER ADMIN</div>
    <form method="post" action="/logout"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="btn sm danger logout" type="submit">⏻ Log Out</button></form>
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
      <div class="stat-card total"><div class="stat-label">Total Detections</div><div class="stat-value" id="stat-total">0</div><div class="stat-sub">all severities, all users</div></div>
      <div class="stat-card recent"><div class="stat-label">Alerts (24h)</div><div class="stat-value" id="stat-24h">0</div><div class="stat-sub">last 24 hours</div></div>
      <div class="stat-card integrity" id="card-integrity" title="Share of forensic log entries whose SHA-256 hash still matches their contents. Below 100% means an entry was edited after it was recorded."><div class="stat-label">Log Integrity</div><div class="stat-value" id="stat-integrity">—</div><div class="stat-sub" id="stat-integrity-sub">no entries</div></div>
      <div class="stat-card high"><div class="stat-label">Alerts</div><div class="stat-value" id="stat-high">0</div><div class="stat-sub">HIGH + MEDIUM · all users</div></div>
      <div class="stat-card users"><div class="stat-label">Total Users</div><div class="stat-value" id="stat-users">0</div><div class="stat-sub">registered operators</div></div>
      <div class="stat-card active"><div class="stat-label">Active Users</div><div class="stat-value" id="stat-active">0</div><div class="stat-sub">accounts enabled</div></div>
    </div>

    <div class="chart-grid">
      <div class="panel chart-card">
        <div class="chart-title">Severity Distribution <b>all detections</b></div>
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
        <div class="chart-title">Detection Reasons <b>alerts per rule</b></div>
        <div class="hbars" id="reason-bars"></div>
      </div>
      <div class="panel chart-card">
        <div class="chart-title">Most Targeted SSIDs <b>alerts · top 6</b></div>
        <div class="hbars" id="ssid-bars"></div>
      </div>
    </div>
  </section>

  <section id="threats">
    <div class="sec-head"><div class="sec-title">Threat Log</div><div class="sec-note">HIGH + MEDIUM severity · one log per user · SHA-256 sealed</div></div>
    <div class="refresh-bar"><div class="refresh-fill" id="rfill"></div></div>
    <div class="controls">
      <button class="btn primary" id="btn-refresh" type="button">↻ Refresh</button>
      <input class="search" id="search" type="text" placeholder="Filter by SSID or BSSID...">
      <button class="btn" id="btn-export" type="button">⬇ Export JSON</button>
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

  <section id="scans">
    <div class="sec-head"><div class="sec-title">Scans</div><div class="sec-note">every sealed sweep · newest first · click a row for the networks seen</div></div>
    <div class="controls">
      <button class="btn primary" id="btn-refresh-scans" type="button">↻ Refresh</button>
      <input class="search" id="scan-search" type="text" placeholder="Filter by operator...">
      <span class="sec-note" id="scan-count"></span>
    </div>
    <div class="panel table-wrap">
      <table>
        <thead><tr>
          <th>Timestamp (GMT+8)</th><th>Operator</th><th>Networks</th><th>Threats</th>
          <th>Highest Finding</th><th>Clock</th><th>SHA-256 Integrity</th>
        </tr></thead>
        <tbody id="scan-body">
          <tr><td colspan="7" class="empty-state"><div class="icon">📡</div>Loading scans...</td></tr>
        </tbody>
      </table>
    </div>
    <div class="pager" id="scan-pager"></div>
  </section>

  <section id="users">
    <div class="sec-head"><div class="sec-title">User Management</div><div class="sec-note">operator accounts for the TwinGuard app</div></div>
    <div class="panel">
      <form class="user-form" id="user-form">
        <label>Username<input class="field" id="u-username" required minlength="3" maxlength="32" placeholder="operator01"></label>
        <label>Full Name<input class="field" id="u-fullname" maxlength="80" placeholder="Ali Ahmad"></label>
        <label>Email (app sign-in)<input class="field" id="u-email" type="email" required maxlength="120" placeholder="ali@example.com"></label>
        <label>Password<input class="field" id="u-password" type="password" required minlength="8" autocomplete="new-password" placeholder="min. 8 characters"></label>
        <div class="form-actions">
          <button class="btn primary" type="submit">＋ Add User</button>
          <span class="form-status" id="user-status"></span>
        </div>
      </form>
      <div class="user-err" id="user-err" role="alert"></div>
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
      <div class="ret-label">Log Retention</div>
      <div class="ret-desc">Logs older than this are automatically deleted every hour.</div>
      <div class="ret-wrap">
        <input class="ret-input" type="number" id="retention-days" min="1" max="3650" value="30">
        <span class="ret-unit">days</span>
        <button class="btn save" id="btn-save-retention" type="button">Save</button>
        <span class="ret-status" id="ret-status"></span>
      </div>
    </div>
    <div class="panel retention-panel">
      <div class="ret-label">Scan Retention</div>
      <div class="ret-desc">Scan sweeps older than this are automatically deleted every hour.</div>
      <div class="ret-wrap">
        <input class="ret-input" type="number" id="scan-retention-days" min="1" max="3650" value="30">
        <span class="ret-unit">days</span>
        <button class="btn save" id="btn-save-scan-retention" type="button">Save</button>
        <span class="ret-status" id="scan-ret-status"></span>
      </div>
    </div>
    <div class="panel retention-panel">
      <div class="ret-label">Auto Refresh</div>
      <div class="ret-desc">How often the dashboard pulls new data. Saved on this device.</div>
      <div class="ret-wrap">
        <select class="ret-select" id="refresh-interval" aria-label="Auto refresh interval">
          <option value="0">Off</option>
          <option value="5">Every 5s</option>
          <option value="10">Every 10s</option>
          <option value="30">Every 30s</option>
          <option value="60">Every 60s</option>
        </select>
      </div>
    </div>
    <div class="panel retention-panel">
      <div class="ret-label">Font Size</div>
      <div class="ret-desc">Adjust the dashboard text size. Saved on this device.</div>
      <div class="fs-wrap">
        <span class="fs-a fs-a-sm" data-fs="0" aria-hidden="true">A</span>
        <div class="fs-track">
          <div class="fs-line" aria-hidden="true"></div>
          <div class="fs-ticks" aria-hidden="true">
            <div class="fs-tick"></div><div class="fs-tick"></div><div class="fs-tick"></div><div class="fs-tick"></div><div class="fs-tick"></div><div class="fs-tick"></div><div class="fs-tick"></div>
          </div>
          <input class="fs-slider" type="range" id="font-scale" min="0" max="6" step="1" value="3"
            aria-label="Font size" aria-valuetext="100%">
        </div>
        <span class="fs-a fs-a-lg" data-fs="6" aria-hidden="true">A</span>
        <button class="fs-reset" type="button" id="font-reset" title="Reset to default size" aria-label="Reset font size to default"><span class="fs-reset-ic" aria-hidden="true"></span></button>
      </div>
    </div>
    <div class="panel retention-panel">
      <div class="ret-label">Scans Per Page</div>
      <div class="ret-desc">Rows shown per page in the Scans table. Saved on this device.</div>
      <div class="ret-wrap">
        <select class="ret-select" id="scan-pp" aria-label="Scans per page">
          <option value="10">10</option>
          <option value="12">12</option>
          <option value="25">25</option>
          <option value="50">50</option>
        </select>
      </div>
    </div>
    <div class="panel retention-panel">
      <div class="ret-label">Export Data</div>
      <div class="ret-desc">Download the forensic log or the scan sweeps.</div>
      <div class="ret-wrap export-wrap">
        <button class="btn" id="exp-log-json" type="button">⬇ Log JSON</button>
        <button class="btn" id="exp-log-csv" type="button">⬇ Log CSV</button>
        <button class="btn" id="exp-scan-json" type="button">⬇ Scans JSON</button>
        <button class="btn" id="exp-scan-csv" type="button">⬇ Scans CSV</button>
      </div>
    </div>
    <div class="panel acct-panel">
      <div class="ret-label">Admin Account</div>
      <div class="acct-grid">
        <form class="acct-card" id="email-form">
          <div class="acct-title">Change Email</div>
          <label>New email<input class="field" id="acc-email" type="email" maxlength="120" value="{{ admin }}" autocomplete="username"></label>
          <label>Current password<input class="field" id="acc-email-pw" type="password" autocomplete="current-password" placeholder="Confirm it's you"></label>
          <div class="acct-foot"><button class="btn primary" type="submit">Update Email</button><span class="form-status" id="acc-email-status"></span></div>
        </form>
        <form class="acct-card" id="password-form">
          <div class="acct-title">Change Password</div>
          <label>New password<input class="field" id="acc-newpw" type="password" minlength="8" autocomplete="new-password" placeholder="min. 8 characters"></label>
          <label>Current password<input class="field" id="acc-pw-cur" type="password" autocomplete="current-password" placeholder="Confirm it's you"></label>
          <div class="acct-foot"><button class="btn primary" type="submit">Update Password</button><span class="form-status" id="acc-pw-status"></span></div>
        </form>
        <form class="acct-card" id="tfa-form">
          <div class="acct-title">Two-Factor Auth</div>
          <div class="acct-note">Re-enroll your authenticator app with a fresh secret. You'll be taken to the QR setup page.</div>
          <label>Current password<input class="field" id="acc-2fa-pw" type="password" autocomplete="current-password" placeholder="Confirm it's you"></label>
          <div class="acct-foot"><button class="btn" type="submit">Reset 2FA</button><span class="form-status" id="acc-2fa-status"></span></div>
        </form>
      </div>
    </div>
  </section>
</main>

<div class="tip" id="tip" hidden></div>

<div class="modal-overlay" id="confirm-modal" hidden>
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="cm-title" aria-describedby="cm-body">
    <div class="modal-title" id="cm-title">⚠ Delete user</div>
    <div class="modal-body" id="cm-body"></div>
    <div class="modal-actions">
      <button class="btn" type="button" id="cm-cancel">Cancel</button>
      <button class="btn danger" type="button" id="cm-confirm">Delete</button>
    </div>
  </div>
</div>

<footer>TwinGuard-SHA256 &nbsp;|&nbsp; GMI Final Year Project JAN 2026 &nbsp;|&nbsp; SEM 4 DCBS 6</footer>
</div>

<script nonce="{{ csp_nonce }}">
let allLogs = [], allUsers = [], activeTab = null, prevCounts = {}, allScans = [], trendLogs = [];

// ── Session guard + CSRF: writes carry the page's token; 401 = session ended ──
const CSRF   = document.querySelector('meta[name="csrf-token"]').content;
const _fetch = window.fetch.bind(window);
window.fetch = async (url, opts = {}) => {
  const headers = new Headers(opts.headers || {});
  if ((opts.method || 'GET').toUpperCase() !== 'GET') headers.set('X-CSRF-Token', CSRF);
  const r = await _fetch(url, {...opts, headers, credentials: 'same-origin'});
  if (r.status === 401) location.href = '/login';
  return r;
};

// ── Theme ──────────────────────────────────────
function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  localStorage.setItem('tg-theme', t);
  const b = document.getElementById('theme-btn');
  b.setAttribute('aria-checked', t === 'dark');
  b.setAttribute('aria-label', t === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
  b.title = t === 'dark' ? 'Dark mode — click for light' : 'Light mode — click for dark';
}
function toggleTheme() {
  applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
}
applyTheme(localStorage.getItem('tg-theme') || 'dark');

// ── Font size (per-device): 7 steps, default 100%. Applied on release so the ──
//    page doesn't reflow out from under the slider while you drag it. ──────────
const FONT_SCALES  = [0.7, 0.8, 0.9, 1.0, 1.1, 1.2, 1.3];
const FONT_DEFAULT = 3;            // index of 1.0 — the middle of the 7 steps
const FONT_KEY     = 'tg-fontscale3';
const clampFs = i => { i = Math.round(Number(i)); return i >= 0 ? Math.min(FONT_SCALES.length - 1, i) : FONT_DEFAULT; };
function applyFontScale(idx, persist) {
  idx = clampFs(idx);
  document.documentElement.style.zoom = FONT_SCALES[idx];
  const slider = document.getElementById('font-scale');
  if (slider) { slider.value = idx; slider.setAttribute('aria-valuetext', Math.round(FONT_SCALES[idx] * 100) + '%'); }
  if (persist) { try { localStorage.setItem(FONT_KEY, idx); } catch(e) {} }
}
let savedScale = FONT_DEFAULT;
try { const v = localStorage.getItem(FONT_KEY); if (v !== null && v !== '') savedScale = Number(v); } catch(e) {}
applyFontScale(savedScale, false);

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
    const d = await (await fetch('/api/retention')).json();
    document.getElementById('retention-days').value = d.retention_days || 30;
    const s = document.getElementById('scan-retention-days');
    if (s) s.value = d.scan_retention_days || 30;
  } catch(e) {}
}
async function saveRetentionField(inputId, key, statusId) {
  const days = parseInt(document.getElementById(inputId).value);
  const s = document.getElementById(statusId);
  if (isNaN(days) || days < 1) { s.textContent='✗ Invalid'; s.className='ret-status err'; return; }
  try {
    const r = await fetch('/api/retention', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({[key]: days})
    });
    const d = await r.json();
    if (d.status === 'ok') {
      s.textContent = `✓ Saved (${days} days)`; s.className = 'ret-status ok';
      setTimeout(() => { s.textContent = ''; }, 3000);
    } else { s.textContent = '✗ ' + (d.error || 'Failed'); s.className = 'ret-status err'; }
  } catch(e) { s.textContent='✗ Failed'; s.className='ret-status err'; }
}

// ── Data ───────────────────────────────────────
async function loadData(background = false) {
  const opts = background ? {headers: {'X-Background': '1'}} : {};
  try {
    const [sr, lr, lowr] = await Promise.all([
      fetch('/api/stats', opts), fetch('/api/logs', opts), fetch('/api/logs/low', opts)]);
    const stats = await sr.json();
    allLogs     = await lr.json();
    // LOW detections are fetched only for the trend graph; the Threat Log,
    // stats and reason/SSID bars stay HIGH+MEDIUM.
    const low   = await lowr.json().catch(() => []);
    trendLogs   = allLogs.concat(Array.isArray(low) ? low : []);
    document.getElementById('stat-total').textContent  = stats.total_alerts;
    document.getElementById('stat-high').textContent   = stats.high + stats.medium;
    document.getElementById('stat-users').textContent  = stats.total_users;
    document.getElementById('stat-active').textContent = stats.active_users;
    renderThreatLog();
    renderCharts(allLogs, stats);
  } catch(e) {
    document.getElementById('log-body').innerHTML =
      '<tr><td colspan="8" class="empty-state"><div class="icon">⚠️</div>Backend not reachable.</td></tr>';
  }
}

function renderTable(logs, highlight=false, emptyMsg='No alerts.') {
  const tbody = document.getElementById('log-body');
  if (!logs.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty-state"><div class="icon"><img class="check" src="/static/check.webp" alt=""></div>${esc(emptyMsg)}</td></tr>`;
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
      <td><span class="badge ${sev}">${sev}</span>${l.simulated === true ? ' <span class="badge sim" title="Simulated alert (test only, not real evidence)">SIM</span>' : ''}</td>
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
  allLogs.filter(l => ['HIGH','MEDIUM'].includes(l.severity)).forEach(l => (groups[ownerKey(l)] ||= []).push(l));

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
    btn.append(htmlEl('span', 'tab-ava'), htmlEl('span', 'uname-t', t.label), htmlEl('span', 'cnt' + (n ? '' : ' zero'), n));
    btn.addEventListener('click', () => { activeTab = t.key; renderThreatLog(); });
    return btn;
  }));

  const current = tabs.find(t => t.key === activeTab);
  const mine    = groups[activeTab] || [];
  owner.replaceChildren(document.createTextNode('Viewing log of '), htmlEl('b', '', current.label),
    document.createTextNode(` · ${mine.length} alert${mine.length === 1 ? '' : 's'}` +
      (current.enabled ? '' : ' · account disabled')));

  const q = document.getElementById('search').value.toLowerCase();
  const rows = mine.filter(l => String(l.ssid || '').toLowerCase().includes(q) || String(l.bssid || '').toLowerCase().includes(q));
  const highlight = prevCounts[activeTab] !== undefined && mine.length > prevCounts[activeTab];
  prevCounts = Object.fromEntries(tabs.map(t => [t.key, (groups[t.key] || []).length]));
  renderTable(rows.slice().reverse(), highlight,
    q ? 'No matching alerts.' : `No alerts for ${current.label}.`);
}

function filterTable() { renderThreatLog(); }

function openUserLog(key) {
  activeTab = key;
  renderThreatLog();
  document.getElementById('threats').scrollIntoView();
}

function download(name, text, type) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], {type}));
  a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
function toCSV(rows, cols) {
  const cell = v => { v = (v === null || v === undefined) ? '' : String(v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
  return [cols.map(c => cell(c.label)).join(',')]
    .concat(rows.map(r => cols.map(c => cell(c.get(r))).join(','))).join('\n');
}
function exportLogs() { download('twinguard_forensic_log.json', JSON.stringify(allLogs, null, 2), 'application/json'); }
function exportLogsCSV() {
  const cols = [
    {label:'timestamp', get:r=>r.timestamp}, {label:'severity', get:r=>r.severity},
    {label:'ssid', get:r=>r.ssid}, {label:'bssid', get:r=>r.bssid},
    {label:'signal_dbm', get:r=>r.signal_dbm}, {label:'encryption', get:r=>r.encryption},
    {label:'reasons', get:r=>Array.isArray(r.reasons)?r.reasons.join(' | '):''},
    {label:'integrity_ok', get:r=>r.integrity_ok}, {label:'sha256_hash', get:r=>r.sha256_hash},
  ];
  download('twinguard_forensic_log.csv', toCSV(allLogs, cols), 'text/csv');
}
async function scansForExport() {
  if (allScans.length) return allScans;
  try { return await (await fetch('/api/scans')).json(); } catch(e) { return []; }
}
async function exportScansJSON() { download('twinguard_scans.json', JSON.stringify(await scansForExport(), null, 2), 'application/json'); }
async function exportScansCSV() {
  const cols = [
    {label:'timestamp', get:r=>r.timestamp}, {label:'operator', get:r=>r.username},
    {label:'networks_scanned', get:r=>Array.isArray(r.networks)?r.networks.length:r.scanned},
    {label:'threats', get:r=>r.threats}, {label:'highest_finding', get:r=>scanFinding(r)},
    {label:'clock_source', get:r=>r.clock_source}, {label:'integrity_ok', get:r=>r.integrity_ok},
    {label:'sha256_hash', get:r=>r.sha256_hash},
  ];
  download('twinguard_scans.csv', toCSV(await scansForExport(), cols), 'text/csv');
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

function renderDonut(stats) {
  const svg = document.getElementById('sev-donut'), legend = document.getElementById('sev-legend');
  const counts = SEV.map(s => Number(stats[s.key.toLowerCase()]) || 0);   // all detections, not just the listed alerts
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
      seg.style.color  = s.color;   // drives the drop-shadow glow (see .donut .seg)
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

// Smooth line through points via a Catmull-Rom spline converted to cubic
// beziers. tension < 1 tames overshoot; a clip-path keeps curves in the plot.
function smoothPath(pts, tension = 0.8) {
  if (!pts.length) return '';
  if (pts.length === 1) return `M${pts[0].x},${pts[0].y}`;
  const t = tension / 6;
  let d = `M${pts[0].x},${pts[0].y}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || pts[i + 1];
    const c1x = p1.x + (p2.x - p0.x) * t, c1y = p1.y + (p2.y - p0.y) * t;
    const c2x = p2.x - (p3.x - p1.x) * t, c2y = p2.y - (p3.y - p1.y) * t;
    d += ` C${c1x.toFixed(2)},${c1y.toFixed(2)} ${c2x.toFixed(2)},${c2y.toFixed(2)} ${p2.x.toFixed(2)},${p2.y.toFixed(2)}`;
  }
  return d;
}

// null = show all three lines; a severity key = show only that one ("solo").
let trendFilter = null;

function renderTrend(logs) {
  const svg = document.getElementById('trend-chart');
  const W = Math.max(svg.clientWidth, 280), H = 220, pad = {l:32, r:8, t:12, b:24};
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  svg.replaceChildren();

  const today = new Date(toKL(new Date().toISOString())), days = [];
  for (let i = 13; i >= 0; i--)
    days.push(new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate() - i)).toISOString().slice(0, 10));
  const buckets = Object.fromEntries(days.map(d => [d, {HIGH:0, MEDIUM:0, LOW:0}]));
  logs.forEach(l => { const d = (toKL(l.timestamp) || '').slice(0, 10); if (buckets[d]) buckets[d][sevOf(l)]++; });
  const totals = days.map(d => SEV.reduce((a, s) => a + buckets[d][s.key], 0));
  document.getElementById('trend-sum').textContent = `${totals.reduce((a, b) => a + b, 0)} total`;

  const shown = SEV.filter(s => !trendFilter || s.key === trendFilter);
  // Y axis = number of alerts that day. Scale to the tallest single-day value
  // among the shown severities, rounded up to a tidy integer step (1/2/5/10...)
  // so every gridline label is a whole, sensible number.
  const peak = Math.max(1, ...days.flatMap(d => shown.map(s => buckets[d][s.key])));
  const niceStep = [1, 2, 5, 10, 20, 25, 50, 100].find(s => s >= peak / 4) || Math.ceil(peak / 400) * 100;
  const top = Math.ceil(peak / niceStep) * niceStep;
  const pw = W - pad.l - pad.r, ph = H - pad.t - pad.b, base = pad.t + ph;
  const xOf = i => pad.l + (days.length === 1 ? pw / 2 : i * pw / (days.length - 1));
  const yOf = v => base - v / top * ph;

  // Soft vertical guide for each day (the "blurred" day separators).
  days.forEach((d, i) => svg.append(svgEl('line',
    {x1:xOf(i), x2:xOf(i), y1:pad.t, y2:base, class:'vgrid'})));

  // Horizontal gridlines at whole-number alert counts.
  for (let v = 0; v <= top + 1e-9; v += niceStep) {
    const y = yOf(v);
    svg.append(svgEl('line', {x1:pad.l, x2:W - pad.r, y1:y, y2:y, class: v ? 'grid' : 'base'}));
    const lbl = svgEl('text', {x:pad.l - 8, y:y + 4, 'text-anchor':'end', class:'axis'}); lbl.textContent = v;
    svg.append(lbl);
  }

  // Clip so smoothed curves never bleed past the plot area.
  const clipId = 'trend-clip';
  const defs = svgEl('defs'), clip = svgEl('clipPath', {id:clipId});
  clip.append(svgEl('rect', {x:pad.l, y:pad.t - 4, width:pw, height:ph + 8}));
  defs.append(clip);
  svg.append(defs);
  const plot = svgEl('g', {'clip-path': `url(#${clipId})`});
  svg.append(plot);

  // One smooth line + faint area per shown severity. Draw back-to-front so
  // HIGH (first in SEV) ends up on top.
  shown.slice().reverse().forEach(s => {
    const pts = days.map((d, i) => ({x: xOf(i), y: yOf(buckets[d][s.key]), v: buckets[d][s.key]}));
    const line = smoothPath(pts);
    const area = svgEl('path', {d: `${line} L${xOf(days.length - 1).toFixed(2)},${base} L${xOf(0).toFixed(2)},${base} Z`, class:'trend-area'});
    area.style.fill = s.color;
    const stroke = svgEl('path', {d: line, class:'trend-line'});
    stroke.style.stroke = s.color;
    stroke.style.color  = s.color;   // drives the drop-shadow glow
    plot.append(area, stroke);
    pts.forEach(p => { if (p.v) { const dot = svgEl('circle', {cx:p.x, cy:p.y, r:2.6, class:'trend-dot'}); dot.style.fill = s.color; plot.append(dot); } });
  });

  const step = pw / (days.length - 1), labelEvery = step < 34 ? 3 : 2;
  days.forEach((d, i) => {
    if ((days.length - 1 - i) % labelEvery === 0) {
      const lbl = svgEl('text', {x:xOf(i), y:H - 6, 'text-anchor':'middle', class:'axis'});
      lbl.textContent = d.slice(5);
      svg.append(lbl);
    }
    // Whole-column hit target: tooltip lists the currently-shown severities.
    const shownTot = shown.reduce((a, s) => a + buckets[d][s.key], 0);
    const hit = svgEl('rect', {x:pad.l + i * step - step / 2, y:pad.t, width:step, height:ph, class:'hit', 'aria-label': `${d}: ${shownTot} alerts`});
    bindTip(hit, `${d} · ${shownTot} alert${shownTot === 1 ? '' : 's'}`,
      shown.map(s => ({color:s.color, value:buckets[d][s.key], label:s.label})));
    svg.append(hit);
  });

  // Clickable legend: press a severity to show it alone; press it again for all.
  const legend = document.getElementById('trend-legend');
  legend.replaceChildren(...SEV.map(s => {
    const row = htmlEl('button', 'lg-row lg-btn' + (trendFilter && trendFilter !== s.key ? ' off' : ''));
    row.type = 'button';
    row.setAttribute('aria-pressed', trendFilter === s.key ? 'true' : 'false');
    const sw = htmlEl('span', 'lg-sw'); sw.style.background = s.color;
    row.append(sw, document.createTextNode(s.label));
    row.addEventListener('click', () => {
      trendFilter = trendFilter === s.key ? null : s.key;
      hideTip();
      renderTrend(trendLogs);
    });
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

function renderCharts(logs, stats) {
  hideTip();
  renderStats(logs);
  renderDonut(stats);
  renderTrend(trendLogs.length ? trendLogs : logs);

  const reasons = Object.fromEntries(KNOWN_REASONS.map(r => [r, 0]));
  logs.forEach(l => (Array.isArray(l.reasons) ? l.reasons : []).forEach(r => { r = String(r); reasons[r] = (reasons[r] || 0) + 1; }));
  renderHBars('reason-bars', Object.entries(reasons).sort((a, b) => b[1] - a[1]), 'No detections yet');

  const ssids = {};
  logs.forEach(l => { const k = String(l.ssid || '?'); ssids[k] = (ssids[k] || 0) + 1; });
  renderHBars('ssid-bars', Object.entries(ssids).sort((a, b) => b[1] - a[1]).slice(0, 6), 'No targeted SSIDs yet');
}

let resizeTimer;
window.addEventListener('resize', () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => renderTrend(trendLogs), 150); });

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
      <td><div class="user-cell"><span class="user-ava"></span><div><div class="uname">${esc(u.username)}</div><div class="umeta">${esc(u.full_name) || '—'}</div></div></div></td>
      <td class="umeta">${esc(u.email) || '—'}</td>
      <td><span class="badge role">${esc(u.role).toUpperCase()}</span></td>
      <td><div class="status-cell">
        <button class="tswitch" type="button" role="switch" aria-checked="${u.enabled}" data-action="toggle"
          data-id="${esc(u.id)}" aria-label="${u.enabled ? 'Disable' : 'Enable'} ${esc(u.username)}"
          title="${u.enabled ? 'On: click to disable' : 'Off: click to enable'}"><span class="knob"></span></button>
        <span class="tswitch-lbl ${u.enabled ? 'on' : ''}">${u.enabled ? 'ON' : 'OFF'}</span></div></td>
      <td class="ts">${fmtTs(u.created_at)}</td>
      <td class="ts">${fmtTs(u.last_login)}</td>
      <td class="row-actions">
        <button class="btn sm" type="button" data-action="log" data-id="${esc(u.id)}">📄 View Log</button>
        <button class="btn sm icon-btn trash-btn" type="button" data-action="delete" data-id="${esc(u.id)}" data-name="${esc(u.username)}" title="Delete user" aria-label="Delete ${esc(u.username)}"><img src="/static/trash.png" alt=""></button></td>
    </tr>`).join('');
  } catch(e) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state"><div class="icon">⚠️</div>Backend not reachable.</td></tr>';
  }
}

// ── Scans ──────────────────────────────────────
const sevRank = s => ({HIGH:3, MEDIUM:2, LOW:1}[s] || 0);

// Highest finding in a sweep: a raised alert's level (HIGH/MEDIUM), else LOW if
// anything scored below the alert threshold, else CLEAN.
function scanFinding(scan) {
  const nets = Array.isArray(scan.networks) ? scan.networks : [];
  let worstLvl = null, worstScore = 0;
  nets.forEach(n => {
    if (n.threat_level && sevRank(n.threat_level) > sevRank(worstLvl)) worstLvl = n.threat_level;
    if (typeof n.score === 'number' && n.score > worstScore) worstScore = n.score;
  });
  return worstLvl || (worstScore >= 1 ? 'LOW' : 'CLEAN');
}

let scanPage = 0;
const SCANPP_KEY = 'tg-scanpp';
let scansPerPage = 12;
try { const v = localStorage.getItem(SCANPP_KEY); if (v) scansPerPage = Number(v) || 12; } catch(e) {}

function renderScanPager(pages) {
  const pager = document.getElementById('scan-pager');
  pager.replaceChildren();
  if (pages <= 1) return;
  const prev = htmlEl('button', 'btn sm', '‹ Prev'); prev.type = 'button'; prev.disabled = scanPage === 0;
  prev.addEventListener('click', () => { scanPage--; renderScans(); });
  const next = htmlEl('button', 'btn sm', 'Next ›'); next.type = 'button'; next.disabled = scanPage >= pages - 1;
  next.addEventListener('click', () => { scanPage++; renderScans(); });
  pager.append(prev, htmlEl('span', 'pager-ind', `Page ${scanPage + 1} of ${pages}`), next);
}

function renderScans() {
  const tbody = document.getElementById('scan-body');
  const q = (document.getElementById('scan-search').value || '').toLowerCase();
  const list = allScans.filter(s => String(s.username || '').toLowerCase().includes(q));
  const pages = Math.max(1, Math.ceil(list.length / scansPerPage));
  scanPage = Math.min(Math.max(scanPage, 0), pages - 1);
  const pageItems = list.slice(scanPage * scansPerPage, scanPage * scansPerPage + scansPerPage);
  document.getElementById('scan-count').textContent =
    `${list.length} scan${list.length === 1 ? '' : 's'}` + (pages > 1 ? ` · page ${scanPage + 1}/${pages}` : '');
  if (!list.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-state"><div class="icon"><img class="check" src="/static/check.webp" alt=""></div>No scans recorded yet.</td></tr>`;
    renderScanPager(pages);
    return;
  }
  tbody.innerHTML = pageItems.map(s => {
    const nets = Array.isArray(s.networks) ? s.networks : [];
    const finding = scanFinding(s);
    const iok = s.integrity_ok;
    const istr = iok === undefined ? '<span class="hash">—</span>'
               : iok ? '<span class="int-ok">✓ VALID</span>' : '<span class="int-fail">✗ TAMPERED</span>';
    const threats = Number(s.threats) || 0;
    const detail = nets.length ? `<table class="net-table"><thead><tr>
        <th>SSID</th><th>BSSID</th><th>Signal</th><th>Ch</th><th>Encryption</th><th>Status</th><th>Score</th><th>Reasons</th></tr></thead>
        <tbody>${nets.map(n => `<tr>
          <td><strong>${esc(n.ssid || '?')}</strong></td>
          <td class="bssid">${esc(n.bssid || '?')}</td>
          <td>${esc(n.signal_dbm)} dBm</td>
          <td>${esc(n.channel)}</td>
          <td>${esc(n.encryption || '?')}</td>
          <td><span class="badge ${esc(n.threat_level || n.status || '')}">${esc(n.status || '?')}</span></td>
          <td>${esc(n.score)}</td>
          <td class="reasons">${(Array.isArray(n.reasons) ? n.reasons : []).map(esc).join(' · ') || '—'}</td>
        </tr>`).join('')}</tbody></table>` : '<div class="chart-empty">No networks recorded.</div>';
    return `<tr class="scan-row">
        <td class="ts"><span class="caret">▸</span> ${esc(fmtTs(s.timestamp))}</td>
        <td><strong>${esc(s.username || '?')}</strong>${s.simulated === true ? ' <span class="badge sim" title="Simulated sweep (test only, not real evidence)">SIM</span>' : ''}</td>
        <td>${esc(nets.length)}</td>
        <td>${threats > 0 ? `<span class="badge HIGH">${threats}</span>` : '0'}</td>
        <td><span class="badge ${finding}">${finding}</span></td>
        <td class="hash">${esc(s.clock_source || '—')}</td>
        <td>${istr}<br><span class="hash">${esc(String(s.sha256_hash || '').substring(0, 20))}…</span></td>
      </tr>
      <tr class="scan-detail" hidden><td colspan="7">${detail}</td></tr>`;
  }).join('');
  tbody.querySelectorAll('.scan-row').forEach(row => row.addEventListener('click', () => {
    const d = row.nextElementSibling;
    if (d && d.classList.contains('scan-detail')) { d.hidden = !d.hidden; row.classList.toggle('open', !d.hidden); }
  }));
  renderScanPager(pages);
}

async function loadScans() {
  const tbody = document.getElementById('scan-body');
  try {
    allScans = await (await fetch('/api/scans')).json();
    renderScans();
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

async function setUserStatus(sw) {
  const enabled = sw.getAttribute('aria-checked') !== 'true';
  const err = document.getElementById('user-err');
  err.textContent = '';
  sw.disabled = true;
  sw.setAttribute('aria-checked', enabled);          // flip right away; loadUsers() redraws from the server
  try {
    const r = await fetch(`/api/users/${encodeURIComponent(sw.dataset.id)}/status`, {
      method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({enabled})
    });
    if (!r.ok) err.textContent = '✗ ' + ((await r.json().catch(() => ({}))).error || `Failed (HTTP ${r.status})`);
  } catch(e) { err.textContent = '✗ Backend not reachable.'; }
  loadUsers();
}

// ── Auto-refresh (per-device) ──────────────────
const REFRESH_KEY = 'tg-refresh';
let refreshTimer = null, scansTimer = null;
function applyRefresh(sec, persist) {
  sec = Number(sec); if (isNaN(sec) || sec < 0) sec = 10;
  if (refreshTimer) clearInterval(refreshTimer);
  if (scansTimer)   clearInterval(scansTimer);
  refreshTimer = scansTimer = null;
  const sel = document.getElementById('refresh-interval');
  if (sel) sel.value = String(sec);
  const bar = document.getElementById('rfill');
  if (!sec) {
    if (bar) bar.style.animationPlayState = 'paused';
  } else {
    if (bar) { bar.style.animationDuration = sec + 's'; bar.style.animationPlayState = 'running'; }
    refreshTimer = setInterval(() => loadData(true), sec * 1000);
    scansTimer   = setInterval(loadScans, Math.max(sec, 30) * 1000);
  }
  if (persist) { try { localStorage.setItem(REFRESH_KEY, sec); } catch(e) {} }
}
let savedRefresh = 10;
try { const v = localStorage.getItem(REFRESH_KEY); if (v !== null && v !== '') savedRefresh = Number(v); } catch(e) {}

loadRetention();
loadData();
loadUsers();
loadScans();
applyRefresh(savedRefresh, false);

// ── Delete user (confirmation modal) ──────────────
let pendingDelete = null;
function askDeleteUser(id, name) {
  pendingDelete = id;
  const body = document.getElementById('cm-body');
  body.replaceChildren(
    document.createTextNode('Permanently delete '),
    htmlEl('b', '', name || 'this user'),
    document.createTextNode('? This removes their account and every detection and scan they uploaded. This cannot be undone.')
  );
  const m = document.getElementById('confirm-modal');
  m.hidden = false;
  document.getElementById('cm-confirm').focus();
}
function closeDeleteModal() {
  document.getElementById('confirm-modal').hidden = true;
  pendingDelete = null;
}
async function confirmDeleteUser() {
  if (!pendingDelete) return;
  const id = pendingDelete, btn = document.getElementById('cm-confirm');
  const err = document.getElementById('user-err'); err.textContent = '';
  btn.disabled = true;
  try {
    const r = await fetch(`/api/users/${encodeURIComponent(id)}/delete`, {
      method:'POST', headers:{'Content-Type':'application/json'}, body:'{}'
    });
    if (!r.ok) err.textContent = '✗ ' + ((await r.json().catch(() => ({}))).error || `Failed (HTTP ${r.status})`);
  } catch(e) { err.textContent = '✗ Backend not reachable.'; }
  btn.disabled = false;
  closeDeleteModal();
  loadUsers();
}

// ── Admin account (change email / password / reset 2FA) ──
const val = id => document.getElementById(id).value;
async function postAdmin(url, body, statusEl, okMsg) {
  statusEl.textContent = '…'; statusEl.className = 'form-status';
  try {
    const r = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
    const d = await r.json().catch(() => ({}));
    if (!r.ok) { statusEl.textContent = '✗ ' + (d.error || `Failed (HTTP ${r.status})`); statusEl.className = 'form-status err'; return null; }
    statusEl.textContent = '✓ ' + okMsg; statusEl.className = 'form-status ok';
    setTimeout(() => { statusEl.textContent = ''; }, 4000);
    return d;
  } catch(e) { statusEl.textContent = '✗ Backend not reachable.'; statusEl.className = 'form-status err'; return null; }
}
async function changeEmail(ev) {
  ev.preventDefault();
  const d = await postAdmin('/api/admin/email', {new_email: val('acc-email'), current_password: val('acc-email-pw')},
    document.getElementById('acc-email-status'), 'Email updated');
  if (d && d.email) { document.getElementById('acc-email-pw').value = ''; const se = document.getElementById('signed-in-email'); if (se) se.textContent = d.email; }
}
async function changePassword(ev) {
  ev.preventDefault();
  const d = await postAdmin('/api/admin/password', {new_password: val('acc-newpw'), current_password: val('acc-pw-cur')},
    document.getElementById('acc-pw-status'), 'Password updated');
  if (d) { document.getElementById('acc-newpw').value = ''; document.getElementById('acc-pw-cur').value = ''; }
}
async function reset2FA(ev) {
  ev.preventDefault();
  const d = await postAdmin('/api/admin/2fa/reset', {current_password: val('acc-2fa-pw')},
    document.getElementById('acc-2fa-status'), 'Redirecting to QR setup…');
  if (d && d.redirect) setTimeout(() => { window.location = d.redirect; }, 600);
}

// ── Event wiring (no inline handlers: the Content-Security-Policy forbids them) ──
document.getElementById('theme-btn').addEventListener('click', toggleTheme);
document.getElementById('btn-refresh').addEventListener('click', () => loadData());
document.getElementById('search').addEventListener('input', filterTable);
document.getElementById('btn-export').addEventListener('click', exportLogs);
document.getElementById('btn-refresh-scans').addEventListener('click', loadScans);
document.getElementById('scan-search').addEventListener('input', () => { scanPage = 0; renderScans(); });
document.getElementById('user-form').addEventListener('submit', addUser);
document.getElementById('btn-save-retention').addEventListener('click', () => saveRetentionField('retention-days', 'retention_days', 'ret-status'));
document.getElementById('btn-save-scan-retention').addEventListener('click', () => saveRetentionField('scan-retention-days', 'scan_retention_days', 'scan-ret-status'));
document.getElementById('refresh-interval').addEventListener('change', e => applyRefresh(e.target.value, true));
document.getElementById('scan-pp').value = String(scansPerPage);
document.getElementById('scan-pp').addEventListener('change', e => {
  scansPerPage = Number(e.target.value) || 12;
  try { localStorage.setItem(SCANPP_KEY, scansPerPage); } catch(_) {}
  scanPage = 0; renderScans();
});
document.getElementById('exp-log-json').addEventListener('click', exportLogs);
document.getElementById('exp-log-csv').addEventListener('click', exportLogsCSV);
document.getElementById('exp-scan-json').addEventListener('click', exportScansJSON);
document.getElementById('exp-scan-csv').addEventListener('click', exportScansCSV);
document.getElementById('email-form').addEventListener('submit', changeEmail);
document.getElementById('password-form').addEventListener('submit', changePassword);
document.getElementById('tfa-form').addEventListener('submit', reset2FA);
document.getElementById('cm-cancel').addEventListener('click', closeDeleteModal);
document.getElementById('cm-confirm').addEventListener('click', confirmDeleteUser);
document.getElementById('confirm-modal').addEventListener('click', e => { if (e.target.id === 'confirm-modal') closeDeleteModal(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape' && !document.getElementById('confirm-modal').hidden) closeDeleteModal(); });
document.getElementById('font-scale').addEventListener('input', e =>   // live label only; no zoom until release
  e.target.setAttribute('aria-valuetext', Math.round(FONT_SCALES[clampFs(e.target.value)] * 100) + '%'));
document.getElementById('font-scale').addEventListener('change', e => applyFontScale(e.target.value, true));
document.getElementById('font-reset').addEventListener('click', () => applyFontScale(FONT_DEFAULT, true));
document.querySelectorAll('.fs-a[data-fs]').forEach(s => s.addEventListener('click', () => applyFontScale(s.dataset.fs, true)));
document.getElementById('user-body').addEventListener('click', ev => {
  const b = ev.target.closest('button[data-action]');
  if (!b) return;
  if (b.dataset.action === 'log') openUserLog(b.dataset.id);
  else if (b.dataset.action === 'toggle') setUserStatus(b);
  else if (b.dataset.action === 'delete') askDeleteUser(b.dataset.id, b.dataset.name);
});
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
<title>TwinGuard-SHA256 | {{ {'setup': 'Admin Setup', '2fa': 'Verification', '2fa_setup': 'Set Up 2FA'}.get(mode, 'Admin Login') }}</title>
<link rel="icon" type="image/png" href="/static/favicon.png">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;500;700;900&display=swap" rel="stylesheet">
<style nonce="{{ csp_nonce }}">
:root{--accent:#4fc3f7;--accent2:#2b8fe0;--cyan:#7ddcff;--danger:#ff5a76;--safe:#3ee6a8;
  --mono:'Share Tech Mono',monospace;--sans:'Exo 2',sans-serif;}
[data-theme="dark"]{--bg:#0e1c33;--panel:#14284a;--border:#264878;--text:#dcebff;--dim:#86a5cc;--inp:#0f2140;--inp-border:#264878;
  --glow:rgba(79,195,247,.18);--grid:rgba(79,195,247,.05);--onaccent:#06142a;}
[data-theme="light"]{--bg:#e8f1fb;--panel:#ffffff;--border:#c3d7ef;--text:#0f2545;--dim:#5b7699;--inp:#eef4fb;--inp-border:#6a8ab3;
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
.logo-icon{width:66px;height:66px;flex-shrink:0;background:linear-gradient(135deg,var(--cyan),var(--accent2));
  -webkit-mask:url(/static/logo.png) center/contain no-repeat;mask:url(/static/logo.png) center/contain no-repeat;}
.logo-text{font-size:24px;font-weight:900;letter-spacing:1.5px;line-height:1.1;}
.logo-sub{font-family:var(--mono);font-size:11px;color:var(--dim);letter-spacing:2px;margin-top:4px;}
h1{font-family:var(--mono);font-size:16px;letter-spacing:3px;color:var(--accent);text-transform:uppercase;margin-bottom:6px;}
.hint{font-size:16px;color:var(--dim);margin-bottom:20px;line-height:1.5;}
label{display:flex;flex-direction:column;gap:6px;font-family:var(--mono);font-size:13px;letter-spacing:2px;
  color:var(--dim);text-transform:uppercase;margin-bottom:14px;}
input{padding:11px 14px;border-radius:8px;border:1px solid var(--inp-border);background:var(--inp);color:var(--text);
  font-family:var(--mono);font-size:17px;outline:none;transition:border-color .2s;}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--glow);}
button{width:100%;margin-top:6px;padding:12px;border:none;border-radius:8px;cursor:pointer;font-family:var(--sans);
  font-size:17px;font-weight:700;letter-spacing:1px;color:var(--onaccent);
  background:linear-gradient(135deg,var(--cyan),var(--accent2));}
button:hover{opacity:.88;}
.error{font-family:var(--mono);font-size:15px;color:var(--danger);border:1px solid var(--danger);border-radius:6px;
  padding:9px 12px;margin-bottom:16px;background:rgba(255,90,118,.08);}
.qr{background:#fff;border-radius:10px;padding:10px;width:200px;height:200px;margin:4px auto 14px;}
.qr svg{width:100%;height:100%;display:block;}
.secret{font-family:var(--mono);font-size:16px;letter-spacing:2px;text-align:center;color:var(--text);
  background:var(--inp);border:1px dashed var(--border);border-radius:8px;padding:8px;margin-bottom:16px;overflow-wrap:anywhere;}
ol.steps{font-size:16px;color:var(--dim);line-height:1.6;margin:0 0 16px 18px;}
.code-in{font-size:24px;letter-spacing:8px;text-align:center;}
.linkbtn{background:none;border:none;color:var(--dim);font-family:var(--mono);font-size:14px;cursor:pointer;
  width:auto;margin:14px auto 0;display:block;padding:4px;}
.linkbtn:hover{color:var(--accent);opacity:1;}
.foot{font-family:var(--mono);font-size:13px;color:var(--dim);text-align:center;margin-top:20px;letter-spacing:1px;}
</style>
<script nonce="{{ csp_nonce }}">
try { document.documentElement.setAttribute('data-theme', localStorage.getItem('tg-theme') || 'dark'); } catch(e) {}
</script>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="logo-icon" role="img" aria-label="TwinGuard logo"></div>
    <div><div class="logo-text">TWINGUARD</div><div class="logo-sub">ROGUE AP DEFENSE</div></div>
  </div>
  {% if mode == 'setup' %}
    <h1>First-Run Setup</h1>
    {% if locked %}
      <p class="hint">No admin account exists yet. For security, the admin account can only be created from the machine running the dashboard. Open <b>127.0.0.1:5000</b> on that machine.</p>
    {% else %}
      <p class="hint">Create the administrator account for this dashboard. It is stored in Firebase Authentication.</p>
      {% if error %}<div class="error">✗ {{ error }}</div>{% endif %}
      <form method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <label>Admin Email<input name="email" type="email" required maxlength="120" autocomplete="username" autofocus></label>
        <label>Password<input name="password" type="password" required minlength="10" autocomplete="new-password" placeholder="min. 10 characters"></label>
        <label>Confirm Password<input name="confirm" type="password" required minlength="10" autocomplete="new-password"></label>
        <button type="submit">Create Admin Account</button>
      </form>
    {% endif %}
  {% elif mode == '2fa' %}
    <h1>Two-Factor Verification</h1>
    <p class="hint">Enter the 6-digit code from your authenticator app for <b>{{ email }}</b>.</p>
    {% if error %}<div class="error">✗ {{ error }}</div>{% endif %}
    <form method="post">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <label>Authentication Code<input class="code-in" name="code" required inputmode="numeric" pattern="[0-9 ]{6,7}"
        maxlength="7" autocomplete="one-time-code" autofocus></label>
      <button type="submit">Verify</button>
    </form>
    <form method="post" action="/logout"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <button class="linkbtn" type="submit">← Cancel and sign out</button></form>
  {% elif mode == '2fa_setup' %}
    <h1>Set Up Two-Factor Authentication</h1>
    {% if locked %}
      <p class="hint">Two-factor setup can only be done on the machine running the dashboard. Open <b>127.0.0.1:5000</b> there.</p>
    {% else %}
      <ol class="steps">
        <li>Install an authenticator app on your phone (Google Authenticator, Microsoft Authenticator, Aegis, 2FAS…).</li>
        <li>Scan this QR code, or type the key below.</li>
        <li>Enter the 6-digit code it shows.</li>
      </ol>
      <div class="qr" role="img" aria-label="Authenticator QR code">{{ qr }}</div>
      <div class="secret">{{ secret }}</div>
      {% if error %}<div class="error">✗ {{ error }}</div>{% endif %}
      <form method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <label>Code from the app<input class="code-in" name="code" required inputmode="numeric" pattern="[0-9 ]{6,7}"
          maxlength="7" autocomplete="one-time-code" autofocus></label>
        <button type="submit">Turn On 2FA &amp; Continue</button>
      </form>
    {% endif %}
  {% else %}
    <h1>Admin Login</h1>
    <p class="hint">Authorized personnel only. Access attempts are logged.</p>
    {% if error %}<div class="error">✗ {{ error }}</div>{% endif %}
    <form method="post">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
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
        return render_template_string(LOGIN_HTML, mode="setup", locked=True), 403
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
                uid = store.create_admin(email, password, now_iso())
            except FirebaseError as e:
                error = str(e)
            else:
                print(f"[Auth] Admin account '{email}' created in Firebase.")
                start_pending("enroll", uid, email)
                return redirect(url_for("two_factor_setup"))
    return render_template_string(LOGIN_HTML, mode="setup", locked=False, error=error)

@app.route("/login", methods=["GET", "POST"])
def login():
    if not store.admin_exists():
        return redirect(url_for("setup"))
    if admin_session_valid():
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
                uid, admin_email = store.sign_in_admin(email, password)
            except FirebaseError as e:
                record_failure(key)
                print(f"[Auth] Failed admin password from {request.remote_addr}.")
                error = str(e)
            else:
                if (store.admin_record(uid) or {}).get("totp_secret"):
                    start_pending("2fa", uid, admin_email)
                    return redirect(url_for("two_factor"))
                if request.remote_addr in LOOPBACK:
                    start_pending("enroll", uid, admin_email)
                    return redirect(url_for("two_factor_setup"))
                error = ("Two-factor authentication is not set up yet. Log in once on the dashboard "
                         "machine itself (127.0.0.1:5000) to set it up.")
    return render_template_string(LOGIN_HTML, mode="login", error=error)

@app.route("/2fa", methods=["GET", "POST"])
def two_factor():
    pending = get_pending("2fa")
    if not pending:
        session.clear()
        return redirect(url_for("login"))
    error = None
    if request.method == "POST":
        key = f"admin:{request.remote_addr}"
        if is_locked(key):
            error = "Too many failed attempts. Try again in a few minutes."
        else:
            secret  = (store.admin_record(pending["uid"]) or {}).get("totp_secret", "")
            counter = verify_totp(secret, request.form.get("code"))
            if counter is not None and store.consume_totp_counter(pending["uid"], counter):
                clear_failures(key)
                start_admin_session(pending["uid"], pending["email"])
                print(f"[Auth] Admin '{pending['email']}' logged in (2FA) from {request.remote_addr}.")
                return redirect(url_for("dashboard"))
            record_failure(key)
            print(f"[Auth] Failed 2FA code from {request.remote_addr}.")
            pending["tries"] += 1
            session["pending"] = pending
            if pending["tries"] >= MAX_2FA_TRIES:
                session.clear()
                return redirect(url_for("login"))
            error = "Invalid or already-used code"
    return render_template_string(LOGIN_HTML, mode="2fa", email=pending["email"], error=error)

@app.route("/2fa/setup", methods=["GET", "POST"])
def two_factor_setup():
    """Enrol the authenticator app. Only from this machine, right after a verified password."""
    pending = get_pending("enroll")
    if not pending:
        session.clear()
        return redirect(url_for("login"))
    if request.remote_addr not in LOOPBACK:
        return render_template_string(LOGIN_HTML, mode="2fa_setup", locked=True), 403
    if not pending.get("secret"):
        pending["secret"] = pyotp.random_base32()
        session["pending"] = pending
    secret, error = pending["secret"], None
    if request.method == "POST":
        counter = verify_totp(secret, request.form.get("code"))
        if counter is not None:
            store.set_admin_totp(pending["uid"], secret, counter, now_iso())
            start_admin_session(pending["uid"], pending["email"])
            print(f"[Auth] 2FA enabled for admin '{pending['email']}'.")
            return redirect(url_for("dashboard"))
        error = "That code didn't match. Check the phone's time is automatic and try the newest code."
    uri = pyotp.TOTP(secret).provisioning_uri(name=pending["email"], issuer_name="TwinGuard")
    return render_template_string(LOGIN_HTML, mode="2fa_setup", locked=False, error=error,
                                  qr=qr_svg(uri), secret=" ".join(secret[i:i + 4] for i in range(0, len(secret), 4)))

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

def cert_hosts(path):
    """Host names / IPv4 addresses the certificate is valid for -> TRUSTED_HOSTS."""
    with open(path, "rb") as f:
        san = x509.load_pem_x509_certificate(f.read()).extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    return san.get_values_for_type(x509.DNSName) + \
        [str(ip) for ip in san.get_values_for_type(x509.IPAddress) if isinstance(ip, ipaddress.IPv4Address)]

def main():
    global store
    sys.stdout.reconfigure(line_buffering=True)   # show log lines immediately in dashboard.log
    ap = argparse.ArgumentParser(description="TwinGuard-SHA256 admin dashboard")
    ap.add_argument("--host", default="0.0.0.0", help="address to listen on (0.0.0.0 = LAN, 127.0.0.1 = this machine only)")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--https", action="store_true",
                    help="serve HTTPS (TLS 1.2+) with the certificates from make_certs.py instead of plain HTTP")
    ap.add_argument("--allow-host", action="append", default=[], metavar="NAME_OR_IP",
                    help="extra host name/IP the dashboard may be opened as, e.g. the laptop IP when "
                         "using VMware NAT port forwarding (repeatable)")
    args = ap.parse_args()

    if args.https:
        # Keep the certificate valid for this machine's current IPs (e.g. after switching the
        # VM to bridged networking or joining another Wi-Fi). The CA is reused, so devices that
        # already trust it need nothing new.
        have_cert = os.path.exists(SRV_CRT) and os.path.exists(SRV_KEY)
        wanted = set(make_certs.local_ipv4s()) | {h for h in args.allow_host if h[:1].isdigit()}
        missing = wanted - set(cert_hosts(SRV_CRT)) if have_cert else set()
        if not have_cert or missing:
            old_dns = [h for h in cert_hosts(SRV_CRT) if not h[0].isdigit()] if have_cert else []
            _dns, ips, ca_new, _until = make_certs.issue_server_cert(
                extra_ips=[h for h in args.allow_host if h[:1].isdigit()],
                extra_dns=old_dns + [h for h in args.allow_host if not h[:1].isdigit()])
            print(f"  [HTTPS] Certificate {'created' if not have_cert else 'updated'} for: {', '.join(ips)}")
            if ca_new:
                print("  [HTTPS] New certificate authority: install certs/twinguard-ca.crt on admin devices.")
        hosts = cert_hosts(SRV_CRT)
        app.config.update(USE_HTTPS=True, SESSION_COOKIE_NAME="__Host-twinguard", SESSION_COOKIE_SECURE=True)
    else:
        name = socket.gethostname()
        hosts = sorted({"localhost", name, f"{name}.local", "127.0.0.1", *make_certs.local_ipv4s(), *args.allow_host})
    app.config["TRUSTED_HOSTS"] = hosts      # reject requests addressed to any other host name
    try:
        store = FirebaseStore()
    except FirebaseNotConfigured as e:
        print(f"\n  [Firebase] Not configured: {e}\n  See firebase/README.md for the one-time setup.\n")
        sys.exit(1)
    threading.Thread(target=purge_old_logs, daemon=True).start()

    server = wsgi.Server((args.host, args.port), app, numthreads=16, server_name="TwinGuard")
    if args.https:
        adapter = BuiltinSSLAdapter(SRV_CRT, SRV_KEY)
        adapter.context.minimum_version = ssl.TLSVersion.TLSv1_2
        server.ssl_adapter = adapter

    scheme = "https" if args.https else "http"
    print(f"\n  TwinGuard-SHA256 — Dashboard Server (Firebase, {scheme.upper()})")
    print("  ─────────────────────────────────────────────────────")
    for h in hosts:
        if h[0].isdigit() and (args.host == "0.0.0.0" or h == "127.0.0.1"):
            print(f"  Open: {scheme}://{h}:{args.port}")
    if not args.https:
        print("  Note: plain HTTP. Logins are not encrypted on the network; use --https for encryption.")
    print()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()

if __name__ == "__main__":
    main()
