"""
TwinGuard-SHA256: Firebase data layer for the dashboard
========================================================
Uses only Firebase's free Spark plan features:
  - Firebase Authentication (email/password) for the admin and operator accounts
  - Cloud Firestore for user profiles and the sealed forensic alerts

Firestore layout:
  users/{uid}     operator profile: username, full_name, email, role, enabled, created_at
  alerts/{sha}    sealed alert written by an operator's detection engine
  config/admin    marker for the dashboard admin account (server-only)

The dashboard keeps live in-memory copies of `users` and `alerts` through
Firestore listeners, so the 10-second browser refresh costs no Firestore reads.
"""

import json, os, threading
from datetime import datetime, timezone
import requests
import firebase_admin
from firebase_admin import auth, credentials, firestore
from google.cloud.firestore_v1.base_query import FieldFilter

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_FILE = os.path.join(BASE_DIR, "firebase_config.json")
SIGN_IN_URL = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword"


class FirebaseNotConfigured(RuntimeError):
    pass


class FirebaseError(RuntimeError):
    """An error safe to show to the admin."""


def load_firebase_config():
    if not os.path.exists(CONFIG_FILE):
        raise FirebaseNotConfigured(
            f"{CONFIG_FILE} not found. Copy firebase_config.example.json to "
            "firebase_config.json and fill it in (see firebase/README.md).")
    with open(CONFIG_FILE) as f:
        cfg = json.load(f)
    for key in ("project_id", "web_api_key"):
        if not cfg.get(key) or str(cfg[key]).startswith("YOUR_"):
            raise FirebaseNotConfigured(f"'{key}' is not set in {CONFIG_FILE}.")
    sa = cfg.get("service_account_file") or "firebase-service-account.json"
    cfg["service_account_path"] = sa if os.path.isabs(sa) else os.path.join(BASE_DIR, sa)
    if not os.path.exists(cfg["service_account_path"]):
        raise FirebaseNotConfigured(
            f"Service account key {cfg['service_account_path']} not found "
            "(Firebase console > Project settings > Service accounts > Generate new private key).")
    return cfg


class FirebaseStore:

    def __init__(self):
        cfg = load_firebase_config()
        self.api_key = cfg["web_api_key"]
        firebase_admin.initialize_app(credentials.Certificate(cfg["service_account_path"]),
                                      {"projectId": cfg["project_id"]})
        self.db = firestore.client()
        self._lock         = threading.Lock()
        self._alerts       = {}
        self._users        = {}
        self._admin_exists = False
        self._watches = [
            self.db.collection("alerts").on_snapshot(self._on_alerts),
            self.db.collection("users").on_snapshot(self._on_users),
        ]

    # ── Live caches ──────────────────────────────────────────────────────────
    def _apply(self, cache, changes):
        with self._lock:
            for ch in changes:
                if ch.type.name == "REMOVED":
                    cache.pop(ch.document.id, None)
                else:
                    cache[ch.document.id] = ch.document.to_dict()

    def _on_alerts(self, _snap, changes, _read_time):
        self._apply(self._alerts, changes)

    def _on_users(self, _snap, changes, _read_time):
        self._apply(self._users, changes)

    # ── Alerts ───────────────────────────────────────────────────────────────
    def alerts(self):
        with self._lock:
            entries = [dict(a) for a in self._alerts.values()]
        return sorted(entries, key=lambda a: str(a.get("timestamp", "")))

    def purge_alerts_before(self, cutoff_iso):
        """Delete alerts whose timestamp is older than cutoff_iso. Returns the count."""
        removed = 0
        while True:
            docs = list(self.db.collection("alerts")
                        .where(filter=FieldFilter("timestamp", "<", cutoff_iso))
                        .limit(400).stream())
            if not docs:
                return removed
            batch = self.db.batch()
            for d in docs:
                batch.delete(d.reference)
            batch.commit()
            removed += len(docs)

    # ── Operators ────────────────────────────────────────────────────────────
    def user_profiles(self):
        with self._lock:
            return {uid: dict(u) for uid, u in self._users.items()}

    def users(self):
        """Operator profiles merged with live Firebase Auth state (disabled flag, last sign-in)."""
        profiles = self.user_profiles()
        meta = {}
        for u in auth.list_users().iterate_all():
            if u.uid in profiles:
                meta[u.uid] = (u.disabled, u.user_metadata.last_sign_in_timestamp)
        result = []
        for uid, p in profiles.items():
            disabled, last_ms = meta.get(uid, (not p.get("enabled", False), None))
            result.append({
                "id":         uid,
                "username":   p.get("username", ""),
                "full_name":  p.get("full_name", ""),
                "email":      p.get("email", ""),
                "role":       p.get("role", "operator"),
                "enabled":    not disabled,
                "created_at": p.get("created_at"),
                "last_login": _ms_to_iso(last_ms),
            })
        return sorted(result, key=lambda u: u["created_at"] or "")

    def create_user(self, username, full_name, email, password, created_at):
        lower = username.lower()
        if any(p.get("username_lower") == lower for p in self.user_profiles().values()):
            raise FirebaseError("Username already exists")
        try:
            user = auth.create_user(email=email, password=password,
                                    display_name=full_name or username, disabled=False)
        except auth.EmailAlreadyExistsError:
            raise FirebaseError("An account with this email already exists")
        except ValueError as e:
            raise FirebaseError(str(e))
        profile = {"username": username, "username_lower": lower, "full_name": full_name,
                   "email": email, "role": "operator", "enabled": True, "created_at": created_at}
        try:
            self.db.collection("users").document(user.uid).set(profile)
        except Exception:
            auth.delete_user(user.uid)  # don't leave an Auth account without a profile
            raise
        with self._lock:
            self._users[user.uid] = profile
        return user.uid

    def set_user_enabled(self, uid, enabled):
        if uid not in self.user_profiles():
            raise KeyError(uid)
        auth.update_user(uid, disabled=not enabled)
        if not enabled:
            auth.revoke_refresh_tokens(uid)  # sign the phone app / detector out
        self.db.collection("users").document(uid).update({"enabled": enabled})
        with self._lock:
            self._users[uid]["enabled"] = enabled
        return self._users[uid].get("username", uid)

    # ── Admin ────────────────────────────────────────────────────────────────
    def admin_exists(self):
        if not self._admin_exists:
            self._admin_exists = self.db.collection("config").document("admin").get().exists
        return self._admin_exists

    def create_admin(self, email, password, created_at):
        ref = self.db.collection("config").document("admin")
        if ref.get().exists:
            raise FirebaseError("An admin account already exists")
        try:
            user = auth.create_user(email=email, password=password, display_name="TwinGuard Admin")
        except auth.EmailAlreadyExistsError:
            raise FirebaseError("An account with this email already exists")
        except ValueError as e:
            raise FirebaseError(str(e))
        auth.set_custom_user_claims(user.uid, {"admin": True})
        ref.create({"uid": user.uid, "email": email, "created_at": created_at})
        self._admin_exists = True
        return user.uid

    def sign_in_admin(self, email, password):
        """Check credentials with Firebase Auth; returns (uid, email) for admins only."""
        try:
            r = requests.post(SIGN_IN_URL, params={"key": self.api_key}, timeout=10,
                              json={"email": email, "password": password, "returnSecureToken": True})
        except requests.RequestException:
            raise FirebaseError("Cannot reach Firebase. Check the internet connection.")
        if r.status_code != 200:
            code = r.json().get("error", {}).get("message", "")
            if code.startswith("USER_DISABLED"):
                raise FirebaseError("This account is disabled")
            if code.startswith("TOO_MANY_ATTEMPTS"):
                raise FirebaseError("Too many failed attempts. Try again later.")
            raise FirebaseError("Invalid email or password")
        claims = auth.verify_id_token(r.json()["idToken"])
        if claims.get("admin") is not True:
            raise FirebaseError("This account is not an administrator")
        return claims["uid"], claims.get("email", email)


def _ms_to_iso(ms):
    if not ms:
        return None
    return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat()
