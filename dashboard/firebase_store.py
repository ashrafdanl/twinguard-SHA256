"""
TwinGuard-SHA256: Firebase data layer for the dashboard
========================================================
Uses only Firebase's free Spark plan features:
  - Firebase Authentication (email/password) for the admin and operator accounts
  - Cloud Firestore for user profiles and the sealed forensic alerts

Firestore layout:
  users/{uid}                        application user (operator) profile: username,
                                     full_name, email, role, enabled, created_at
  users/{uid}/detections/{sha256}    the operator's own space: EVERY sealed detection from
                                     their phone app or detector (all severities)
  admins/{uid}         the single super admin of the dashboard + their 2FA (server-only)

There is exactly one dashboard admin (the super admin, created on first run).
Everyone else is an application user managed from the dashboard.

The dashboard receives only CRITICAL (severity HIGH) detections: it keeps a live
in-memory copy of them through a collection-group listener, plus severity counts of
all detections (cheap count queries, refreshed every minute) for the charts.
"""

import json, os, threading, time
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
        self._counts       = (0, None)    # (fetched_at, {"HIGH": n, ...})
        self._users_watch    = self.db.collection("users").on_snapshot(self._on_users)
        self._critical_watch = None
        self._ensure_critical_watch()
        threading.Thread(target=self._watchdog, daemon=True).start()

    def _ensure_critical_watch(self):
        """(Re)subscribe to critical detections from every operator's space. The query
        needs a collection-group index; until it exists the stream stops, so retry."""
        if self._critical_watch is not None and self._critical_watch.is_active:
            return True
        if self._critical_watch is not None:
            self._critical_watch.close()
        try:
            list(self.db.collection_group("detections")
                 .where(filter=FieldFilter("severity", "==", "HIGH")).limit(1).stream())
        except Exception as e:
            if not getattr(self, "_index_warned", False):
                print(f"[Firebase] Waiting for the 'detections' index (see firebase/README.md): {str(e)[:120]}")
                self._index_warned = True
            self._critical_watch = None
            return False
        with self._lock:
            self._alerts.clear()
        self._critical_watch = (self.db.collection_group("detections")
                                .where(filter=FieldFilter("severity", "==", "HIGH")).on_snapshot(self._on_alerts))
        if getattr(self, "_index_warned", False):
            print("[Firebase] ✓ 'detections' index ready: critical alerts are live.")
            self._index_warned = False
        return True

    def _watchdog(self):
        while True:
            time.sleep(30)
            try:
                self._ensure_critical_watch()
            except Exception as e:
                print(f"[Firebase] Listener check failed: {e}")

    # ── Live caches ──────────────────────────────────────────────────────────
    def _apply(self, cache, changes, by_path=False):
        with self._lock:
            for ch in changes:
                # detections: full path (ids are only unique within one operator's space)
                key = ch.document.reference.path if by_path else ch.document.id
                if ch.type.name == "REMOVED":
                    cache.pop(key, None)
                else:
                    cache[key] = ch.document.to_dict()

    def _on_alerts(self, _snap, changes, _read_time):
        self._apply(self._alerts, changes, by_path=True)

    def _on_users(self, _snap, changes, _read_time):
        self._apply(self._users, changes)

    # ── Detections ───────────────────────────────────────────────────────────
    def alerts(self):
        """Critical (HIGH) detections from all operators, oldest first."""
        with self._lock:
            entries = [dict(a) for a in self._alerts.values()]
        return sorted(entries, key=lambda a: str(a.get("timestamp", "")))

    def severity_counts(self, max_age=60):
        """Counts of ALL detections per severity (aggregation queries: ~1 read per 1000)."""
        fetched, counts = self._counts
        if counts is None or time.time() - fetched > max_age:
            group = self.db.collection_group("detections")
            try:
                counts = {sev: int(group.where(filter=FieldFilter("severity", "==", sev)).count().get()[0][0].value)
                          for sev in ("HIGH", "MEDIUM", "LOW")}
            except Exception as e:     # index not serving yet: show what we have instead of failing
                print(f"[Firebase] Severity counts unavailable, using critical alerts only: {str(e)[:120]}")
                counts = {"HIGH": len(self.alerts()), "MEDIUM": 0, "LOW": 0}
                self._counts = (time.time() - max_age + 10, counts)   # retry in ~10 s
                return dict(counts)
            self._counts = (time.time(), counts)
        return dict(counts)

    def purge_alerts_before(self, cutoff_iso):
        """Delete detections (every operator's space) older than cutoff_iso. Returns the count."""
        removed = 0
        while True:
            docs = list(self.db.collection_group("detections")
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
        try:
            auth.update_user(uid, disabled=not enabled)
            if not enabled:
                auth.revoke_refresh_tokens(uid)  # sign the phone app / detector out
        except auth.UserNotFoundError:
            raise FirebaseError("This operator has no Firebase Auth account (deleted in the console?)")
        except firebase_admin.exceptions.FirebaseError as e:
            raise FirebaseError(f"Firebase refused the change: {e}")
        self.db.collection("users").document(uid).update({"enabled": enabled})
        with self._lock:
            self._users[uid]["enabled"] = enabled
        return self._users[uid].get("username", uid)

    # ── Super admin (admins/{uid}; server-only, client security rules deny all access) ──
    #   email, display_name, enabled, role "super", created_at,
    #   totp_secret, totp_last_counter, totp_enrolled_at      (2FA)
    def _admins(self):
        return self.db.collection("admins")

    def _migrate_single_admin(self):
        """Move the original single-admin record (config/admin) into admins/{uid}, once."""
        old = self.db.collection("config").document("admin")
        snap = old.get()
        if not snap.exists:
            return
        d = snap.to_dict()
        ref = self._admins().document(d["uid"])
        if not ref.get().exists:
            rec = {k: v for k, v in d.items() if k != "uid"}
            rec.update(display_name=rec.get("display_name", ""), enabled=True, created_by=None)
            ref.set(rec)
            if ref.get().to_dict() != rec:
                raise RuntimeError("Admin migration could not be verified; config/admin left in place.")
        old.delete()
        print(f"[Admins] Migrated admin '{d.get('email')}' to admins/{d['uid']}.")

    def admin_exists(self):
        if not self._admin_exists:
            self._migrate_single_admin()
            self._admin_exists = any(True for _ in self._admins().limit(1).stream())
        return self._admin_exists

    def admin_record(self, uid):
        snap = self._admins().document(uid).get()
        return snap.to_dict() if snap.exists else None

    def create_admin(self, email, password, created_at):
        """Create the one super admin (first-run setup only)."""
        if self.admin_exists():
            raise FirebaseError("An admin account already exists")
        try:
            user = auth.create_user(email=email, password=password, display_name="TwinGuard Super Admin")
        except auth.EmailAlreadyExistsError:
            raise FirebaseError("An account with this email already exists")
        except ValueError as e:
            raise FirebaseError(str(e))
        try:
            auth.set_custom_user_claims(user.uid, {"admin": True})
            self._admins().document(user.uid).create({
                "email": email, "display_name": "", "enabled": True, "role": "super", "created_at": created_at})
        except Exception:
            auth.delete_user(user.uid)
            raise
        self._admin_exists = True
        return user.uid

    # ── Admin 2FA ────────────────────────────────────────────────────────────
    def set_admin_totp(self, uid, secret, counter, enrolled_at):
        self._admins().document(uid).update(
            {"totp_secret": secret, "totp_last_counter": counter, "totp_enrolled_at": enrolled_at})

    def consume_totp_counter(self, uid, counter):
        """Atomically record a used TOTP time-step. False if it (or a later one) was already used."""
        ref = self._admins().document(uid)

        @firestore.transactional
        def txn(t):
            last = (ref.get(transaction=t).to_dict() or {}).get("totp_last_counter", -1)
            if counter <= last:
                return False
            t.update(ref, {"totp_last_counter": counter})
            return True

        return txn(self.db.transaction())

    def admin_account_ok(self, uid, logged_in_at):
        """Still an enabled admin, and sessions not revoked (e.g. password reset) since login."""
        try:
            u = auth.get_user(uid)
        except auth.UserNotFoundError:
            return False
        rec = self.admin_record(uid) or {}
        revoked_after = (u.tokens_valid_after_timestamp or 0) / 1000
        return (not u.disabled and (u.custom_claims or {}).get("admin") is True
                and rec.get("enabled") is True and rec.get("role", "super") == "super"
                and revoked_after <= logged_in_at)

    def sign_in_admin(self, email, password):
        """Check credentials with Firebase Auth; returns (uid, email) for the super admin only."""
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
        rec = self.admin_record(claims["uid"])
        if claims.get("admin") is not True or not rec or rec.get("role", "super") != "super":
            raise FirebaseError("This account is not an administrator")
        if not rec.get("enabled"):
            raise FirebaseError("This account is disabled")
        return claims["uid"], claims.get("email", email)


def _ms_to_iso(ms):
    if not ms:
        return None
    return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat()
