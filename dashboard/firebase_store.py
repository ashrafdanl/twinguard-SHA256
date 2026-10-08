"""
TwinGuard-SHA256: Firebase data layer for the dashboard
========================================================
Uses only Firebase's free Spark plan features:
  - Firebase Authentication (email/password) for the admin and operator accounts
  - Cloud Firestore for user profiles and the sealed forensic alerts

Firestore layout:
  users/{uid}          operator profile: username, full_name, email, role, enabled,
                       created_at, workspace_id
  alerts/{sha}         sealed alert written by an operator's detection engine
  admins/{uid}         dashboard admin: role "super" | "admin", workspace_id, 2FA (server-only)
  workspaces/{id}      one isolated workspace per admin: name, owner (server-only)

Workspaces: every admin owns a workspace (id = their uid). Operators belong to one
workspace, and an alert belongs to its operator's workspace. Workspace admins see only
their own workspace; super admins see all. (Separate Firestore databases would need a
billing account, so isolation is done inside the free default database.)

The dashboard keeps live in-memory copies of `users` and `alerts` through
Firestore listeners, so the 10-second browser refresh costs no Firestore reads.
"""

import json, os, secrets, threading
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
                "workspace_id": p.get("workspace_id"),
                "enabled":    not disabled,
                "created_at": p.get("created_at"),
                "last_login": _ms_to_iso(last_ms),
            })
        return sorted(result, key=lambda u: u["created_at"] or "")

    def create_user(self, username, full_name, email, password, created_at, workspace_id):
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
                   "email": email, "role": "operator", "enabled": True, "created_at": created_at,
                   "workspace_id": workspace_id}
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

    # ── Admins (admins/{uid}; server-only, client security rules deny all access) ──
    #   email, display_name, enabled, created_at, created_by,
    #   totp_secret, totp_last_counter, totp_enrolled_at      (2FA)
    #   setup_code_hash, setup_code_expires                   (one-time setup code)
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
            if self._admin_exists:
                self._migrate_workspaces()
        return self._admin_exists

    # ── Workspaces ───────────────────────────────────────────────────────────
    def _workspaces(self):
        return self.db.collection("workspaces")

    def _ensure_workspace(self, admin_uid, rec):
        ref = self._workspaces().document(admin_uid)
        if not ref.get().exists:
            ref.set({"name": rec.get("display_name") or rec.get("email", admin_uid),
                     "owner_uid": admin_uid, "owner_email": rec.get("email"),
                     "created_at": rec.get("created_at")})

    def _migrate_workspaces(self):
        """Give older records roles/workspaces: the original admin becomes super admin,
        and operators without a workspace join the first super admin's workspace."""
        supers = []
        for snap in self._admins().stream():
            rec = snap.to_dict()
            if not rec.get("role") or not rec.get("workspace_id"):
                rec["role"] = rec.get("role") or ("super" if rec.get("created_by") is None else "admin")
                rec["workspace_id"] = snap.id
                snap.reference.update({"role": rec["role"], "workspace_id": snap.id})
                print(f"[Workspaces] Admin '{rec.get('email')}' -> role {rec['role']}, own workspace.")
            self._ensure_workspace(snap.id, rec)
            if rec["role"] == "super":
                supers.append((rec.get("created_at") or "", snap.id))
        if not supers:
            return
        home = min(supers)[1]
        for snap in self.db.collection("users").stream():
            if not snap.to_dict().get("workspace_id"):
                snap.reference.update({"workspace_id": home})
                with self._lock:
                    if snap.id in self._users:
                        self._users[snap.id]["workspace_id"] = home
                print(f"[Workspaces] Operator '{snap.to_dict().get('username')}' -> workspace {home}.")

    def list_workspaces(self):
        return sorted(({"id": w.id, **w.to_dict()} for w in self._workspaces().stream()),
                      key=lambda w: w.get("created_at") or "")

    def admin_record(self, uid):
        snap = self._admins().document(uid).get()
        return snap.to_dict() if snap.exists else None

    def create_admin(self, email, password, created_at, display_name="", created_by=None,
                     setup_code_hash=None, setup_code_expires=None):
        """First-run admin (password given) or an admin created by another admin
        (no usable password yet: they set it with their one-time setup code)."""
        if created_by is None and self.admin_exists():
            raise FirebaseError("An admin account already exists")
        try:
            user = auth.create_user(email=email, password=password or secrets.token_urlsafe(32),
                                    display_name=display_name or "TwinGuard Admin")
        except auth.EmailAlreadyExistsError:
            raise FirebaseError("An account with this email already exists")
        except ValueError as e:
            raise FirebaseError(str(e))
        rec = {"email": email, "display_name": display_name, "enabled": True,
               "role": "super" if created_by is None else "admin", "workspace_id": user.uid,
               "created_at": created_at, "created_by": created_by,
               "setup_code_hash": setup_code_hash, "setup_code_expires": setup_code_expires}
        try:
            auth.set_custom_user_claims(user.uid, {"admin": True})
            self._admins().document(user.uid).create(rec)
            self._ensure_workspace(user.uid, rec)
        except Exception:
            auth.delete_user(user.uid)
            raise
        self._admin_exists = True
        return user.uid

    def list_admins(self):
        meta = {}
        for u in auth.list_users().iterate_all():
            if (u.custom_claims or {}).get("admin"):
                meta[u.uid] = (u.disabled, u.user_metadata.last_sign_in_timestamp)
        result = []
        for snap in self._admins().stream():
            d = snap.to_dict()
            disabled, last_ms = meta.get(snap.id, (True, None))
            pending = bool(d.get("setup_code_hash")) and not d.get("totp_secret")
            result.append({
                "id": snap.id, "email": d.get("email", ""), "display_name": d.get("display_name", ""),
                "role": d.get("role", "admin"), "workspace_id": d.get("workspace_id", snap.id),
                "enabled": bool(d.get("enabled")) and not disabled,
                "twofa": "active" if d.get("totp_secret") else ("setup_pending" if pending else "not_set"),
                "setup_code_expires": d.get("setup_code_expires") if pending else None,
                "created_at": d.get("created_at"), "created_by": d.get("created_by"),
                "last_login": _ms_to_iso(last_ms),
            })
        return sorted(result, key=lambda a: a["created_at"] or "")

    def set_admin_enabled(self, uid, enabled):
        if not self.admin_record(uid):
            raise KeyError(uid)
        auth.update_user(uid, disabled=not enabled)
        if not enabled:
            auth.revoke_refresh_tokens(uid)
        self._admins().document(uid).update({"enabled": enabled})

    def set_admin_setup_code(self, uid, code_hash, expires):
        """Issue a new one-time setup code and remove the current 2FA (used for 2FA resets)."""
        if not self.admin_record(uid):
            raise KeyError(uid)
        self._admins().document(uid).update({
            "setup_code_hash": code_hash, "setup_code_expires": expires,
            "totp_secret": firestore.DELETE_FIELD, "totp_last_counter": firestore.DELETE_FIELD})
        auth.revoke_refresh_tokens(uid)

    def find_admin_by_email(self, email):
        try:
            u = auth.get_user_by_email(email)
        except (auth.UserNotFoundError, ValueError):
            return None, None
        rec = self.admin_record(u.uid)
        return (u.uid, rec) if rec else (None, None)

    def complete_admin_setup(self, uid, password, secret, counter, enrolled_at):
        """Redeem a setup code: set the admin's own password and 2FA; the code is single-use."""
        auth.update_user(uid, password=password)
        self._admins().document(uid).update({
            "totp_secret": secret, "totp_last_counter": counter, "totp_enrolled_at": enrolled_at,
            "setup_code_hash": None, "setup_code_expires": None})

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
                and rec.get("enabled") is True and revoked_after <= logged_in_at)

    def sign_in_admin(self, email, password):
        """Check credentials with Firebase Auth; returns (uid, email) for enabled admins only."""
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
        if claims.get("admin") is not True or not rec:
            raise FirebaseError("This account is not an administrator")
        if not rec.get("enabled"):
            raise FirebaseError("This account is disabled")
        return claims["uid"], claims.get("email", email)


def _ms_to_iso(ms):
    if not ms:
        return None
    return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat()
