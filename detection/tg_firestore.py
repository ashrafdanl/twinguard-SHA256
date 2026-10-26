"""TwinGuard - Cloud Firestore uploader for the Raspberry Pi.

The Pi signs in as an ordinary operator account (email + password, Firebase
Auth REST API) and writes through the same Firestore security rules as the
phone app. It never uses a service-account key: an admin key on a portable
device would bypass every rule, so a stolen Pi could rewrite all evidence.

Writes:
  users/{uid}/detections/{sha256_hash}   one sealed alert
  users/{uid}/scans/{sha256_hash}        one sealed scan record

Both are create-only under the rules. Document ids are the content's SHA-256,
so a retry after a lost response can never create a duplicate: the second
attempt is refused as already-existing and is treated as success.

Pending writes survive power loss in a JSON queue on disk.
"""
import json
import os
import threading
import time

import requests

AUTH_URL = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword"
REFRESH_URL = "https://securetoken.googleapis.com/v1/token"
FS_ROOT = "https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents"


def log(msg):
    print(f"[FIRESTORE] {msg}", flush=True)


# ── Firestore REST value encoding ────────────────────────────────────────────

def encode_value(v):
    if v is None:
        return {"nullValue": None}
    if isinstance(v, bool):
        return {"booleanValue": v}
    if isinstance(v, int):
        return {"integerValue": str(v)}
    if isinstance(v, float):
        return {"doubleValue": v}
    if isinstance(v, str):
        return {"stringValue": v}
    if isinstance(v, (list, tuple)):
        return {"arrayValue": {"values": [encode_value(x) for x in v]}}
    if isinstance(v, dict):
        return {"mapValue": {"fields": {str(k): encode_value(x) for k, x in v.items()}}}
    return {"stringValue": str(v)}


def encode_fields(d):
    return {str(k): encode_value(v) for k, v in d.items()}


def decode_value(v):
    if "stringValue" in v:
        return v["stringValue"]
    if "booleanValue" in v:
        return v["booleanValue"]
    if "integerValue" in v:
        return int(v["integerValue"])
    if "doubleValue" in v:
        return float(v["doubleValue"])
    if "nullValue" in v:
        return None
    if "arrayValue" in v:
        return [decode_value(x) for x in v["arrayValue"].get("values", [])]
    if "mapValue" in v:
        return {k: decode_value(x) for k, x in v["mapValue"].get("fields", {}).items()}
    if "timestampValue" in v:
        return v["timestampValue"]
    return None


# ── Operator session ─────────────────────────────────────────────────────────

class AuthError(Exception):
    pass


class OperatorSession:
    """Holds the operator's ID token and refreshes it before it expires."""

    def __init__(self, cfg, http=None):
        self.cfg = cfg
        self.http = http or requests.Session()
        self.id_token = None
        self.refresh_token = None
        self.expires_at = 0
        self.uid = cfg.get("uid")
        self.username = cfg.get("username")
        self.lock = threading.Lock()

    def sign_in(self):
        r = self.http.post(AUTH_URL, params={"key": self.cfg["api_key"]}, json={
            "email": self.cfg["email"],
            "password": self.cfg["password"],
            "returnSecureToken": True,
        }, timeout=20)
        if r.status_code != 200:
            try:
                code = r.json()["error"]["message"]
            except Exception:
                code = f"HTTP {r.status_code}"
            raise AuthError(code)
        j = r.json()
        with self.lock:
            self.id_token = j["idToken"]
            self.refresh_token = j["refreshToken"]
            self.expires_at = time.time() + int(j.get("expiresIn", 3600))
            self.uid = j["localId"]
        return self.uid

    def _refresh(self):
        r = self.http.post(REFRESH_URL, params={"key": self.cfg["api_key"]}, data={
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token,
        }, timeout=20)
        if r.status_code != 200:
            raise AuthError(f"refresh failed HTTP {r.status_code}")
        j = r.json()
        with self.lock:
            self.id_token = j["id_token"]
            self.refresh_token = j["refresh_token"]
            self.expires_at = time.time() + int(j.get("expires_in", 3600))

    def token(self):
        if self.id_token is None:
            self.sign_in()
        elif time.time() > self.expires_at - 300:
            try:
                self._refresh()
            except (AuthError, requests.RequestException):
                self.sign_in()
        return self.id_token

    def invalidate(self):
        with self.lock:
            self.expires_at = 0


# ── Uploader ─────────────────────────────────────────────────────────────────

class FirestoreUploader:
    def __init__(self, cfg, data_dir, http=None, root_url=None):
        self.cfg = cfg
        self.http = http or requests.Session()
        self.session = OperatorSession(cfg, self.http)
        self.root = root_url or FS_ROOT.format(project=cfg["project_id"])
        self.data_dir = data_dir
        self.lock = threading.Lock()
        self.wake = threading.Event()
        self.queue = []
        self.rejected_count = 0
        self.uploaded_count = 0
        self.last_upload = None
        self.last_error = None
        self.signed_in = False
        self.profile_enabled = None
        self._stop = False
        self.queue_file = None
        self.rejected_file = None

    # -- startup ---------------------------------------------------------------
    def start(self):
        """Signs in (retrying ~1 min on network errors) and checks the profile.

        Returns the operator's uid and username. Raises AuthError on a wrong
        password or a disabled account - those will not fix themselves.
        """
        attempt = 0
        while True:
            try:
                uid = self.session.sign_in()
                break
            except AuthError:
                raise
            except requests.RequestException as e:
                attempt += 1
                self.last_error = f"sign-in network error: {e}"
                if attempt >= 6:
                    log("no network yet - continuing offline; uploads are queued")
                    uid = self.cfg.get("uid")
                    if not uid:
                        raise AuthError("offline and no cached uid")
                    break
                time.sleep(10)
        self.signed_in = self.session.id_token is not None
        self.queue_file = os.path.join(self.data_dir, f"firebase_queue_{uid}.json")
        self.rejected_file = os.path.join(self.data_dir, f"firebase_rejected_{uid}.json")
        self._load_queue()
        if self.signed_in:
            self._check_profile(uid)
        threading.Thread(target=self._worker, name="firestore", daemon=True).start()
        return uid, self.session.username

    def _check_profile(self, uid):
        """Reads users/{uid}. The rules require detection.username to equal the
        profile's username exactly, so the profile is the source of truth."""
        try:
            r = self.http.get(f"{self.root}/users/{uid}", headers=self._headers(), timeout=20)
        except requests.RequestException as e:
            log(f"profile check skipped (network): {e}")
            return
        if r.status_code != 200:
            log(f"profile users/{uid} not readable (HTTP {r.status_code}). Detections "
                "will be rejected until the admin creates this operator's profile.")
            self.profile_enabled = False
            return
        fields = {k: decode_value(v) for k, v in r.json().get("fields", {}).items()}
        name = fields.get("username")
        self.profile_enabled = bool(fields.get("enabled"))
        if name and name != self.session.username:
            log(f"username from profile is {name!r} (config had {self.session.username!r})")
            self.session.username = name
        if not self.profile_enabled:
            log("WARNING: this operator is DISABLED in users/{uid}; uploads will be refused")
        log(f"signed in as {self.session.username} (uid {uid[:8]}...), "
            f"role={fields.get('role')}, enabled={self.profile_enabled}")

    @property
    def uid(self):
        return self.session.uid

    @property
    def username(self):
        return self.session.username

    # -- queue -----------------------------------------------------------------
    def _load_queue(self):
        if self.queue_file and os.path.exists(self.queue_file):
            try:
                with open(self.queue_file) as f:
                    self.queue = json.load(f)
                log(f"{len(self.queue)} pending upload(s) restored from disk")
            except (OSError, ValueError):
                self.queue = []
        if self.rejected_file and os.path.exists(self.rejected_file):
            try:
                with open(self.rejected_file) as f:
                    self.rejected_count = len(json.load(f))
            except (OSError, ValueError):
                pass

    def _save_queue(self):
        if not self.queue_file:
            return
        tmp = self.queue_file + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.queue, f)
        os.replace(tmp, self.queue_file)

    def enqueue(self, kind, doc_id, data):
        collection = "detections" if kind == "detection" else "scans"
        item = {"collection": collection, "doc_id": doc_id, "data": data,
                "queued_at": time.time()}
        with self.lock:
            if any(q["doc_id"] == doc_id and q["collection"] == collection
                   for q in self.queue):
                return
            self.queue.append(item)
            self._save_queue()
        self.wake.set()

    def pending(self):
        with self.lock:
            return len(self.queue)

    def _reject(self, item, reason):
        log(f"REJECTED {item['collection']}/{item['doc_id'][:12]}...: {reason}")
        entries = []
        if os.path.exists(self.rejected_file):
            try:
                with open(self.rejected_file) as f:
                    entries = json.load(f)
            except (OSError, ValueError):
                entries = []
        entries.append({**item, "reason": reason, "rejected_at": time.time()})
        with open(self.rejected_file, "w") as f:
            json.dump(entries, f, indent=1)
        self.rejected_count = len(entries)

    # -- network ---------------------------------------------------------------
    def _headers(self):
        return {"Authorization": f"Bearer {self.session.token()}"}

    def _exists(self, item):
        url = f"{self.root}/users/{self.uid}/{item['collection']}/{item['doc_id']}"
        r = self.http.get(url, headers=self._headers(), timeout=20)
        return r.status_code == 200

    def _upload_one(self, item):
        """Returns 'done', 'reject:<reason>' or 'retry:<reason>'."""
        url = f"{self.root}/users/{self.uid}/{item['collection']}"
        body = {"fields": encode_fields(item["data"])}
        r = self.http.post(url, params={"documentId": item["doc_id"]},
                           headers=self._headers(), json=body, timeout=30)
        if r.status_code == 200:
            return "done"
        if r.status_code == 409:
            return "done"  # already uploaded by an earlier attempt
        if r.status_code == 401:
            self.session.invalidate()
            return "retry:token expired"
        if r.status_code == 403:
            # A create on an existing id is evaluated as an update, which the
            # rules forbid. Distinguish "already there" from "really refused".
            if self._exists(item):
                return "done"
            return "reject:permission denied by Firestore rules"
        if r.status_code in (400, 404):
            return f"reject:HTTP {r.status_code} {r.text[:200]}"
        return f"retry:HTTP {r.status_code}"

    def _worker(self):
        backoff = 5
        while not self._stop:
            with self.lock:
                item = self.queue[0] if self.queue else None
            if item is None:
                self.wake.wait(30)
                self.wake.clear()
                continue
            try:
                outcome = self._upload_one(item)
            except AuthError as e:
                outcome = f"retry:auth {e}"
            except requests.RequestException as e:
                outcome = f"retry:network {type(e).__name__}"
            if outcome == "done" or outcome.startswith("reject:"):
                if outcome.startswith("reject:"):
                    self._reject(item, outcome[7:])
                else:
                    self.uploaded_count += 1
                    self.last_upload = time.time()
                    self.signed_in = True
                    log(f"uploaded {item['collection']}/{item['doc_id'][:12]}...")
                with self.lock:
                    if self.queue and self.queue[0] is item:
                        self.queue.pop(0)
                    self._save_queue()
                backoff = 5
                self.last_error = None if outcome == "done" else outcome
                continue
            self.last_error = outcome[6:]
            log(f"upload deferred ({self.last_error}); retry in {backoff}s")
            self.wake.wait(backoff)
            self.wake.clear()
            backoff = min(backoff * 2, 120)

    def status(self):
        return {
            "signed_in": self.signed_in,
            "username": self.username,
            "uid": self.uid,
            "profile_enabled": self.profile_enabled,
            "pending": self.pending(),
            "uploaded": self.uploaded_count,
            "rejected": self.rejected_count,
            "last_upload": self.last_upload,
            "last_error": self.last_error,
        }

    def stop(self):
        self._stop = True
        self.wake.set()
