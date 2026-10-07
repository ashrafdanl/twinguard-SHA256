"""
TwinGuard-SHA256: Firebase uploader for the detection engine
=============================================================
Signs in to Firebase Authentication AS THE OPERATOR (email + password) and
writes each sealed alert to Cloud Firestore through the public REST API, so:
  - no admin/service-account key is needed on detector machines,
  - Firestore security rules decide what this operator may write,
  - an operator disabled by the admin can no longer upload.

Only free Spark-plan features are used, and only the `requests` library.
"""

import json, os, time
import requests

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_FILE = os.path.join(BASE_DIR, "firebase_config.json")

SIGN_IN_URL  = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword"
REFRESH_URL  = "https://securetoken.googleapis.com/v1/token"
FIRESTORE    = "https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents"
MAX_PENDING  = 500


class UploaderError(RuntimeError):
    pass


def load_config():
    if not os.path.exists(CONFIG_FILE):
        raise UploaderError(f"{CONFIG_FILE} not found (see firebase/README.md).")
    with open(CONFIG_FILE) as f:
        cfg = json.load(f)
    for key in ("project_id", "web_api_key"):
        if not cfg.get(key) or str(cfg[key]).startswith("YOUR_"):
            raise UploaderError(f"'{key}' is not set in {CONFIG_FILE}.")
    return cfg


# ── Firestore REST value encoding ─────────────────────────────────────────────
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
        return {"mapValue": {"fields": {k: encode_value(x) for k, x in v.items()}}}
    return {"stringValue": str(v)}


def decode_value(v):
    if "nullValue" in v:
        return None
    if "booleanValue" in v:
        return v["booleanValue"]
    if "integerValue" in v:
        return int(v["integerValue"])
    if "doubleValue" in v:
        return float(v["doubleValue"])
    if "stringValue" in v:
        return v["stringValue"]
    if "arrayValue" in v:
        return [decode_value(x) for x in v["arrayValue"].get("values", [])]
    if "mapValue" in v:
        return {k: decode_value(x) for k, x in v["mapValue"].get("fields", {}).items()}
    return None


def _error_code(resp):
    try:
        return resp.json().get("error", {}).get("message", "") or resp.json().get("error", {}).get("status", "")
    except ValueError:
        return resp.text[:200]


class FirebaseUploader:

    def __init__(self, email, password):
        cfg = load_config()
        self.api_key   = cfg["web_api_key"]
        self.base      = FIRESTORE.format(project=cfg["project_id"])
        self.pending   = []
        self.revoked   = False
        self._sign_in(email, password)
        profile = self._get(f"users/{self.uid}")
        if profile is None:
            raise UploaderError("This account has no TwinGuard operator profile. Ask the admin to create it in the dashboard.")
        if not profile.get("enabled"):
            raise UploaderError("This operator account is disabled by the admin.")
        self.username = profile.get("username", email)

    # ── Auth ──────────────────────────────────────────────────────────────────
    def _sign_in(self, email, password):
        try:
            r = requests.post(SIGN_IN_URL, params={"key": self.api_key}, timeout=10,
                              json={"email": email, "password": password, "returnSecureToken": True})
        except requests.RequestException as e:
            raise UploaderError(f"Cannot reach Firebase: {e}")
        if r.status_code != 200:
            code = _error_code(r)
            if code.startswith("USER_DISABLED"):
                raise UploaderError("This operator account is disabled by the admin.")
            raise UploaderError(f"Sign-in failed ({code or r.status_code}).")
        d = r.json()
        self.uid           = d["localId"]
        self.id_token      = d["idToken"]
        self.refresh_token = d["refreshToken"]
        self.expires_at    = time.time() + int(d.get("expiresIn", 3600)) - 120

    def _token(self):
        if time.time() < self.expires_at:
            return self.id_token
        r = requests.post(REFRESH_URL, params={"key": self.api_key}, timeout=10,
                          data={"grant_type": "refresh_token", "refresh_token": self.refresh_token})
        if r.status_code != 200:
            code = _error_code(r)
            if code.startswith(("USER_DISABLED", "TOKEN_EXPIRED", "USER_NOT_FOUND", "INVALID_REFRESH_TOKEN")):
                self.revoked = True
                raise UploaderError("Session revoked: this operator was disabled or removed by the admin.")
            raise UploaderError(f"Token refresh failed ({code or r.status_code}).")
        d = r.json()
        self.id_token      = d["id_token"]
        self.refresh_token = d["refresh_token"]
        self.expires_at    = time.time() + int(d.get("expires_in", 3600)) - 120
        return self.id_token

    # ── Firestore ─────────────────────────────────────────────────────────────
    def _headers(self):
        return {"Authorization": f"Bearer {self._token()}"}

    def _get(self, path):
        r = requests.get(f"{self.base}/{path}", headers=self._headers(), timeout=10)
        if r.status_code == 404:
            return None
        if r.status_code != 200:
            raise UploaderError(f"Firestore read failed ({_error_code(r) or r.status_code}).")
        return {k: decode_value(v) for k, v in r.json().get("fields", {}).items()}

    def _create_alert(self, alert):
        # The SHA-256 seal is the document id, so a retried upload can never duplicate an alert.
        r = requests.post(f"{self.base}/alerts", params={"documentId": alert["sha256_hash"]},
                          headers=self._headers(), timeout=10,
                          json={"fields": {k: encode_value(v) for k, v in alert.items()}})
        if r.status_code == 409:      # already uploaded by an earlier attempt
            return
        if r.status_code == 403:
            raise UploaderError("Firestore denied the write (account disabled, or security rules not published).")
        if r.status_code != 200:
            raise UploaderError(f"Firestore write failed ({_error_code(r) or r.status_code}).")

    def upload(self, alert):
        """Upload an alert; on failure it is kept and retried with the next one."""
        if self.revoked:
            return
        if len(self.pending) < MAX_PENDING:
            self.pending.append(alert)
        while self.pending:
            try:
                self._create_alert(self.pending[0])
            except (UploaderError, requests.RequestException) as e:
                print(f"[Firebase] Upload deferred ({len(self.pending)} pending): {e}")
                return
            self.pending.pop(0)
        print("[Firebase] ✓ Alert uploaded.")
