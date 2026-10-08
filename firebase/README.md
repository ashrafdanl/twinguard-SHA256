# TwinGuard-SHA256 — Firebase setup (free Spark plan)

TwinGuard stores accounts and alerts in Firebase using **only free Spark-plan
features**: Firebase Authentication (email/password) and Cloud Firestore.
No billing account, Blaze plan, Cloud Functions, Storage or paid add-ons are
needed. If the console ever asks you to upgrade or add a card, you've clicked
something TwinGuard doesn't use.

| What | Where it lives |
|---|---|
| Super admin (one) | Firebase Authentication (+ `admin` custom claim) + `admins/{uid}` in Firestore |
| Operator accounts | Firebase Authentication + `users/{uid}` in Firestore |
| Detections (every severity) | `users/{uid}/detections/{sha256}`, each operator's own space; the dashboard shows the HIGH ones |
| Retention setting | `twinguard_config.json` on the dashboard machine |

## 1. Create the project (one time)

1. Go to <https://console.firebase.google.com> → **Create a project**.
   Google Analytics is not needed; you can turn it off.
   New projects start on the free **Spark** plan; leave it there.
2. **Build → Authentication → Get started → Sign-in method → Email/Password → Enable → Save.**
   Leave "Email link (passwordless)" off.
3. **Build → Firestore Database → Create database**
   - Location: **asia-southeast1 (Singapore)**, closest to Kuala Lumpur (cannot be changed later)
   - Start in **production mode**
4. **Firestore → Rules**: replace everything with the contents of
   [`firestore.rules`](firestore.rules) → **Publish**.
5. **Firestore → Indexes → Composite → Create index** twice, collection `alerts`:
   - `uid` Ascending, `timestamp` Descending
   - `uid` Ascending, `severity` Ascending, `timestamp` Descending

   (Same as [`firestore.indexes.json`](firestore.indexes.json). If you skip this,
   the app's first query fails with an error containing a link that creates it.)

## 2. Connect the dashboard and detector

1. **Project settings (gear icon) → General** → copy the **Project ID** and **Web API Key**.
   If no Web API Key is shown, add a Web app under "Your apps" first (free).
2. In the project root, copy `firebase_config.example.json` to `firebase_config.json`
   and fill in both values.
3. **Dashboard machine only:** Project settings → **Service accounts → Generate new
   private key**. Save the file as `firebase-service-account.json` in the project root.
   - This key has full admin access. **Never commit it, share it, or copy it to
     detector machines or phones.** It is already in `.gitignore`.
4. `pip install -r requirements.txt` (adds `firebase-admin`, Apache-2.0 open source).

## 3. Run

```bash
# Dashboard (admin's machine). Plain HTTP by default
python3 dashboard/dashboard_server.py
# Encrypted HTTPS instead (recommended on shared Wi-Fi); see "Admin dashboard security"
python3 dashboard/dashboard_server.py --https
```

Open <http://127.0.0.1:5000> (or `https://` with `--https`) **on that machine**. The first visit creates the admin
account in Firebase and sets up two-factor authentication. After that, add operators
under **User Management**. The email and password you set there are what the
operator uses in the phone app and on the detector.

```bash
# Detection engine, signed in as an operator (asks for their password)
sudo .venv/bin/python detection/detection.py --email ali@example.com
# or both together
python3 run/run.py --email ali@example.com
```

The detector needs only `firebase_config.json` (project ID + Web API key), not
the service account key. It signs in **as the operator**, so the security rules
only let it upload that operator's alerts. When the admin disables the operator,
uploads stop and the app signs them out.

Without `--email` the detector still runs, but alerts only go to the local
`forensic_log.json` and never reach the dashboard or app.

Options:

| Option | Use |
|---|---|
| `--interface NAME` | Monitor-mode Wi-Fi interface (default `wlan0`, or `$TWINGUARD_INTERFACE`). On a Raspberry Pi the USB adapter is usually `wlan1`; the built-in chip can't do monitor mode. |
| `--simulate` | No adapter needed: feeds realistic scans with occasional evil twins (HIGH and MEDIUM) through the real detection logic. Alerts carry `"simulated": true` inside their SHA-256 seal, show a **SIM** badge on the dashboard and a "SIMULATED" banner on Telegram, and are logged locally to `forensic_log_simulated.json`. No sudo needed. |

```bash
# Demo the whole pipeline without hardware
.venv/bin/python detection/detection.py --simulate --email lily@gmail.com
# Raspberry Pi with a USB adapter
sudo .venv/bin/python detection/detection.py --interface wlan1 --email lily@gmail.com
```

## 4. Phone app integration

The phone app **scans**, saves **every** detection in the operator's own space, and
only the **critical (HIGH)** ones appear on the admin dashboard. The app never talks
to the dashboard directly; both use Firebase.

```
Phone app (signed in as the operator)
   │  every detection, sealed with SHA-256
   ▼
users/{uid}/detections/{sha256}    ← operator's own space (HIGH, MEDIUM, LOW)
users/{uid}/scans/{auto-id}        ← full scan results (all networks), private to the user
   │  dashboard listens only to severity == "HIGH" (all operators)
   ▼
Admin dashboard: critical alerts in full + severity counts of everything
```

Use the free Firebase SDK for your platform (Android, iOS, Flutter…) with this project.

### 1. Sign in
Firebase Auth email/password with the credentials the admin created under
**User Management**. Every user added there *is* an app login, and their space
`users/{uid}/…` appears automatically the first time the app saves something. A disabled account fails with `user-disabled`: show
"Your account has been disabled by the administrator".

### 2. Build a detection

| Field | Type | Example |
|---|---|---|
| `uid` | string | `FirebaseAuth.currentUser.uid` |
| `username` | string | from `users/{uid}`: **must equal the profile's `username`** |
| `severity` | string | `"HIGH"` \| `"MEDIUM"` \| `"LOW"` (HIGH = critical, goes to the dashboard) |
| `timestamp` | string | UTC ISO-8601 with `Z`, e.g. `"2026-10-08T10:15:30Z"` |
| `ssid`, `bssid`, `encryption` | string | `"GMI-Student"`, `"AA:BB:CC:DD:EE:FF"`, `"OPN"` |
| `signal_dbm`, `channel`, `score` | **integer** | `-40`, `6`, `7` (no decimals) |
| `reasons` | array of strings | `["Unknown BSSID", "Open encryption"]` |
| `source` | string | `"app"` (optional, recommended) |

Use **integers, not decimals**, anywhere you have numbers, so every platform hashes them identically.

### 3. Seal it (SHA-256)
1. Take all fields above (**not** `sha256_hash`).
2. Serialize as JSON with **keys sorted alphabetically** (also inside nested objects),
   **no spaces**, and text as **UTF-8** (don't escape non-English characters as `\uXXXX`).
   ```
   {"bssid":"AA:BB:CC:DD:EE:FF","channel":6,"encryption":"OPN","reasons":["Unknown BSSID"],"severity":"HIGH",...}
   ```
3. `sha256_hash` = lowercase hex SHA-256 of those UTF-8 bytes. Add it to the detection.

The dashboard recomputes this and shows **✓ VALID** or **✗ TAMPERED**.

### 4. Save it in the operator's space
Write to `users/{uid}/detections/{sha256_hash}`, using the **hash as the document id**
and `set()`/`create()`, not `add()`. Retrying the same detection never duplicates it.
The security rules reject writes to anyone else's space, unsealed or malformed
detections, and any edit or delete.

**Flutter (Dart)**
```dart
import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:firebase_auth/firebase_auth.dart';

dynamic _sorted(dynamic v) => v is Map
    ? Map.fromEntries((v.keys.toList()..sort()).map((k) => MapEntry(k, _sorted(v[k]))))
    : v is List ? v.map(_sorted).toList() : v;

Future<void> saveDetection(Map<String, dynamic> d, String username) async {
  final uid = FirebaseAuth.instance.currentUser!.uid;
  d = {...d, 'uid': uid, 'username': username, 'source': 'app',
       'timestamp': DateTime.now().toUtc().toIso8601String().split('.').first + 'Z'};
  final hash = sha256.convert(utf8.encode(jsonEncode(_sorted(d)))).toString();
  await FirebaseFirestore.instance
      .doc('users/$uid/detections/$hash').set({...d, 'sha256_hash': hash});
}
```

**Android (Kotlin)**
```kotlin
fun canonical(v: Any?): String = when (v) {
    is Map<*, *> -> v.keys.map { it.toString() }.sorted()
        .joinToString(",", "{", "}") { k -> JSONObject.quote(k) + ":" + canonical(v[k]) }
    is List<*> -> v.joinToString(",", "[", "]") { canonical(it) }
    is String -> JSONObject.quote(v).replace("\\/", "/")
    null -> "null"
    else -> v.toString()           // Int / Long / Boolean
}

fun saveDetection(d: Map<String, Any>, username: String) {
    val uid = FirebaseAuth.getInstance().currentUser!!.uid
    val doc = d + mapOf("uid" to uid, "username" to username, "source" to "app",
        "timestamp" to Instant.now().truncatedTo(ChronoUnit.SECONDS).toString())
    val hash = MessageDigest.getInstance("SHA-256").digest(canonical(doc).toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
    Firebase.firestore.document("users/$uid/detections/$hash").set(doc + ("sha256_hash" to hash))
}
```

### 5. Save full scan results (optional, everything the app saw)
Each user's space also has `users/{uid}/scans/`, for complete scans including normal
networks. Use an auto-generated document id (`add()`):

```
users/{uid}/scans/{auto-id} = {
  "uid": "<uid>", "timestamp": "2026-10-08T10:15:30Z", "source": "app",
  "networks": [ {"ssid": "GMI-Student", "bssid": "A4:2B:B0:11:22:01", "signal_dbm": -61,
                 "channel": 6, "encryption": "WPA2"}, ... ]        // up to 300 networks
}
```
Only that user can read or write their scans, nobody can edit or delete them, and the
admin dashboard doesn't read them.

**Free quota:** each saved scan is 1 write, and the free plan allows **20,000 writes/day for
the whole project**. Saving a scan every 10 s uses 8,640 writes/day *per phone*. Save a
scan every few minutes, or only when the list of networks changes.

### 6. Show the operator's own history
```
collection("users/{uid}/detections").orderBy("timestamp", descending)             // everything
collection("users/{uid}/detections").where("severity","==","HIGH").orderBy(...)   // critical only
```
Use a realtime listener (`snapshots()` / `addSnapshotListener`). It downloads only new
detections, which keeps you inside the free read quota. Detections marked
`"simulated": true` come from the detector's `--simulate` test mode; label them "TEST".

### Indexes needed (one-time, Firebase console → Firestore → Indexes)
- **Single field → Add exemption:** collection `detections`, field `severity`, enable **Collection group, Ascending**
- **Single field → Add exemption:** collection `detections`, field `timestamp`, enable **Collection group, Ascending**
- **Composite:** collection `detections`, `severity` Ascending + `timestamp` Descending

## Free-tier limits (Spark)

| Resource | Free per day | TwinGuard usage |
|---|---|---|
| Firestore reads | 50,000 | dashboard: all alerts once at start, then 1 per new alert; app: same per phone |
| Firestore writes | 20,000 | 1 per alert |
| Firestore deletes | 20,000 | retention purge, hourly |
| Stored data | 1 GiB | each alert is ~1 KB |
| Auth (email/password) | 50,000 monthly active users | one per operator |

If a quota runs out, Firestore stops serving requests until it resets the next
day (Pacific time). Nothing is charged on the Spark plan.

## Admin dashboard security

The dashboard is built to be opened from devices on the same LAN. Everything below
is free and open source (cheroot, pyotp, qrcode, cryptography).

| Protection | What it does |
|---|---|
| HTTPS with `--https` (TLS 1.2+) | Traffic can't be read or altered on the network. **Without `--https` the dashboard uses plain HTTP: passwords and session cookies cross the network unencrypted** |
| Private certificate authority | With `--https`, certificates are created/updated automatically for this machine's IPs; devices that install `certs/twinguard-ca.crt` get a padlock, no warnings |
| Two-factor login | Firebase password **and** a 6-digit authenticator-app code; codes can't be reused |
| 2FA setup only on the dashboard machine | A stolen password can't be used to enrol the attacker's phone |
| Brute-force lockout | 5 wrong passwords/codes from an IP → locked for 5 minutes |
| Session limits | Logged out after 30 min idle or 8 h total, and when the admin is disabled or their password reset in Firebase |
| CSRF tokens | Other websites can't make your browser perform dashboard actions |
| Content-Security-Policy (nonces) | Injected scripts can't run, even if an XSS bug slipped in |
| Cookies | Not readable by JavaScript, never sent cross-site; with `--https` also a Secure `__Host-` cookie |
| Trusted hosts | Requests addressed to any other host name are rejected |
| Security headers | HSTS, no framing (clickjacking), no MIME sniffing, no referrer, no caching of pages |

### Install the CA certificate on each admin device (once)

Copy `certs/twinguard-ca.crt` to the device (USB, email to yourself…). It is safe to
share. **Never** copy `certs/twinguard-ca.key` or `certs/server.key` anywhere.

- **Windows:** double-click the file → *Install Certificate* → *Local Machine* →
  *Place all certificates in the following store* → **Trusted Root Certification Authorities**.
- **macOS:** double-click → Keychain Access → open the certificate → *Trust* →
  *When using this certificate:* **Always Trust**.
- **Android:** Settings → Security → *Encryption & credentials* → *Install a certificate* →
  **CA certificate**.
- **iPhone/iPad:** open the file → Settings → *Profile Downloaded* → Install; then
  Settings → General → About → *Certificate Trust Settings* → turn it on.
- **Linux / Kali (Chrome/Chromium):** `sudo cp certs/twinguard-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates`,
  then in Chrome: Settings → Privacy and security → Security → Manage certificates → Authorities → Import.
- **Firefox (any OS):** Settings → Privacy & Security → Certificates → *View Certificates* →
  Authorities → Import → tick *Trust this CA to identify websites*.

Then open `https://<dashboard IP>:5000` (the dashboard prints the exact addresses at startup).
Installing the CA is only needed when you run with `--https`.

### Opening the dashboard from other devices

Other devices must be able to reach the VM. With VMware's default **NAT** network the VM has a
private `192.168.x.x` address only the host laptop can reach. Either:

- **Bridged networking:** VM → Settings → Network Adapter → *Bridged*. The VM gets an address on
  your Wi-Fi; the dashboard prints it at startup. (In VMware Player, use *Configure Adapters* to
  tick only your Wi-Fi adapter.)
- **NAT port forwarding:** forward host port 5000 to the VM's port 5000 in VMware's NAT settings,
  allow port 5000 in the host's firewall, and start the dashboard with
  `--allow-host <laptop Wi-Fi IP>` so requests addressed to the laptop are accepted.

Some campus/hotel Wi-Fi blocks device-to-device traffic ("client isolation"); a phone hotspot
avoids that.

### Two-factor authentication

- First login on the dashboard machine shows a QR code. Scan it with any authenticator
  app (Google Authenticator, Microsoft Authenticator, Aegis, 2FAS) and enter the code.
- After that, every login asks for the password, then the current 6-digit code.
- **Lost the phone?** Firebase console → Firestore → `admins` → your uid → delete the
  `totp_secret` field, then log in on the dashboard machine itself to set up 2FA again.
  Only someone with your Firebase console access can do this.

### One super admin

The dashboard has exactly **one administrator**, the super admin created on first run.
There are no other admin accounts; everyone else is an **application user** (operator)
created under **User Management**, who signs in to the phone app and detector.

### Optional: firewall

Allow the dashboard port only from your LAN, for example with ufw:

```bash
sudo ufw allow from 192.168.184.0/24 to any port 5000 proto tcp
sudo ufw enable
```

