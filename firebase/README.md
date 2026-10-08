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
| Sealed alerts | `alerts/{sha256}` in Firestore |
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

Use the free Firebase SDK for your app's platform (Android, iOS, Flutter, React Native…)
with the same Firebase project.

1. **Sign in** with Firebase Auth email/password, using the credentials the admin created.
   A disabled account fails with `user-disabled`; show "Your account has been
   disabled by the administrator".
2. **Read the operator's alerts**. The query **must** filter by the signed-in uid
   or the security rules reject it:

   ```
   collection("alerts")
     .where("uid", "==", currentUser.uid)
     .where("severity", "==", "HIGH")      // optional: dashboard shows HIGH only
     .orderBy("timestamp", "desc")
   ```

   Use a realtime listener (`onSnapshot` / `snapshots()`), not polling. It only
   downloads new alerts, which keeps you inside the free read quota.
3. **Profile**: `users/{currentUser.uid}` has `username`, `full_name`, `email`, `enabled`.

Alert fields: `timestamp` (UTC ISO text; show it in GMT+8), `severity`, `ssid`,
`bssid`, `signal_dbm`, `channel`, `encryption`, `reasons` (list), `score`,
`trusted_bssids`, `uid`, `username`, `sha256_hash`, and `simulated: true` on test
alerts from `--simulate` (absent on real ones). Show those with a "TEST" label.

Apps cannot edit or delete alerts. The rules forbid it, which preserves the evidence.

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

