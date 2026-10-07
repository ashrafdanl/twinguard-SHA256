# TwinGuard-SHA256 — Firebase setup (free Spark plan)

TwinGuard stores accounts and alerts in Firebase using **only free Spark-plan
features**: Firebase Authentication (email/password) and Cloud Firestore.
No billing account, Blaze plan, Cloud Functions, Storage or paid add-ons are
needed. If the console ever asks you to upgrade or add a card, you've clicked
something TwinGuard doesn't use.

| What | Where it lives |
|---|---|
| Admin account | Firebase Authentication (+ `admin` custom claim) |
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
# Dashboard (admin's machine)
python3 dashboard/dashboard_server.py
```

Open <http://127.0.0.1:5000> **on that machine**. The first visit creates the admin
account in Firebase. After that, add operators under **User Management**. The email
and password you set there are what the operator uses in the phone app and on
the detector.

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
`trusted_bssids`, `uid`, `username`, `sha256_hash`.

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
