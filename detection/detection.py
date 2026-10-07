#!/usr/bin/env python3
"""
TwinGuard-SHA256 — Detection Engine  (with Telegram real-time alerts)
=====================================================================
Changes vs original:
  • Imports TelegramNotifier and registers it as an alert callback.
  • Sends a startup / shutdown ping to Telegram.
  • All original detection logic is unchanged.
"""

import os
import time
import argparse
import getpass
import json
import hashlib
import datetime

from collections import defaultdict
from scanner import scan_networks
from firebase_uploader import FirebaseUploader, UploaderError

# ── NEW: Telegram notifier ────────────────────────────────────────────────────
try:
    from telegram_notifier import TelegramNotifier
    _telegram_available = True
except ImportError:
    _telegram_available = False
    print("[WARNING] telegram_notifier.py not found — Telegram alerts disabled.")
# ─────────────────────────────────────────────────────────────────────────────

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = MAGENTA = ""
    class Style:
        BRIGHT = RESET_ALL = ""


# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────

LOG_FILE        = "forensic_log.json"
INTERFACE       = "wlan0"
SCAN_INTERVAL   = 10
SCAN_DURATION   = 8

# Operator this engine reports for: their TwinGuard (Firebase) email, set with
# --email or TWINGUARD_EMAIL. The engine signs in as that operator and uploads
# alerts to Firebase, tagged with their uid so the dashboard and their phone
# app show them in that operator's log.
OPERATOR_EMAIL  = os.getenv("TWINGUARD_EMAIL", "").strip()
OPERATOR_FIELDS = {}   # {"uid": ..., "username": ...} once signed in

# Telegram — can also be set as env vars (see telegram_notifier.py)
# Leave as empty string to use values from telegram_notifier.py / env vars.
TELEGRAM_TOKEN   = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID",   "")
TG_MIN_SEVERITY  = os.getenv("TG_MIN_SEVERITY", "LOW")   # LOW | MEDIUM | HIGH


# ─────────────────────────────────────────────────────────────────────────────
# FORENSIC LOGGER  (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

class ForensicLogger:

    def __init__(self, log_file):
        self.log_file = log_file
        self.entries  = []

        if os.path.exists(log_file):
            try:
                with open(log_file, "r") as f:
                    self.entries = json.load(f)
            except Exception:
                self.entries = []

    def _hash(self, data):
        raw = json.dumps(data, sort_keys=True).encode()
        return hashlib.sha256(raw).hexdigest()

    def log(self, event):
        entry = {"timestamp": datetime.datetime.utcnow().isoformat() + "Z", **event}
        entry["sha256_hash"] = self._hash(entry)
        self.entries.append(entry)
        with open(self.log_file, "w") as f:
            json.dump(self.entries, f, indent=2)
        return entry


# ─────────────────────────────────────────────────────────────────────────────
# DETECTION ENGINE  (unchanged logic, Telegram callback added at startup)
# ─────────────────────────────────────────────────────────────────────────────

class DetectionEngine:

    def __init__(self, logger):
        self.logger           = logger
        self.alert_callbacks  = []
        self.known_bssids     = defaultdict(set)

    def on_alert(self, callback):
        self.alert_callbacks.append(callback)

    def _notify(self, alert):
        for cb in self.alert_callbacks:
            try:
                cb(alert)
            except Exception as exc:
                print(f"[DetectionEngine] Callback error: {exc}")

    def _scan(self):
        return scan_networks(interface=INTERFACE, duration=SCAN_DURATION)

    # ── Scoring ───────────────────────────────────────────────────────────────

    def _severity(self, score):
        if score >= 6:
            return "HIGH"
        elif score >= 3:
            return "MEDIUM"
        return "LOW"

    def analyze(self, networks):
        grouped = defaultdict(list)
        for net in networks:
            ssid = net.get("ssid", "").strip()
            if ssid:
                grouped[ssid].append(net)

        alerts = []

        for ssid, aps in grouped.items():

            if len(aps) == 1:
                self.known_bssids[ssid].add(aps[0].get("bssid", ""))
                continue

            known = self.known_bssids.get(ssid, set())

            for ap in aps:
                score   = 0
                reasons = []

                bssid      = ap.get("bssid", "")
                signal     = ap.get("signal", -100)
                channel    = ap.get("channel")
                encryption = ap.get("encryption", "Unknown")

                if known and bssid not in known:
                    score += 2
                    reasons.append("Unknown BSSID")

                if encryption.lower() == "open":
                    score += 2
                    reasons.append("Open encryption")

                if len(aps) > 1:
                    score += 1
                    reasons.append("Multiple APs with same SSID")

                avg_signal = sum(n.get("signal", -100) for n in aps) / len(aps)
                if signal > avg_signal + 20:
                    score += 1
                    reasons.append("Signal anomaly")

                legit_channels = {
                    x.get("channel")
                    for x in aps
                    if x.get("bssid") in known
                }
                if legit_channels and channel not in legit_channels:
                    score += 1
                    reasons.append("Channel mismatch")

                if score >= 3:
                    alert = {
                        "type":          "ROGUE_AP_DETECTED",
                        "severity":      self._severity(score),
                        "score":         score,
                        "ssid":          ssid,
                        "bssid":         bssid,
                        "signal_dbm":    signal,
                        "channel":       channel,
                        "encryption":    encryption,
                        "trusted_bssids": list(known),
                        "reasons":       reasons,
                        "timestamp":     datetime.datetime.utcnow().isoformat() + "Z",
                    }
                    alert.update(OPERATOR_FIELDS)  # inside the SHA-256 seal
                    logged = self.logger.log(alert)
                    alerts.append(logged)
                    self._notify(logged)  # ← triggers all callbacks incl. Telegram

        return alerts

    # ── Run loop ──────────────────────────────────────────────────────────────

    def run(self):
        print(f"\n{Fore.CYAN}{Style.BRIGHT}")
        print("════════════════════════════════════════════")
        print(" TwinGuard-SHA256 — Detection Engine")
        print(f" Interface : {INTERFACE}")
        print(f" Operator  : {OPERATOR_FIELDS.get('username') or '(none - local log only)'}")
        print("════════════════════════════════════════════\n")

        scan_count = 0

        while True:
            scan_count += 1
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            print(f"{Fore.WHITE}[{ts}] Scan #{scan_count}")

            networks = self._scan()
            print(f"{Fore.CYAN}Found {len(networks)} networks\n")

            for net in networks:
                signal = net.get("signal", -100)
                color  = Fore.RED if signal > -70 else Fore.GREEN
                print(
                    f"{color}● "
                    f"{net.get('ssid','?'):<24} "
                    f"BSSID={net.get('bssid','?')}  "
                    f"CH={net.get('channel','?')}  "
                    f"SIG={signal} dBm  "
                    f"ENC={net.get('encryption','?')}"
                )

            alerts = self.analyze(networks)

            if alerts:
                print(f"\n{Fore.RED}{Style.BRIGHT}⚠ {len(alerts)} THREATS DETECTED!\n")
                for a in alerts:
                    print(f"{Fore.RED}┌─ [{a['severity']}] ALERT")
                    print(f"│  SSID    : {a['ssid']}")
                    print(f"│  BSSID   : {a['bssid']}")
                    print(f"│  SCORE   : {a['score']}")
                    print(f"│  SIGNAL  : {a['signal_dbm']} dBm")
                    print(f"│  CHANNEL : {a['channel']}")
                    print(f"│  REASONS : {', '.join(a['reasons'])}")
                    print(f"│  SHA256  : {a['sha256_hash'][:32]}...")
                    print(f"└─ {a['timestamp']}\n")
            else:
                print(f"\n{Fore.GREEN}✓ No threats detected\n")

            time.sleep(SCAN_INTERVAL)


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="TwinGuard-SHA256 detection engine")
    parser.add_argument("--email", default=OPERATOR_EMAIL,
                        help="operator's TwinGuard sign-in email (default: $TWINGUARD_EMAIL)")
    OPERATOR_EMAIL = parser.parse_args().email.strip()

    if os.geteuid() != 0:
        print(f"{Fore.RED}[ERROR] Run with sudo.")
        exit(1)

    if not os.path.exists(f"/sys/class/net/{INTERFACE}"):
        print(f"{Fore.RED}[ERROR] Interface not found: {INTERFACE}")
        exit(1)

    logger = ForensicLogger(LOG_FILE)
    engine = DetectionEngine(logger)

    # ── Callback: upload to Firebase as the signed-in operator ───────────────
    if OPERATOR_EMAIL:
        password = os.getenv("TWINGUARD_PASSWORD") or getpass.getpass(f"Password for {OPERATOR_EMAIL}: ")
        try:
            uploader = FirebaseUploader(OPERATOR_EMAIL, password)
        except UploaderError as e:
            print(f"{Fore.RED}[Firebase] {e}")
            exit(1)
        OPERATOR_FIELDS.update(uid=uploader.uid, username=uploader.username)
        engine.on_alert(uploader.upload)
        print(f"{Fore.GREEN}[Firebase] ✓ Signed in as {uploader.username} — alerts go to the dashboard and app.")
    else:
        print(f"{Fore.YELLOW}[Firebase] No --email given: alerts are saved to {LOG_FILE} only "
              f"and will NOT appear on the dashboard or app.")

    # ── NEW callback: Telegram real-time alerts ───────────────────────────────
    telegram = None
    if _telegram_available:
        try:
            kwargs = {"min_severity": TG_MIN_SEVERITY}
            if TELEGRAM_TOKEN:
                kwargs["token"] = TELEGRAM_TOKEN
            if TELEGRAM_CHAT_ID:
                kwargs["chat_id"] = TELEGRAM_CHAT_ID

            telegram = TelegramNotifier(**kwargs)
            engine.on_alert(telegram.send_alert)

            print(f"{Fore.CYAN}[Telegram] Notifier registered — min severity: {TG_MIN_SEVERITY}")
            telegram.send_startup_message()
            print(f"{Fore.GREEN}[Telegram] ✓ Startup ping sent.")

        except ValueError as e:
            print(f"{Fore.YELLOW}[Telegram] Skipped — {e}")
    # ─────────────────────────────────────────────────────────────────────────

    try:
        engine.run()

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[✓] TwinGuard stopped.")
        if telegram:
            telegram.send_shutdown_message()
            print(f"{Fore.YELLOW}[Telegram] Shutdown ping sent.")
