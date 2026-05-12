#!/usr/bin/env python3

import os
import time
import json
import hashlib
import datetime
import requests

from collections import defaultdict
from scanner import scan_networks

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = MAGENTA = ""
    class Style:
        BRIGHT = RESET_ALL = ""


# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

DASHBOARD_URL = "http://127.0.0.1:5000/api/alert"

LOG_FILE = "forensic_log.json"

INTERFACE = "wlan0mon"

SCAN_INTERVAL = 10
SCAN_DURATION = 8


# ─────────────────────────────────────────────
# FORENSIC LOGGER
# ─────────────────────────────────────────────

class ForensicLogger:

    def __init__(self, log_file):
        self.log_file = log_file
        self.entries = []

        if os.path.exists(log_file):
            try:
                with open(log_file, "r") as f:
                    self.entries = json.load(f)
            except:
                self.entries = []

    def _hash(self, data):
        raw = json.dumps(data, sort_keys=True).encode()
        return hashlib.sha256(raw).hexdigest()

    def log(self, event):
        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            **event
        }

        entry["sha256_hash"] = self._hash(entry)

        self.entries.append(entry)

        with open(self.log_file, "w") as f:
            json.dump(self.entries, f, indent=2)

        return entry


# ─────────────────────────────────────────────
# DETECTION ENGINE
# ─────────────────────────────────────────────

class DetectionEngine:

    def __init__(self, logger):
        self.logger = logger
        self.alert_callbacks = []
        self.known_bssids = defaultdict(set)

    def on_alert(self, callback):
        self.alert_callbacks.append(callback)

    def _notify(self, alert):
        for cb in self.alert_callbacks:
            try:
                cb(alert)
            except:
                pass

    def _scan(self):
        return scan_networks(
            interface=INTERFACE,
            duration=SCAN_DURATION
        )

    # ─────────────────────────────────────────────
    # SCORING SYSTEM
    # ─────────────────────────────────────────────

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

            # baseline learning
            if len(aps) == 1:
                self.known_bssids[ssid].add(aps[0].get("bssid", ""))
                continue

            known = self.known_bssids.get(ssid, set())

            for ap in aps:

                score = 0
                reasons = []

                bssid = ap.get("bssid", "")
                signal = ap.get("signal", -100)
                channel = ap.get("channel")
                encryption = ap.get("encryption", "Unknown")

                # 1. unknown BSSID
                if known and bssid not in known:
                    score += 2
                    reasons.append("Unknown BSSID")

                # 2. open encryption
                if encryption.lower() == "open":
                    score += 2
                    reasons.append("Open encryption")

                # 3. multiple APs with same SSID
                if len(aps) > 1:
                    score += 1
                    reasons.append("Multiple APs with same SSID")

                # 4. signal deviation (soft anomaly)
                avg_signal = sum(n.get("signal", -100) for n in aps) / len(aps)

                if signal > avg_signal + 20:
                    score += 1
                    reasons.append("Signal anomaly")

                # 5. channel mismatch
                legit_channels = {
                    x.get("channel")
                    for x in aps
                    if x.get("bssid") in known
                }

                if legit_channels and channel not in legit_channels:
                    score += 1
                    reasons.append("Channel mismatch")

                # ─────────────────────────────────────
                # FINAL DECISION
                # ─────────────────────────────────────
                if score >= 3:

                    alert = {
                        "type": "ROGUE_AP_DETECTED",
                        "severity": self._severity(score),
                        "score": score,
                        "ssid": ssid,
                        "bssid": bssid,
                        "signal_dbm": signal,
                        "channel": channel,
                        "encryption": encryption,
                        "trusted_bssids": list(known),
                        "reasons": reasons,
                        "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
                    }

                    logged = self.logger.log(alert)
                    alerts.append(logged)
                    self._notify(logged)

        return alerts

    # ─────────────────────────────────────────────
    # RUN LOOP
    # ─────────────────────────────────────────────

    def run(self):

        print(f"\n{Fore.CYAN}{Style.BRIGHT}")
        print("════════════════════════════════════════════")
        print(" TwinGuard-SHA256 — Detection Engine")
        print(f" Interface : {INTERFACE}")
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

                color = Fore.RED if signal > -70 else Fore.GREEN

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


# ─────────────────────────────────────────────
# DASHBOARD HOOK
# ─────────────────────────────────────────────

def send_to_dashboard(alert):
    try:
        requests.post(DASHBOARD_URL, json=alert, timeout=2)
    except:
        pass


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":

    if os.geteuid() != 0:
        print(f"{Fore.RED}[ERROR] Run with sudo.")
        exit(1)

    if not os.path.exists(f"/sys/class/net/{INTERFACE}"):
        print(f"{Fore.RED}[ERROR] Interface not found: {INTERFACE}")
        exit(1)

    logger = ForensicLogger(LOG_FILE)
    engine = DetectionEngine(logger)

    engine.on_alert(send_to_dashboard)

    try:
        engine.run()

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[✓] TwinGuard stopped.")
        