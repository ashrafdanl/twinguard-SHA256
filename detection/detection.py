#!/usr/bin/env python3
"""
TwinGuard-SHA256: Rogue AP Detection Engine
============================================
Scans nearby Wi-Fi networks, detects Evil Twin / Rogue AP attacks,
logs forensic evidence with SHA-256 hashing, and sends real-time
alerts to the TwinGuard Dashboard.

Requirements (install first):
    pip install scapy requests colorama

Run with sudo:
    sudo python3 detector.py
"""

import os
import time
import json
import hashlib
import datetime
import threading
import subprocess
import requests
from collections import defaultdict

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = MAGENTA = ""
    class Style:
        BRIGHT = RESET_ALL = ""

# ─── Configuration ────────────────────────────────────────────────────────────
DASHBOARD_URL  = "http://127.0.0.1:5000/api/alert"
LOG_FILE       = "forensic_log.json"
SCAN_INTERVAL  = 10        # seconds between scans
RSSI_THRESHOLD = -49       # dBm — signals stronger than this are suspicious
INTERFACE      = "wlan0"   # change to your monitor-mode interface (e.g. wlan1mon)
USE_SCAPY      = False     # Set True if running as root with a monitor-mode adapter
                           # Set False to use iwlist scan (works on most laptops)

# ─── Forensic Logger ──────────────────────────────────────────────────────────
class ForensicLogger:
    def __init__(self, log_file: str):
        self.log_file = log_file
        self.entries = []
        if os.path.exists(log_file):
            with open(log_file) as f:
                try:
                    self.entries = json.load(f)
                except json.JSONDecodeError:
                    self.entries = []

    def _sha256(self, data: dict) -> str:
        raw = json.dumps(data, sort_keys=True).encode()
        return hashlib.sha256(raw).hexdigest()

    def log(self, event: dict) -> dict:
        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            **event,
        }
        entry["sha256_hash"] = self._sha256(entry)
        self.entries.append(entry)
        with open(self.log_file, "w") as f:
            json.dump(self.entries, f, indent=2)
        return entry

    def get_all(self):
        return self.entries


# ─── Wi-Fi Scanner (iwlist fallback — no root / monitor mode needed) ──────────
def scan_with_iwlist(interface: str) -> list[dict]:
    """
    Uses `iwlist scan` — works on standard Ubuntu/Kali with a regular adapter.
    Returns list of dicts: {ssid, bssid, signal, encryption, channel}
    """
    networks = []
    try:
        result = subprocess.run(
            ["sudo", "iwlist", interface, "scan"],
            capture_output=True, text=True, timeout=15
        )
        raw = result.stdout
    except Exception as e:
        print(f"{Fore.RED}[ERROR] iwlist scan failed: {e}")
        return networks

    current = {}
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("Cell "):
            if current:
                networks.append(current)
            current = {}
            # Extract BSSID
            parts = line.split("Address:")
            if len(parts) > 1:
                current["bssid"] = parts[1].strip()
        elif "ESSID:" in line:
            current["ssid"] = line.split('"')[1] if '"' in line else ""
        elif "Signal level=" in line:
            try:
                sig_part = line.split("Signal level=")[1].split(" ")[0]
                current["signal"] = int(sig_part.split("/")[0])
            except (IndexError, ValueError):
                current["signal"] = -100
        elif "Encryption key:" in line:
            current["encryption"] = "WPA2" if "on" in line else "Open"
        elif "Channel:" in line:
            try:
                current["channel"] = int(line.split("Channel:")[1].strip())
            except (IndexError, ValueError):
                current["channel"] = 0

    if current:
        networks.append(current)

    return networks


# ─── Demo / Simulation Mode ───────────────────────────────────────────────────
def simulate_networks() -> list[dict]:
    """
    Simulates a real scan result including one Evil Twin rogue AP.
    Used for demo when hardware/sudo isn't available.
    """
    import random
    base = [
        {"ssid": "GMI_WiFi",       "bssid": "AA:BB:CC:DD:EE:01", "signal": -65, "encryption": "WPA2", "channel": 6},
        {"ssid": "GMI_WiFi",       "bssid": "AA:BB:CC:DD:EE:02", "signal": -45, "encryption": "Open", "channel": 6},  # ← ROGUE!
        {"ssid": "Office_Net",     "bssid": "11:22:33:44:55:66", "signal": -72, "encryption": "WPA2", "channel": 11},
        {"ssid": "TP-Link_Guest",  "bssid": "DE:AD:BE:EF:00:01", "signal": -80, "encryption": "WPA2", "channel": 1},
        {"ssid": "Hotspot_Free",   "bssid": "CA:FE:BA:BE:00:01", "signal": -90, "encryption": "Open", "channel": 3},
    ]
    # Add slight signal jitter
    for n in base:
        n["signal"] += random.randint(-3, 3)
    return base


# ─── Detection Engine ─────────────────────────────────────────────────────────
class DetectionEngine:
    def __init__(self, logger: ForensicLogger, simulate: bool = False):
        self.logger   = logger
        self.simulate = simulate
        self.known_bssids: dict[str, str] = {}   # ssid → trusted bssid
        self.alert_callbacks = []

    def on_alert(self, callback):
        self.alert_callbacks.append(callback)

    def _notify(self, alert: dict):
        for cb in self.alert_callbacks:
            try:
                cb(alert)
            except Exception:
                pass

    def _scan(self) -> list[dict]:
        if self.simulate:
            return simulate_networks()
        return scan_with_iwlist(INTERFACE)

    def _severity(self, network: dict, reasons: list[str]) -> str:
        if "Open encryption" in reasons and "Duplicate SSID" in reasons:
            return "HIGH"
        if "Strong signal anomaly" in reasons:
            return "HIGH"
        if len(reasons) >= 2:
            return "MEDIUM"
        return "LOW"

    def analyze(self, networks: list[dict]) -> list[dict]:
        # Group by SSID
        by_ssid: dict[str, list] = defaultdict(list)
        for n in networks:
            ssid = n.get("ssid", "")
            if ssid:
                by_ssid[ssid].append(n)

        alerts = []

        for ssid, entries in by_ssid.items():
            if len(entries) < 2:
                # Only one AP with this name — learn it as trusted if not seen before
                bssid = entries[0].get("bssid", "")
                if ssid not in self.known_bssids:
                    self.known_bssids[ssid] = bssid
                continue

            # Multiple APs share the same SSID — potential Evil Twin
            trusted_bssid = self.known_bssids.get(ssid)

            for ap in entries:
                reasons = []
                bssid = ap.get("bssid", "")
                signal = ap.get("signal", -100)
                enc    = ap.get("encryption", "WPA2")

                # Check 1: Duplicate SSID
                reasons.append("Duplicate SSID")

                # Check 2: Unknown BSSID (not the trusted one)
                if trusted_bssid and bssid != trusted_bssid:
                    reasons.append("BSSID mismatch (unknown AP)")

                # Check 3: Open/no encryption
                if enc == "Open":
                    reasons.append("Open encryption")

                # Check 4: Unusually strong signal (closer than expected)
                if signal > RSSI_THRESHOLD:
                    reasons.append(f"Strong signal anomaly ({signal} dBm)")

                if len(reasons) >= 2:
                    severity = self._severity(ap, reasons)
                    alert = {
                        "type": "ROGUE_AP_DETECTED",
                        "severity": severity,
                        "ssid": ssid,
                        "bssid": bssid,
                        "signal_dbm": signal,
                        "encryption": enc,
                        "reasons": reasons,
                        "trusted_bssid": trusted_bssid or "Unknown",
                    }
                    logged = self.logger.log(alert)
                    alerts.append(logged)
                    self._notify(logged)

        return alerts

    def run_loop(self):
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'═'*55}")
        print(f"  TwinGuard-SHA256 — Rogue AP Detection Engine")
        print(f"  Mode: {'SIMULATION' if self.simulate else 'LIVE (' + INTERFACE + ')'}")
        print(f"{'═'*55}{Style.RESET_ALL}\n")

        scan_count = 0
        while True:
            scan_count += 1
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            print(f"{Fore.WHITE}[{ts}] Scan #{scan_count} — scanning networks...")

            networks = self._scan()
            print(f"  {Fore.CYAN}Found {len(networks)} network(s)")

            for n in networks:
                sig_color = Fore.RED if n.get("signal", -100) > RSSI_THRESHOLD else Fore.GREEN
                print(f"  {sig_color}● {n.get('ssid','?'):<20} "
                      f"BSSID={n.get('bssid','?')}  "
                      f"Signal={n.get('signal','?')} dBm  "
                      f"Enc={n.get('encryption','?')}")

            alerts = self.analyze(networks)

            if alerts:
                print(f"\n  {Fore.RED}{Style.BRIGHT}⚠  {len(alerts)} ROGUE AP(s) DETECTED!")
                for a in alerts:
                    print(f"\n  {Fore.RED}┌─ [{a['severity']}] ROGUE AP ALERT")
                    print(f"  │  SSID    : {a['ssid']}")
                    print(f"  │  BSSID   : {a['bssid']}")
                    print(f"  │  Signal  : {a['signal_dbm']} dBm")
                    print(f"  │  Reasons : {', '.join(a['reasons'])}")
                    print(f"  │  SHA-256 : {a['sha256_hash'][:32]}...")
                    print(f"  └─ Logged at {a['timestamp']}")
            else:
                print(f"  {Fore.GREEN}✓  No rogue APs detected.")

            print()
            time.sleep(SCAN_INTERVAL)


# ─── Dashboard Alert Sender ───────────────────────────────────────────────────
def send_to_dashboard(alert: dict):
    try:
        requests.post(DASHBOARD_URL, json=alert, timeout=2)
    except requests.exceptions.ConnectionError:
        pass  # Dashboard not running yet — that's okay


# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Auto-detect: use simulation if not root or no wireless interface
    is_root    = os.geteuid() == 0
    has_iface  = os.path.exists(f"/sys/class/net/{INTERFACE}")
    use_sim    = not (is_root and has_iface)

    if use_sim:
        print(f"{Fore.YELLOW}[INFO] Running in SIMULATION mode.")
        print(f"       (Run as root with '{INTERFACE}' available for live scanning)\n")

    logger  = ForensicLogger(LOG_FILE)
    engine  = DetectionEngine(logger, simulate=use_sim)
    engine.on_alert(send_to_dashboard)

    try:
        engine.run_loop()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[✓] TwinGuard stopped. Forensic log saved to: {LOG_FILE}")