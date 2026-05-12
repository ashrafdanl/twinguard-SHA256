#!/usr/bin/env python3
"""
TwinGuard-SHA256: Telegram Real-Time Alert Notifier
=====================================================
Sends instant Telegram messages when the detection engine
flags a rogue / suspicious Wi-Fi access point.

Setup (one-time):
    1. Message @BotFather on Telegram → /newbot → copy the token.
    2. Message your bot once, then run:
           python3 telegram_notifier.py --get-chat-id
       to print your Chat ID.
    3. Fill in TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID below,
       OR export them as environment variables before running TwinGuard.

Integration:
    Import send_telegram_alert and register it as a callback:
        from telegram_notifier import TelegramNotifier
        tg = TelegramNotifier()
        engine.on_alert(tg.send_alert)
"""

import os
import sys
import json
import time
import requests
import argparse
import datetime
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION  ← Fill these in or set as environment variables
# ─────────────────────────────────────────────────────────────────────────────

TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "YOUR_BOT_TOKEN_HERE")
TELEGRAM_CHAT_ID:   str = os.getenv("TELEGRAM_CHAT_ID",   "YOUR_CHAT_ID_HERE")

# Optional: only notify for alerts at or above this severity
#   Accepted values: "LOW" | "MEDIUM" | "HIGH"
MIN_SEVERITY: str = os.getenv("TG_MIN_SEVERITY", "LOW")

# Rate-limit: minimum seconds between Telegram messages (prevents spam)
RATE_LIMIT_SECONDS: int = int(os.getenv("TG_RATE_LIMIT", "5"))

# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

SEVERITY_EMOJI = {
    "HIGH":   "🔴",
    "MEDIUM": "🟡",
    "LOW":    "🟢",
}


class TelegramNotifier:
    """
    Wraps the Telegram Bot API to push real-time Wi-Fi threat alerts.

    Usage:
        notifier = TelegramNotifier()
        engine.on_alert(notifier.send_alert)   # hook into DetectionEngine
    """

    def __init__(
        self,
        token: Optional[str] = None,
        chat_id: Optional[str] = None,
        min_severity: str = MIN_SEVERITY,
        rate_limit: int = RATE_LIMIT_SECONDS,
    ):
        self.token        = token    or TELEGRAM_BOT_TOKEN
        self.chat_id      = chat_id  or TELEGRAM_CHAT_ID
        self.min_severity = min_severity.upper()
        self.rate_limit   = rate_limit
        self._last_sent   = 0.0          # epoch seconds
        self._sent_count  = 0

        self._validate_config()

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _validate_config(self):
        if "YOUR_BOT_TOKEN" in self.token:
            raise ValueError(
                "[TelegramNotifier] BOT TOKEN not set. "
                "Edit TELEGRAM_BOT_TOKEN in telegram_notifier.py "
                "or export it as an environment variable."
            )
        if "YOUR_CHAT_ID" in self.chat_id:
            raise ValueError(
                "[TelegramNotifier] CHAT ID not set. "
                "Run:  python3 telegram_notifier.py --get-chat-id"
            )

    @property
    def _api_base(self) -> str:
        return f"https://api.telegram.org/bot{self.token}"

    def _post(self, method: str, payload: dict, retries: int = 3) -> bool:
        url = f"{self._api_base}/{method}"
        for attempt in range(1, retries + 1):
            try:
                resp = requests.post(url, json=payload, timeout=10)
                if resp.status_code == 200:
                    return True
                print(
                    f"[TelegramNotifier] HTTP {resp.status_code} on attempt {attempt}: "
                    f"{resp.text[:120]}"
                )
            except requests.RequestException as exc:
                print(f"[TelegramNotifier] Network error (attempt {attempt}): {exc}")
            time.sleep(1)
        return False

    # ── Message formatting ────────────────────────────────────────────────────

    def _format_alert(self, alert: dict) -> str:
        severity  = alert.get("severity", "LOW")
        emoji     = SEVERITY_EMOJI.get(severity, "⚠️")
        ssid      = alert.get("ssid", "Unknown")
        bssid     = alert.get("bssid", "Unknown")
        channel   = alert.get("channel", "?")
        signal    = alert.get("signal_dbm", "?")
        enc       = alert.get("encryption", "?")
        score     = alert.get("score", "?")
        reasons   = ", ".join(alert.get("reasons", []))
        sha256    = alert.get("sha256_hash", "")[:24] + "…" if alert.get("sha256_hash") else "N/A"
        ts        = alert.get("timestamp", datetime.datetime.utcnow().isoformat() + "Z")

        return (
            f"{emoji} *TWINGUARD ALERT — {severity} SEVERITY*\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🌐 *SSID*      : `{ssid}`\n"
            f"📡 *BSSID*     : `{bssid}`\n"
            f"📶 *Signal*    : `{signal} dBm`\n"
            f"📻 *Channel*   : `{channel}`\n"
            f"🔒 *Encryption*: `{enc}`\n"
            f"⚡ *Score*     : `{score}`\n"
            f"❗ *Reasons*   : {reasons}\n"
            f"🔑 *SHA-256*   : `{sha256}`\n"
            f"🕐 *Time*      : `{ts}`\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"_TwinGuard\\-SHA256 Forensic Monitor_"
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def send_alert(self, alert: dict) -> bool:
        """
        Called by DetectionEngine._notify() for every detected threat.
        Filters by severity and rate-limits before sending.
        """
        # --- Severity filter ---
        alert_rank = SEVERITY_RANK.get(alert.get("severity", "LOW"), 1)
        min_rank   = SEVERITY_RANK.get(self.min_severity, 1)
        if alert_rank < min_rank:
            return False

        # --- Rate limit ---
        now = time.time()
        if now - self._last_sent < self.rate_limit:
            print(
                f"[TelegramNotifier] Rate-limited — skipping alert "
                f"(next slot in {self.rate_limit - (now - self._last_sent):.1f}s)"
            )
            return False

        # --- Send ---
        message = self._format_alert(alert)
        payload = {
            "chat_id":    self.chat_id,
            "text":       message,
            "parse_mode": "MarkdownV2",
        }

        success = self._post("sendMessage", payload)
        if success:
            self._last_sent  = time.time()
            self._sent_count += 1
            print(
                f"[TelegramNotifier] ✓ Alert #{self._sent_count} sent — "
                f"[{alert.get('severity')}] {alert.get('ssid')}"
            )
        else:
            print("[TelegramNotifier] ✗ Failed to deliver alert to Telegram.")

        return success

    def send_startup_message(self) -> bool:
        """Send a 'system online' ping when TwinGuard starts."""
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        text = (
            "🛡 *TWINGUARD\\-SHA256 ONLINE*\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"✅ Real\\-time Wi\\-Fi monitoring has started\\.\n"
            f"🕐 `{now}`\n"
            f"📌 Minimum alert level: `{self.min_severity}`\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "_You will be notified of any rogue access points\\._"
        )
        return self._post("sendMessage", {
            "chat_id":    self.chat_id,
            "text":       text,
            "parse_mode": "MarkdownV2",
        })

    def send_shutdown_message(self) -> bool:
        """Send a 'system offline' ping when TwinGuard stops."""
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        text = (
            "🔴 *TWINGUARD\\-SHA256 OFFLINE*\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"⛔ Monitoring has stopped\\.\n"
            f"🕐 `{now}`\n"
            f"📊 Alerts sent this session: `{self._sent_count}`\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━"
        )
        return self._post("sendMessage", {
            "chat_id":    self.chat_id,
            "text":       text,
            "parse_mode": "MarkdownV2",
        })

    # ── CLI helper ────────────────────────────────────────────────────────────

    def get_chat_id(self):
        """Print updates so the user can discover their chat_id."""
        print(f"[TelegramNotifier] Fetching recent updates for bot …")
        resp = requests.get(f"{self._api_base}/getUpdates", timeout=10)
        if resp.status_code != 200:
            print(f"[ERROR] {resp.status_code}: {resp.text}")
            return

        data = resp.json()
        updates = data.get("result", [])
        if not updates:
            print(
                "[!] No updates found.\n"
                "    → Send ANY message to your bot on Telegram, then re-run."
            )
            return

        print("\n── Recent chats ──────────────────────────────")
        for u in updates[-5:]:
            msg     = u.get("message", {})
            chat    = msg.get("chat", {})
            chat_id = chat.get("id")
            name    = chat.get("first_name", "") + " " + chat.get("last_name", "")
            text    = msg.get("text", "")
            print(f"  Chat ID : {chat_id}  |  Name: {name.strip()}  |  Last msg: {text!r}")
        print("──────────────────────────────────────────────")
        print("Set TELEGRAM_CHAT_ID to the ID shown above.\n")


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TwinGuard Telegram Notifier utility")
    parser.add_argument("--get-chat-id", action="store_true",
        help="Print the chat IDs that have messaged your bot")
    parser.add_argument("--test", action="store_true",
        help="Send a test alert to confirm the bot is working")
    args = parser.parse_args()

    if args.get_chat_id:
        token = TELEGRAM_BOT_TOKEN
        if "YOUR_BOT_TOKEN" in token:
            print("[ERROR] BOT TOKEN not set.")
            exit(1)
        import requests as _req
        resp = _req.get(f"https://api.telegram.org/bot{token}/getUpdates", timeout=10)
        updates = resp.json().get("result", [])
        if not updates:
            print("[!] No updates found. Send a message to your bot first, then re-run.")
        else:
            print("\n── Recent chats ──────────────────────────────")
            for u in updates[-5:]:
                msg  = u.get("message", {})
                chat = msg.get("chat", {})
                name = (chat.get("first_name","") + " " + chat.get("last_name","")).strip()
                print(f"  Chat ID : {chat.get('id')}  |  Name: {name}  |  Last msg: {msg.get('text','')!r}")
            print("──────────────────────────────────────────────")

    elif args.test:
        notifier = TelegramNotifier()
        print("[TelegramNotifier] Sending test alert …")
        dummy_alert = {
            "type": "ROGUE_AP_DETECTED", "severity": "HIGH", "score": 7,
            "ssid": "TestNetwork", "bssid": "AA:BB:CC:DD:EE:FF",
            "signal_dbm": -45, "channel": 6, "encryption": "Open",
            "reasons": ["Unknown BSSID", "Open encryption", "Signal anomaly"],
            "sha256_hash": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        }
        ok = notifier.send_alert(dummy_alert)
        print("✓ Sent!" if ok else "✗ Failed. Check token / chat ID.")

    else:
        parser.print_help()