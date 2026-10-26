"""TwinGuard - trusted network list, managed from the phone app.

A JSON file of BSSIDs the operator has confirmed are legitimate. The detection
engine already scores an access point partly on whether its BSSID is known for
that SSID; this list seeds that "known" set so a confirmed AP is not re-flagged
on every scan. Managed through the control API (GET/PUT /trusted).
"""
import json
import os
import threading


def _norm(bssid):
    return bssid.strip().lower()


class TrustedList:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._entries = {}  # bssid -> {"ssid": str, "added_at": str}
        self._load()

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    data = json.load(f)
                for e in data.get("entries", []):
                    b = _norm(e.get("bssid", ""))
                    if b:
                        self._entries[b] = {
                            "ssid": e.get("ssid", ""),
                            "added_at": e.get("added_at", ""),
                        }
            except (OSError, ValueError):
                self._entries = {}

    def _entries_as_list(self):
        """Serialisable view. Caller must already hold self._lock."""
        return [{"bssid": b, **v} for b, v in sorted(self._entries.items())]

    def _save(self):
        """Caller must already hold self._lock."""
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"entries": self._entries_as_list()}, f, indent=2)
        os.replace(tmp, self.path)

    def as_list(self):
        with self._lock:
            return self._entries_as_list()

    def bssids(self):
        with self._lock:
            return set(self._entries.keys())

    def is_trusted(self, bssid):
        return _norm(bssid) in self.bssids()

    def replace(self, entries):
        """Replaces the whole list (PUT semantics). Returns the stored list."""
        clean = {}
        for e in entries:
            b = _norm(e.get("bssid", ""))
            if len(b.split(":")) == 6:
                clean[b] = {"ssid": e.get("ssid", ""),
                            "added_at": e.get("added_at", "")}
        with self._lock:
            self._entries = clean
            self._save()
        return self.as_list()
