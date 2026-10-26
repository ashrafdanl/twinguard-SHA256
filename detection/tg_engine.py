"""TwinGuard - controllable detection engine + record sealing.

The scoring is copied verbatim from detection.py (unknown BSSID +2, open +2,
multiple APs +1, signal anomaly +1, channel mismatch +1; alert at score >= 3;
MEDIUM 3-5, HIGH >= 6). Nothing about how a threat is judged has changed.

What is added around it:
  * the trusted list seeds the "known" BSSIDs, so an operator-confirmed AP is
    not re-flagged every scan;
  * every alert and every whole-scan record is sealed with SHA-256 the same
    way the dashboard verifies it: sha256(json.dumps(entry, sort_keys=True))
    over every field except sha256_hash;
  * uid, username and clock_source are part of the sealed payload, so the
    phone can recompute the hash and the Firestore rules see a matching
    username.
"""
import datetime
import hashlib
import json
from collections import defaultdict


def utc_now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def seal(entry: dict) -> str:
    """The project's sealing function, unchanged: SHA-256 over the canonical
    JSON of the entry (every field except the hash itself)."""
    payload = {k: v for k, v in entry.items() if k != "sha256_hash"}
    raw = json.dumps(payload, sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()


def severity_for(score: int) -> str:
    if score >= 6:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    return "LOW"


class Engine:
    def __init__(self, uid, username, trusted, clock):
        self.uid = uid
        self.username = username
        self.trusted = trusted          # TrustedList
        self.clock = clock              # tg_system.Clock
        self.known_bssids = defaultdict(set)

    def _seed_known(self, grouped):
        """A BSSID is 'known' if the operator trusted it, or if it is the only
        AP seen for its SSID (same rule the original built up over time)."""
        trusted = self.trusted.bssids()
        for ssid, aps in grouped.items():
            for ap in aps:
                b = ap.get("bssid", "").lower()
                if b in trusted:
                    self.known_bssids[ssid].add(ap.get("bssid", ""))
            if len(aps) == 1:
                self.known_bssids[ssid].add(aps[0].get("bssid", ""))

    def analyze(self, networks):
        """Returns (alerts, per_network_verdicts). Scoring unchanged."""
        grouped = defaultdict(list)
        for net in networks:
            ssid = net.get("ssid", "").strip()
            if ssid:
                grouped[ssid].append(net)

        self._seed_known(grouped)

        alerts = []
        verdicts = {}  # bssid -> dict

        for ssid, aps in grouped.items():
            if len(aps) == 1:
                self.known_bssids[ssid].add(aps[0].get("bssid", ""))
                b = aps[0].get("bssid", "")
                verdicts[b] = {"status": "BASELINE", "score": 0,
                               "threat_level": None, "reasons": []}
                continue

            known = self.known_bssids.get(ssid, set())
            trusted = self.trusted.bssids()

            for ap in aps:
                bssid = ap.get("bssid", "")
                # An operator-confirmed access point is evidence of a known-good
                # device, not a threat, so it is never raised as an alert. It is
                # still recorded in the scan so the sweep stays complete.
                if bssid.lower() in trusted:
                    verdicts[bssid] = {"status": "TRUSTED", "score": 0,
                                       "threat_level": None, "reasons": []}
                    continue

                score = 0
                reasons = []
                signal = ap.get("signal", -100)
                channel = ap.get("channel")
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
                legit_channels = {x.get("channel") for x in aps
                                  if x.get("bssid") in known}
                if legit_channels and channel not in legit_channels:
                    score += 1
                    reasons.append("Channel mismatch")

                if score >= 3:
                    entry = {
                        "type": "ROGUE_AP_DETECTED",
                        "severity": severity_for(score),
                        "score": score,
                        "ssid": ssid,
                        "bssid": bssid,
                        "signal_dbm": signal,
                        "channel": channel,
                        "encryption": encryption,
                        "trusted_bssids": sorted(known),
                        "reasons": reasons,
                        "timestamp": utc_now_iso(),
                        "clock_source": self.clock.source(),
                        "uid": self.uid,
                        "username": self.username,
                    }
                    entry["sha256_hash"] = seal(entry)
                    alerts.append(entry)
                    verdicts[bssid] = {"status": "ALERT", "score": score,
                                       "threat_level": entry["severity"],
                                       "reasons": reasons,
                                       "detection_id": entry["sha256_hash"]}
                else:
                    verdicts[bssid] = {"status": "CLEAR", "score": score,
                                       "threat_level": None, "reasons": reasons}

        return alerts, verdicts

    def build_scan_record(self, networks, verdicts):
        """One sealed document describing the whole sweep."""
        nets = []
        for n in networks:
            b = n.get("bssid", "")
            v = verdicts.get(b, {"status": "BASELINE", "score": 0,
                                 "threat_level": None, "reasons": []})
            nets.append({
                "ssid": n.get("ssid", ""),
                "bssid": b,
                "signal_dbm": n.get("signal", -100),
                "channel": n.get("channel"),
                "encryption": n.get("encryption", ""),
                "hidden": n.get("hidden", False),
                "status": v["status"],
                "score": v["score"],
                "threat_level": v["threat_level"],
                "reasons": v["reasons"],
                "detection_id": v.get("detection_id"),
            })
        entry = {
            "timestamp": utc_now_iso(),
            "clock_source": self.clock.source(),
            "uid": self.uid,
            "username": self.username,
            "scanned": len(networks),
            "threats": sum(1 for v in verdicts.values() if v["status"] == "ALERT"),
            "networks": nets[:300],
        }
        entry["sha256_hash"] = seal(entry)
        return entry
