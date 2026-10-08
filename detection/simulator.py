"""
TwinGuard-SHA256: simulated Wi-Fi scans (--simulate)
=====================================================
Lets the full pipeline (detector -> Firebase -> dashboard / phone app) be
demonstrated and tested without a Wi-Fi adapter. Networks use the same field
formats as the airodump-ng parser, so the real detection logic runs unchanged.

Every alert raised in simulation is marked "simulated": true inside its
SHA-256 seal, so it can never be mistaken for real evidence.

Timeline:
  scans 1-2   only legitimate networks -> the engine learns their BSSIDs
  scan 3+     each scan has a chance that one evil twin appears
"""

import random

# ssid, legitimate bssid, channel, encryption (airodump format), typical signal
BASELINE = [
    ("GMI-Student",    "A4:2B:B0:11:22:01",  6, "WPA2 CCMP PSK", -72),
    ("CampusNet",      "A4:2B:B0:11:22:02", 11, "WPA2 CCMP PSK", -58),
    ("Library-5G",     "A4:2B:B0:11:22:03", 36, "WPA2 CCMP PSK", -76),
    ("Starbucks_WiFi", "3C:84:6A:55:10:20",  1, "WPA2 CCMP PSK", -64),
    ("TM_Unifi_88",    "C8:3A:35:9E:41:7C",  6, "WPA2 CCMP PSK", -81),
    ("Guest",          "3C:84:6A:55:10:21",  1, "OPN",           -67),
]

# Evil twins: copy a legitimate SSID from a rogue BSSID. Expected severity from
# the scoring rules (unknown BSSID +2, open +2, duplicate SSID +1,
# signal 20 dB above the group average +1, channel mismatch +1).
ATTACKS = [
    # open, strong, wrong channel                  -> 2+2+1+1+1 = 7 HIGH
    {"ssid": "GMI-Student",    "channel": 1,  "encryption": "OPN",           "signal": -24},
    # open, strong, wrong channel                  -> 7 HIGH
    {"ssid": "Library-5G",     "channel": 11, "encryption": "OPN",           "signal": -27},
    # open, same channel, normal signal            -> 2+2+1 = 5 MEDIUM
    {"ssid": "Starbucks_WiFi", "channel": 1,  "encryption": "OPN",           "signal": -60},
    # encrypted clone, same channel                -> 2+1 = 3 MEDIUM
    {"ssid": "CampusNet",      "channel": 11, "encryption": "WPA2 CCMP PSK", "signal": -55},
]


class ScanSimulator:

    def __init__(self, baseline_scans=2, attack_chance=0.5, seed=None):
        self.rng            = random.Random(seed)
        self.baseline_scans = baseline_scans
        self.attack_chance  = attack_chance
        self.scan_no        = 0

    def _rogue_mac(self):
        # locally administered, unicast: what MAC-spoofing tools typically produce
        first = (self.rng.randrange(256) | 0x02) & 0xFE
        return ":".join(f"{b:02X}" for b in [first] + [self.rng.randrange(256) for _ in range(5)])

    def scan(self):
        self.scan_no += 1
        jitter = lambda s: s + self.rng.randint(-2, 2)
        nets = [{"ssid": s, "bssid": b, "channel": c, "encryption": e, "signal": jitter(sig)}
                for s, b, c, e, sig in BASELINE]
        if self.scan_no > self.baseline_scans and self.rng.random() < self.attack_chance:
            atk = self.rng.choice(ATTACKS)
            nets.append({"ssid": atk["ssid"], "bssid": self._rogue_mac(), "channel": atk["channel"],
                         "encryption": atk["encryption"], "signal": jitter(atk["signal"])})
        self.rng.shuffle(nets)
        return nets
