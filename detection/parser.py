import csv
import os


def _clean_ssid(raw: str) -> str:
    """Return the broadcast name, or "" for a hidden network.

    airodump-ng writes a hidden SSID in several ways: an empty field, a run of
    NUL bytes, or a placeholder such as "<length:  0>" / "<length: 7>". The
    original parser kept the placeholder as if it were a real name, so two
    unrelated hidden APs both "named" "<length:  0>" were grouped together and
    scored as an evil twin. They are now normalised to "".
    """
    ssid = raw.strip()
    if ssid.startswith("<length:") and ssid.endswith(">"):
        return ""
    if ssid.replace("\x00", "").strip() == "":
        return ""
    return ssid


def parse_airodump_csv(csv_path: str) -> list[dict]:
    """
    Parse airodump-ng CSV output.

    Returns:
        [
            {
                "ssid": "...",          # "" when the network is hidden
                "bssid": "...",
                "signal": -45,
                "channel": 6,
                "encryption": "WPA2 CCMP PSK",
                "hidden": False
            }
        ]

    Hidden networks are returned with ssid "" and hidden True. The detection
    engine only groups non-empty SSIDs, so they never take part in evil-twin
    scoring, but they are kept for the forensic scan record.
    """

    networks = []

    if not os.path.exists(csv_path):
        return networks

    with open(csv_path, newline='', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)

        parsing_aps = False

        for row in reader:

            # Empty row means transition point
            if not row:
                continue

            # Start of AP section
            if row[0].strip() == "BSSID":
                parsing_aps = True
                continue

            # Stop when station section starts
            if row[0].strip() == "Station MAC":
                break

            if parsing_aps:

                try:
                    bssid = row[0].strip()
                    channel = int(row[3].strip())
                    signal = int(row[8].strip())

                    privacy = row[5].strip()
                    cipher = row[6].strip()
                    auth = row[7].strip()

                    ssid = _clean_ssid(row[13])

                    encryption = f"{privacy} {cipher} {auth}".strip()

                    networks.append({
                        "ssid": ssid,
                        "bssid": bssid,
                        "signal": signal,
                        "channel": channel,
                        "encryption": encryption,
                        "hidden": ssid == "",
                    })

                except (IndexError, ValueError):
                    continue

    return networks
