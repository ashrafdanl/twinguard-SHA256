import csv
import os


def parse_airodump_csv(csv_path: str) -> list[dict]:
    """
    Parse airodump-ng CSV output.

    Returns:
        [
            {
                "ssid": "...",
                "bssid": "...",
                "signal": -45,
                "channel": 6,
                "encryption": "WPA2"
            }
        ]
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

                    ssid = row[13].strip()

                    encryption = f"{privacy} {cipher} {auth}".strip()

                    if ssid:
                        networks.append({
                            "ssid": ssid,
                            "bssid": bssid,
                            "signal": signal,
                            "channel": channel,
                            "encryption": encryption
                        })

                except (IndexError, ValueError):
                    continue

    return networks

