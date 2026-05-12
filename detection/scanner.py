import os
import time
import subprocess
from parser import parse_airodump_csv

SCAN_DIR = "scans"
SCAN_PREFIX = "scan"


def cleanup_old_scans():
    os.makedirs(SCAN_DIR, exist_ok=True)

    for file in os.listdir(SCAN_DIR):
        if file.startswith(SCAN_PREFIX):
            try:
                os.remove(os.path.join(SCAN_DIR, file))
            except:
                pass


def scan_networks(interface="wlan0mon", duration=8):
    cleanup_old_scans()

    output_path = os.path.join(SCAN_DIR, SCAN_PREFIX)

    cmd = [
        "airodump-ng",
        interface,
        "--write", output_path,
        "--output-format", "csv",
        "--write-interval", "1"
    ]

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # 🔥 IMPORTANT FIX: give buffer time AFTER scan, not during kill
    time.sleep(duration)

    # graceful shutdown (NOT instant terminate)
    process.send_signal(subprocess.signal.SIGINT)

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()

    csv_file = f"{output_path}-01.csv"

    # 🔥 WAIT FOR FILE TO FULLY WRITE (CRITICAL FIX)
    timeout = 3
    while timeout > 0:
        if os.path.exists(csv_file) and os.path.getsize(csv_file) > 0:
            break
        time.sleep(1)
        timeout -= 1

    if not os.path.exists(csv_file):
        print("[ERROR] CSV not generated")
        return []

    return parse_airodump_csv(csv_file)
