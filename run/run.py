#!/usr/bin/env python3

import subprocess
import time

print("[TwinGuard] Starting system...")

dashboard = subprocess.Popen([
    "python3",
    "dashboard/dashboard_server.py"
])

time.sleep(2)

detector = subprocess.Popen([
    "python3",
    "detection/detection.py"
])

try:
    dashboard.wait()
    detector.wait()

except KeyboardInterrupt:
    print("\n[TwinGuard] Shutting down...")
    dashboard.terminate()
    detector.terminate()