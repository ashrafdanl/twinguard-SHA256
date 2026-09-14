#!/usr/bin/env python3

import subprocess
import time

#!/usr/bin/env python3

import os
import subprocess
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYTHON = os.path.join(BASE_DIR, ".venv", "bin", "python")

print("[TwinGuard] Starting system...")

dashboard = subprocess.Popen([
    PYTHON,
    os.path.join(BASE_DIR, "dashboard", "dashboard_server.py")
])

time.sleep(2)

detector = subprocess.Popen([
    "sudo",
    PYTHON,
    os.path.join(BASE_DIR, "detection", "detection.py")
])

try:
    dashboard.wait()
    detector.wait()

except KeyboardInterrupt:
    print("\n[TwinGuard] Shutting down...")

    dashboard.terminate()
    detector.terminate()

    dashboard.wait()
    detector.wait()

    print("[TwinGuard] System stopped.")
