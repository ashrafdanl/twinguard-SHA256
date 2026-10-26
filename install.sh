#!/usr/bin/env bash
#
# TwinGuard - Raspberry Pi control service installer.
#
# Run this ON THE PI, from inside the twinguard-SHA256 folder:
#     chmod +x install.sh
#     ./install.sh
#
# It will:
#   1. install the Python dependencies into the repo's .venv
#   2. generate an API key and a self-signed TLS certificate
#   3. ask for the Test02 operator password  (typed here on the Pi only)
#   4. write a chmod-600 config file
#   5. install and start a systemd service
#   6. print the IP address, API key and certificate fingerprint you type
#      into the phone app
#
# It never transmits on the air. "Active" scanning is deliberately not built.

set -euo pipefail

# ── identity (edit only if the operator or project changes) ───────────────────
PROJECT_ID="twinguard67"
WEB_API_KEY="AIzaSyB3M66teOtWx0ScUqUGYXJmmGhV_RxYdDc"
OPERATOR_EMAIL="ilhmsshyli@gmail.com"
OPERATOR_USERNAME="Test02"
INTERFACE="${TWINGUARD_IFACE:-wlan1}"
PORT="${TWINGUARD_PORT:-8080}"

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
CFG_DIR="$HOME/.config/twinguard"
DATA_DIR="$HOME/.local/share/twinguard"
VENV="$REPO_DIR/.venv"

say()  { printf '\033[36m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[install]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[install] %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" -ne 0 ] || die "Run as the normal pi user, NOT root. It will sudo only where needed."

mkdir -p "$CFG_DIR" "$DATA_DIR"
chmod 700 "$CFG_DIR"

# ── 0. ownership ──────────────────────────────────────────────────────────────
# Earlier runs under `sudo` can leave root-owned files in the project, which
# then block overwriting and block writing into the virtualenv. Take ownership
# back (one sudo) before doing anything else.
if [ -n "$(find "$REPO_DIR" ! -user "$(id -un)" -print -quit 2>/dev/null)" ]; then
  say "Some project files are owned by root (from an earlier sudo run). "
  say "Fixing ownership of $REPO_DIR ..."
  sudo chown -R "$(id -un)":"$(id -gn)" "$REPO_DIR"
fi

# ── 1. dependencies ───────────────────────────────────────────────────────────
say "Installing system packages (aircrack-ng for airodump-ng, iw, openssl)..."
sudo apt-get update -qq
sudo apt-get install -y -qq aircrack-ng iw openssl python3-venv >/dev/null

say "Creating the Python virtualenv and installing requirements..."
# Rebuild the venv if it is missing or its pip cannot run — e.g. one left behind
# by an earlier run as a different user, or copied in from another machine.
if ! "$VENV/bin/python" -m pip --version >/dev/null 2>&1; then
  rm -rf "$VENV"
  python3 -m venv "$VENV"
fi
"$VENV/bin/python" -m pip install -q --upgrade pip
# flask+requests+scapy for the sensor; firebase-admin for the admin dashboard
# (dashboard_server.py reads Firestore with the Admin SDK).
"$VENV/bin/python" -m pip install -q flask requests scapy firebase-admin

# ── 2. API key + TLS certificate ──────────────────────────────────────────────
KEY_FILE="$CFG_DIR/api.key"
if [ ! -f "$KEY_FILE" ]; then
  # TG-XXXX-XXXX-XXXX-XXXX, matching the format the app shows.
  RAW="$(openssl rand -hex 8 | tr 'a-f' 'A-F')"
  printf 'TG-%s-%s-%s-%s\n' "${RAW:0:4}" "${RAW:4:4}" "${RAW:8:4}" "${RAW:12:4}" > "$KEY_FILE"
fi
chmod 600 "$KEY_FILE"
API_KEY="$(cat "$KEY_FILE")"

CERT="$CFG_DIR/cert.pem"
TLSKEY="$CFG_DIR/key.pem"
if [ ! -f "$CERT" ]; then
  say "Generating a self-signed TLS certificate (valid 5 years)..."
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$TLSKEY" -out "$CERT" -days 1825 \
    -subj "/CN=twinguard-sensor/O=TwinGuard" >/dev/null 2>&1
fi
chmod 600 "$TLSKEY"
FINGERPRINT="$(openssl x509 -in "$CERT" -noout -fingerprint -sha256 \
  | sed 's/^.*=//')"

# ── 3. operator password (typed on the Pi only) ───────────────────────────────
echo
say "TwinGuard uploads as the operator account:"
say "    $OPERATOR_EMAIL  (username $OPERATOR_USERNAME)"
say "Enter that account's password. It is written only to a 0600 file on this"
say "Pi and is never printed or sent anywhere but Google sign-in."
printf '\033[36m[install]\033[0m Password for %s: ' "$OPERATOR_EMAIL"
read -r -s OPERATOR_PASSWORD
echo
[ -n "$OPERATOR_PASSWORD" ] || die "No password entered."

# ── 4. config file ────────────────────────────────────────────────────────────
CONFIG="$CFG_DIR/service.json"
umask 177
cat > "$CONFIG" <<JSON
{
  "interface": "$INTERFACE",
  "port": $PORT,
  "bind": "0.0.0.0",
  "interval": 60,
  "scan_duration": 8,
  "monitoring": true,
  "data_dir": "$DATA_DIR",
  "api_key_file": "$KEY_FILE",
  "tls_cert": "$CERT",
  "tls_key": "$TLSKEY",
  "firebase": {
    "project_id": "$PROJECT_ID",
    "api_key": "$WEB_API_KEY",
    "email": "$OPERATOR_EMAIL",
    "username": "$OPERATOR_USERNAME",
    "password": "$OPERATOR_PASSWORD"
  }
}
JSON
umask 022
chmod 600 "$CONFIG"
unset OPERATOR_PASSWORD
say "Wrote $CONFIG (chmod 600)."

# ── 5. systemd service ────────────────────────────────────────────────────────
UNIT="/etc/systemd/system/twinguard.service"
say "Installing systemd service..."
sudo tee "$UNIT" >/dev/null <<UNITEOF
[Unit]
Description=TwinGuard rogue-AP detection control service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Environment=TWINGUARD_CONFIG=$CONFIG
ExecStartPre=/bin/sh -c 'ip link set $INTERFACE down; iw dev $INTERFACE set type monitor; ip link set $INTERFACE up'
ExecStart=$VENV/bin/python $REPO_DIR/detection/tg_control.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNITEOF

# The config holds the operator password, so root must read it. It lives under
# the user's home; make it readable by root only via the service (already 600,
# and root can always read). Nothing else changes.
sudo systemctl daemon-reload
sudo systemctl enable twinguard.service >/dev/null 2>&1 || true
sudo systemctl restart twinguard.service

sleep 3
PI_IP="$(ip -4 -o addr show | awk '$2!="lo"{print $4}' | cut -d/ -f1 | head -n1)"

# ── 6. what to type into the app ──────────────────────────────────────────────
cat <<SUMMARY

────────────────────────────────────────────────────────────
 TwinGuard sensor is installed and running.

 In the phone app (Settings -> Raspberry Pi sensor) enter:

     IP address      ${PI_IP:-<this Pi's IP on the phone hotspot>}
     Port            $PORT
     API key         $API_KEY
     Protocol        HTTPS

 On first connect the app shows a certificate fingerprint and
 asks you to confirm it. It must match exactly:

     SHA-256  $FINGERPRINT

 Useful commands:
     systemctl status twinguard        # is it running
     journalctl -u twinguard -f        # live logs
     sudo systemctl restart twinguard  # restart after editing config
────────────────────────────────────────────────────────────
SUMMARY
