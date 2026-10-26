"""TwinGuard - Raspberry Pi system telemetry and clock handling.

Everything here is read from the running system (/proc, /sys, timedatectl).
Nothing is estimated or invented: a value that cannot be read is None.
"""
import os
import shutil
import socket
import subprocess
import threading
import time

VERSION = "3.0.0"

_cpu_lock = threading.Lock()
_cpu_prev = None  # (idle, total)


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def cpu_load():
    """CPU busy fraction since the previous call (0..1), from /proc/stat."""
    global _cpu_prev
    text = _read("/proc/stat")
    if not text:
        return None
    parts = text.splitlines()[0].split()[1:]
    vals = [int(x) for x in parts[:8]]
    idle = vals[3] + vals[4]
    total = sum(vals)
    with _cpu_lock:
        prev = _cpu_prev
        _cpu_prev = (idle, total)
    if prev is None:
        time.sleep(0.2)
        return cpu_load()
    d_total = total - prev[1]
    if d_total <= 0:
        return 0.0
    return round(1.0 - (idle - prev[0]) / d_total, 3)


def memory_used():
    text = _read("/proc/meminfo")
    if not text:
        return None
    info = {}
    for line in text.splitlines():
        k, _, v = line.partition(":")
        info[k] = int(v.split()[0])
    total = info.get("MemTotal")
    avail = info.get("MemAvailable")
    if not total or avail is None:
        return None
    return round(1.0 - avail / total, 3)


def temperature_c():
    raw = _read("/sys/class/thermal/thermal_zone0/temp")
    if not raw:
        return None
    try:
        return round(int(raw.strip()) / 1000.0, 1)
    except ValueError:
        return None


def uptime_seconds():
    raw = _read("/proc/uptime")
    return int(float(raw.split()[0])) if raw else None


def storage(path="/"):
    try:
        u = shutil.disk_usage(path)
        return round(u.used / 1e9, 2), round(u.total / 1e9, 2)
    except OSError:
        return None, None


def interface_mode(iface):
    """'monitor', 'managed', ... as reported by `iw`, or None."""
    if not os.path.exists(f"/sys/class/net/{iface}"):
        return None
    try:
        out = subprocess.run(["iw", "dev", iface, "info"], capture_output=True,
                             text=True, timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("type "):
            return line.split(None, 1)[1]
    return None


def local_ips():
    """IPv4 addresses on non-loopback interfaces (for the installer and /status)."""
    ips = []
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True,
                             text=True, timeout=3).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[1] != "lo":
                ips.append({"iface": parts[1], "ip": parts[3].split("/")[0]})
    except (OSError, subprocess.SubprocessError):
        pass
    return ips


def hostname():
    return socket.gethostname()


# ── Clock ────────────────────────────────────────────────────────────────────
# The Pi 4 has no battery-backed clock. With internet it syncs over NTP; with
# none it boots with a stale time. The phone can push its own time to the Pi
# (POST /api/v1/time). Every sealed record carries `clock_source` so an
# examiner knows how far each timestamp can be trusted.

class Clock:
    def __init__(self):
        self._lock = threading.Lock()
        self.phone_synced_at = None   # epoch when the phone last set the clock
        self.phone_offset_s = None    # how far the Pi was off at that moment

    @staticmethod
    def ntp_synchronized():
        # systemd-timesyncd drops this file once the clock is NTP-synced. Reading
        # it is instant and needs no dbus, so a stuck time daemon can never block
        # the control service (as `timedatectl` would).
        if os.path.exists("/run/systemd/timesync/synchronized"):
            return True
        # adjtimex reports the kernel clock sync state (11 = NOT synced / UNSYNC).
        try:
            import ctypes
            class Timex(ctypes.Structure):
                _fields_ = [("modes", ctypes.c_int)] + \
                    [(n, ctypes.c_long) for n in (
                        "offset", "freq", "maxerror", "esterror")] + \
                    [("status", ctypes.c_int)] + \
                    [(n, ctypes.c_long) for n in (
                        "constant", "precision", "tolerance")] + \
                    [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)] + \
                    [(n, ctypes.c_long) for n in (
                        "tick", "ppsfreq", "jitter")] + \
                    [("shift", ctypes.c_int)] + \
                    [(n, ctypes.c_long) for n in (
                        "stabil", "jitcnt", "calcnt", "errcnt", "stbcnt")] + \
                    [("tai", ctypes.c_int)] + [("pad%d" % i, ctypes.c_int)
                                               for i in range(11)]
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            t = Timex()
            STA_UNSYNC = 0x0040
            res = libc.adjtimex(ctypes.byref(t))
            if res >= 0:
                return not (t.status & STA_UNSYNC)
        except Exception:
            pass
        return False

    def source(self):
        if self.ntp_synchronized():
            return "ntp"
        # A plain attribute read; no lock, so this is safe to call from inside
        # status() which already holds the lock.
        if self.phone_synced_at is not None:
            return "phone"
        return "unsynced"

    def set_from_phone(self, epoch_ms):
        """Sets the system clock from the phone, unless NTP already owns it.

        Returns a dict describing what happened.
        """
        now = time.time()
        phone = epoch_ms / 1000.0
        offset = round(phone - now, 3)
        if self.ntp_synchronized():
            return {"applied": False, "reason": "ntp_synchronized",
                    "offset_s": offset, "source": "ntp"}
        if abs(offset) < 2:
            with self._lock:
                self.phone_synced_at = now
                self.phone_offset_s = offset
            return {"applied": False, "reason": "already_within_2s",
                    "offset_s": offset, "source": "phone"}
        try:
            subprocess.run(["date", "-u", "-s", f"@{phone:.3f}"], check=True,
                           capture_output=True, timeout=5)
        except (OSError, subprocess.SubprocessError) as e:
            return {"applied": False, "reason": f"date failed: {e}",
                    "offset_s": offset, "source": self.source()}
        with self._lock:
            self.phone_synced_at = time.time()
            self.phone_offset_s = offset
        return {"applied": True, "offset_s": offset, "source": "phone"}

    def status(self):
        with self._lock:
            return {
                "source": self.source(),
                "phone_synced_at": self.phone_synced_at,
                "phone_offset_s": self.phone_offset_s,
                "epoch_ms": int(time.time() * 1000),
            }


def telemetry(iface):
    used, total = storage("/")
    return {
        "cpu_load": cpu_load(),
        "memory_used": memory_used(),
        "temperature_c": temperature_c(),
        "uptime_s": uptime_seconds(),
        "storage_used_gb": used,
        "storage_total_gb": total,
        "interface": iface,
        "interface_present": os.path.exists(f"/sys/class/net/{iface}"),
        "interface_mode": interface_mode(iface),
        "hostname": hostname(),
        "ips": local_ips(),
        "version": VERSION,
    }
