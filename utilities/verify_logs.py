#!/usr/bin/env python3
"""
TwinGuard-SHA256: Forensic Log Verifier
=========================================
Standalone tool to verify the integrity of the forensic_log.json file.
Each entry's SHA-256 hash is recomputed and compared to the stored value.
Any discrepancy indicates tampering.

Usage:
    python3 verify_logs.py
    python3 verify_logs.py --log path/to/forensic_log.json
    python3 verify_logs.py --hash <sha256_hash>   # verify a single entry
"""

import sys
import json
import hashlib
import argparse
from datetime import datetime

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = MAGENTA = ""
    class Style:
        BRIGHT = RESET_ALL = ""


def verify_entry(entry: dict) -> tuple[bool, str, str]:
    """Returns (is_valid, stored_hash, computed_hash)."""
    stored = entry.get("sha256_hash", "")
    payload = {k: v for k, v in entry.items() if k != "sha256_hash"}
    raw = json.dumps(payload, sort_keys=True).encode()
    computed = hashlib.sha256(raw).hexdigest()
    return computed == stored, stored, computed


def load_log(path: str) -> list:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"{Fore.RED}[ERROR] Log file not found: {path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"{Fore.RED}[ERROR] Invalid JSON in log file: {e}")
        sys.exit(1)


def print_header():
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'═'*60}")
    print(f"  TwinGuard-SHA256 — Forensic Log Integrity Verifier")
    print(f"{'═'*60}{Style.RESET_ALL}\n")


def verify_all(log_path: str):
    print_header()
    entries = load_log(log_path)

    if not entries:
        print(f"{Fore.YELLOW}  No entries found in {log_path}")
        return

    print(f"  Log file : {log_path}")
    print(f"  Entries  : {len(entries)}\n")
    print(f"  {'#':<4} {'Timestamp':<28} {'SSID':<20} {'Severity':<8} {'Integrity'}")
    print(f"  {'─'*4} {'─'*28} {'─'*20} {'─'*8} {'─'*20}")

    valid_count   = 0
    invalid_count = 0

    for i, entry in enumerate(entries, 1):
        ok, stored, computed = verify_entry(entry)
        ts       = entry.get("timestamp", "?")[:26]
        ssid     = entry.get("ssid", "?")[:18]
        severity = entry.get("severity", "?")

        if ok:
            valid_count += 1
            status = f"{Fore.GREEN}✓ VALID"
        else:
            invalid_count += 1
            status = f"{Fore.RED}✗ TAMPERED!"

        print(f"  {i:<4} {ts:<28} {ssid:<20} {severity:<8} {status}")

        if not ok:
            print(f"       {Fore.RED}Stored  : {stored}")
            print(f"       {Fore.RED}Computed: {computed}")

    print(f"\n{'═'*60}")
    print(f"  SUMMARY:")
    print(f"  ✓ Valid   : {Fore.GREEN}{valid_count}{Style.RESET_ALL}")
    print(f"  ✗ Tampered: {Fore.RED}{invalid_count}{Style.RESET_ALL}")

    if invalid_count == 0:
        print(f"\n  {Fore.GREEN}{Style.BRIGHT}All entries verified — forensic chain intact.")
    else:
        print(f"\n  {Fore.RED}{Style.BRIGHT}WARNING: {invalid_count} entry/entries show signs of tampering!")
    print(f"{'═'*60}\n")


def verify_single(log_path: str, target_hash: str):
    print_header()
    entries = load_log(log_path)

    for entry in entries:
        if entry.get("sha256_hash") == target_hash:
            ok, stored, computed = verify_entry(entry)
            print(f"  Entry found:")
            print(f"  SSID      : {entry.get('ssid','?')}")
            print(f"  BSSID     : {entry.get('bssid','?')}")
            print(f"  Timestamp : {entry.get('timestamp','?')}")
            print(f"  Severity  : {entry.get('severity','?')}")
            print(f"  Reasons   : {', '.join(entry.get('reasons', []))}")
            print(f"\n  Stored Hash  : {stored}")
            print(f"  Computed Hash: {computed}")
            if ok:
                print(f"\n  {Fore.GREEN}{Style.BRIGHT}✓ Integrity verified — entry is authentic.")
            else:
                print(f"\n  {Fore.RED}{Style.BRIGHT}✗ HASH MISMATCH — entry has been tampered with!")
            print()
            return

    print(f"{Fore.YELLOW}  No entry found with hash: {target_hash}")


def main():
    parser = argparse.ArgumentParser(
        description="TwinGuard-SHA256 Forensic Log Verifier"
    )
    parser.add_argument("--log",  default="forensic_log.json", help="Path to forensic_log.json")
    parser.add_argument("--hash", default=None, help="Verify a single entry by its SHA-256 hash")
    args = parser.parse_args()

    if args.hash:
        verify_single(args.log, args.hash)
    else:
        verify_all(args.log)


if __name__ == "__main__":
    main()