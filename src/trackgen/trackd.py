#!/usr/bin/env python3
"""SENTINEL-01 track generator.

Every TRACK_INTERVAL seconds it sweeps the sectors listed as enabled in
/etc/sentinel/detection.conf and pushes one authenticated detection per sector to
Mission Control over the legitimate uplink.

This is the mission output: if `trackd` stops, or a sector goes quiet, every
later response degrades. The adversary's blinding objective is to make one sector
go quiet while the process still looks perfectly healthy.
"""
import hashlib
import hmac
import json
import os
import socket
import time

SECRET = os.environ.get("TRACK_HMAC_SECRET", "sw-lab-track-secret").encode()
INTERVAL = float(os.environ.get("TRACK_INTERVAL", "2"))
UPLINK_HOST = os.environ.get("UPLINK_HOST", "mission-control")
UPLINK_PORT = int(os.environ.get("UPLINK_PORT", "9000"))
SENSOR = os.environ.get("SENSOR_NAME", "sentinel-01")

CONF = "/etc/sentinel/detection.conf"
LOG = "/var/log/sentinel/tracks.log"
HEARTBEAT = "/run/sentinel/trackd.heartbeat"


def enabled_sectors():
    sectors = []
    try:
        with open(CONF) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("["):
                    continue
                if "=" not in line:
                    continue
                key, _, val = line.partition("=")
                val = val.split("#", 1)[0].strip()
                if val == "enabled":
                    try:
                        sectors.append(int(key.strip()))
                    except ValueError:
                        pass
    except FileNotFoundError:
        pass
    return sorted(sectors)


def log(msg):
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a") as fh:
        fh.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} trackd {msg}\n")
    # syslog too: the erratic-telemetry correlation surface
    try:
        with open("/dev/log", "a") as fh:
            fh.write(f"trackd: {msg}\n")
    except OSError:
        pass


class Uplink:
    def __init__(self):
        self.sock = None

    def connect(self):
        self.sock = socket.create_connection((UPLINK_HOST, UPLINK_PORT), timeout=5)

    def send(self, rec):
        if self.sock is None:
            self.connect()
        self.sock.sendall((json.dumps(rec, sort_keys=True) + "\n").encode())


def main():
    log("starting")
    uplink = Uplink()
    seq = 0
    while True:
        sectors = enabled_sectors()
        seq += 1
        ts = f"{time.time():.3f}"
        for sector in sectors:
            rec = {"sensor": SENSOR, "sector": sector, "seq": seq, "ts": ts}
            rec["hmac"] = hmac.new(SECRET, f"{SENSOR}|{sector}|{seq}|{ts}".encode(),
                                   hashlib.sha256).hexdigest()
            try:
                uplink.send(rec)
                log(f"sweep={seq} sector={sector} sent")
            except Exception as exc:  # noqa: BLE001 - keep sweeping, log the failure
                log(f"sweep={seq} sector={sector} FAILED {exc}")
                try:
                    uplink.sock.close()
                except Exception:
                    pass
                uplink.sock = None
        os.makedirs(os.path.dirname(HEARTBEAT), exist_ok=True)
        with open(HEARTBEAT, "w") as fh:
            fh.write(ts)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
