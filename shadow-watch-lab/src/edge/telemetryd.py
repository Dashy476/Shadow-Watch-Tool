#!/usr/bin/env python3
"""EDGE-02 telemetry receiver.

The SENSOR that would feed this host is out of scope, so aircraft telemetry
is generated here and turned into detections for SENTINEL-01. One TCP
session to the sentinel ingest port stays up between detections.
"""

from __future__ import annotations

import json
import os
import socket
import time

SENTINEL_IP = os.environ.get("SENTINEL_IP", "10.80.40.11")
INGEST_PORT = int(os.environ.get("INGEST_PORT", "9000"))
INTERVAL = float(os.environ.get("TRACK_INTERVAL", "4"))
DETECTION_PATH = os.environ.get("DETECTION_PATH", "/var/lib/edge/detections/latest.json")
TELEMETRY_LOG = os.environ.get("TELEMETRY_LOG", "/var/log/edge/telemetry.log")
CLASSES = ("friendly", "hostile", "unknown")


def detection(number: int) -> dict:
    kind = CLASSES[number % len(CLASSES)]
    now = int(time.time())
    points = []
    for step in range(5):
        points.append(
            {
                "t": now - (4 - step),
                "lat": round(38.85 + (number % 7) * 0.01 + step * 0.002, 5),
                "lon": round(-104.80 + (number % 5) * 0.01 + step * 0.003, 5),
                "alt": 80 + (number % 40) + step * 5,
            }
        )
    return {
        "id": f"EDGE-{number:04d}",
        "class": kind,
        "callsign": f"UAS-{(number % 90) + 10}",
        "source": "EDGE-02",
        "points": points,
    }


def remember(payload: dict, log_fh) -> None:
    text = json.dumps(payload)
    export = open(DETECTION_PATH, "w", encoding="utf-8")
    export.write(text)
    export.flush()
    # Hold the descriptor open across calls by stashing it on the function.
    previous = getattr(remember, "export", None)
    if previous is not None and previous is not export:
        previous.close()
    remember.export = export
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    log_fh.write(f"{stamp} telemetry id={payload['id']} class={payload['class']}\n")
    log_fh.flush()


def main() -> None:
    os.makedirs(os.path.dirname(DETECTION_PATH), exist_ok=True)
    os.makedirs(os.path.dirname(TELEMETRY_LOG), exist_ok=True)
    log_fh = open(TELEMETRY_LOG, "a", encoding="utf-8")
    number = 1
    while True:
        try:
            print(f"[telemetryd] connecting to {SENTINEL_IP}:{INGEST_PORT}", flush=True)
            with socket.create_connection((SENTINEL_IP, INGEST_PORT), timeout=5) as sock:
                while True:
                    payload = detection(number)
                    sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))
                    remember(payload, log_fh)
                    print(f"[telemetryd] sent {payload['id']} {payload['class']}", flush=True)
                    number += 1
                    time.sleep(INTERVAL)
        except OSError as exc:
            print(f"[telemetryd] {exc}; retrying", flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()
