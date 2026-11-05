#!/usr/bin/env python3
"""Forward SENTINEL-01 track lines to OPS-03.

This is the log-forwarding flow on the team diagram. It tails the console
track log and keeps one TCP connection to OPS-03. It does not read the
console password file.
"""

from __future__ import annotations

import os
import socket
import time

OPS_IP = os.environ.get("OPS_IP", "10.80.40.13")
LOG_PORT = int(os.environ.get("LOG_PORT", "1514"))
TRACK_LOG = os.environ.get("TRACK_LOG", "/var/log/sentinel/tracks.log")


def follow(path: str):
    while not os.path.exists(path):
        print(f"[log-forward] waiting for {path}", flush=True)
        time.sleep(1)
    handle = open(path, "r", encoding="utf-8", errors="replace")
    handle.seek(0, os.SEEK_END)
    while True:
        line = handle.readline()
        if line:
            yield line
            continue
        time.sleep(0.4)


def send_forever() -> None:
    while True:
        try:
            print(f"[log-forward] connecting to {OPS_IP}:{LOG_PORT}", flush=True)
            with socket.create_connection((OPS_IP, LOG_PORT), timeout=5) as sock:
                sock.settimeout(None)
                for line in follow(TRACK_LOG):
                    text = line if line.endswith("\n") else line + "\n"
                    sock.sendall(text.encode("utf-8"))
        except OSError as exc:
            print(f"[log-forward] {exc}; retrying", flush=True)
            time.sleep(2)


if __name__ == "__main__":
    send_forever()
