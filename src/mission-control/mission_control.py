#!/usr/bin/env python3
"""Mission Control — receives the track feed and computes the availability metric.

Availability is measured on TRACKS, not on the host being up:

    availability = authenticated tracks received / tracks expected

over a rolling window. Expected tracks are (sweeps seen in the window) x
(sectors per sweep); received are the authenticated sectors actually present. A
blinded sector therefore shows up immediately as ~5/6, and recovering it shows
up within one window.

Tracks are authenticated with an HMAC shared only with the real sensor. Forged
tracks (the adversary's "corrupted data enters the grid" objective) fail
authentication and are counted separately, so a blind sector cannot be masked by
injecting fakes.

Two counters drive the verifier's hard gates:
  * availability -- catches blinding / track loss (rolling window)
  * max_gap      -- catches the tracker being down for more than a short window
"""
import hashlib
import hmac
import json
import os
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRET = os.environ.get("TRACK_HMAC_SECRET", "sw-lab-track-secret").encode()
INTERVAL = float(os.environ.get("TRACK_INTERVAL", "2"))
SECTORS = int(os.environ.get("SECTOR_COUNT", "6"))
WINDOW = float(os.environ.get("AVAILABILITY_WINDOW", "60"))
SENSOR = "sentinel-01"

STATE_DIR = "/var/lib/mission-control"
os.makedirs(STATE_DIR, exist_ok=True)
TRACKS_LOG = os.path.join(STATE_DIR, "tracks.jsonl")
FORGERY_LOG = os.path.join(STATE_DIR, "forgeries.jsonl")

_lock = threading.Lock()
_state = {
    "t0": None,
    "last_ts": None,
    "received_total": 0,
    "forged": 0,
    "max_gap": 0.0,
    "sectors_seen": set(),
    "sweeps": {},          # seq -> {"ts": recv_time, "sectors": set()}
}


def _canonical(rec):
    return f"{rec['sensor']}|{rec['sector']}|{rec['seq']}|{rec['ts']}"


class TrackHandler(socketserver.StreamRequestHandler):
    def handle(self):
        for raw in self.rfile:
            line = raw.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                sector = int(rec["sector"])
                seq = int(rec["seq"])
                given = rec["hmac"]
            except (ValueError, KeyError, TypeError):
                continue

            expect = hmac.new(SECRET, _canonical(rec).encode(), hashlib.sha256).hexdigest()
            ok = hmac.compare_digest(expect, str(given))
            now = time.time()

            with _lock:
                if not ok:
                    _state["forged"] += 1
                    with open(FORGERY_LOG, "a") as fh:
                        fh.write(json.dumps(
                            {"ts": now, "src": self.client_address[0],
                             "sector": sector, "seq": seq}) + "\n")
                    continue

                if _state["t0"] is None:
                    _state["t0"] = now
                if _state["last_ts"] is not None:
                    gap = now - _state["last_ts"]
                    if gap > _state["max_gap"]:
                        _state["max_gap"] = gap
                _state["last_ts"] = now
                _state["received_total"] += 1
                _state["sectors_seen"].add(sector)

                sweep = _state["sweeps"].setdefault(seq, {"ts": now, "sectors": set()})
                sweep["sectors"].add(sector)
                sweep["ts"] = now

                with open(TRACKS_LOG, "a") as fh:
                    fh.write(json.dumps(rec, sort_keys=True) + "\n")


def stats():
    with _lock:
        now = time.time()
        lo = now - WINDOW
        recent = [s for s in _state["sweeps"].values() if s["ts"] >= lo]
        expected = len(recent) * SECTORS
        received = sum(len(s["sectors"]) for s in recent)
        avail = (received / expected) if expected else 0.0
        seen = sorted(_state["sectors_seen"])
        return {
            "sensor": SENSOR,
            "received": received,
            "received_total": _state["received_total"],
            "forged": _state["forged"],
            "expected": expected,
            "availability": round(min(avail, 1.0), 4),
            "window_seconds": WINDOW,
            "max_gap": round(_state["max_gap"], 2),
            "sectors_seen": seen,
            "missing_sectors": [s for s in range(1, SECTORS + 1) if s not in _state["sectors_seen"]],
            "sector_count": SECTORS,
            "interval": INTERVAL,
            "t0": _state["t0"],
            "last_ts": _state["last_ts"],
            "now": now,
        }


class Dashboard(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(stats(), indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    ingest = ReusableTCPServer(("0.0.0.0", 9000), TrackHandler)
    threading.Thread(target=ingest.serve_forever, daemon=True).start()
    HTTPServer(("0.0.0.0", 8000), Dashboard).serve_forever()


if __name__ == "__main__":
    main()
