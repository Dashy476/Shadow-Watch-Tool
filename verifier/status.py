#!/usr/bin/env python3
"""One-glance lab status: hosts, availability, forged tracks, wipe countdown."""
import json
import subprocess
import urllib.request

try:
    with urllib.request.urlopen("http://127.0.0.1:8000", timeout=5) as r:
        s = json.loads(r.read())
    print(f"availability  : {s['availability']:.1%}  ({s['received']}/{s['expected']} tracks)")
    print(f"forged tracks : {s['forged']}")
    print(f"max gap       : {s['max_gap']}s")
    print(f"sectors seen  : {s['sectors_seen']}   missing: {s['missing_sectors']}")
except Exception as exc:  # noqa: BLE001
    print(f"mission-control :8000 not answering: {exc}")

print()
subprocess.run(["docker", "exec", "sw-sentinel-01", "systemctl", "list-timers",
                "logrotate-guard.timer", "--no-pager"])
