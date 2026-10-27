#!/usr/bin/env python3
"""Record the no-restart baseline. Run right after `up`.

Captures each host's Start time and restart count. From here on, any change to
either fails the verifier's G1 gate -- the brief says SENTINEL-01 must remain
online, so restarting it is not an option.
"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE = os.path.join(ROOT, "flags", "baseline.json")

HOSTS = {
    "relay": "sw-relay",
    "console": "sw-console",
    "mission_control": "sw-mission-control",
    "sentinel_01": "sw-sentinel-01",
    "sentinel_02": "sw-sentinel-02",
    "analyst": "sw-analyst",
}


def main():
    out = {}
    for key, name in HOSTS.items():
        p = subprocess.run(["docker", "inspect", name], capture_output=True, text=True)
        if p.returncode != 0:
            print(f"cannot inspect {name}: {p.stderr.strip()}")
            return 1
        data = json.loads(p.stdout)[0]
        out[key] = {
            "started_at": data["State"]["StartedAt"],
            "restart_count": data["RestartCount"],
        }
    os.makedirs(os.path.dirname(BASELINE), exist_ok=True)
    with open(BASELINE, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"baseline recorded -> {BASELINE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
