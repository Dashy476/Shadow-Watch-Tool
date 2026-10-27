#!/usr/bin/env python3
"""Shadow Watch response verifier.

Grades the analyst's live response against the brief's hard gates and, only if
every gate passes, emits the flag.

Hard gates (from the brief):
  G1  SENTINEL-01 was never restarted / recreated   ("must remain online")
  G2  availability >= AVAILABILITY_MIN              ("tracks ... enable response")
  G3  max_gap <= MAX_GAP_SECONDS and feed is live   ("down more than a short window")
  G4  no missing sectors                            ("detect the unseen" / blinding)
  G5  SENTINEL-02 is clean                          ("or pivot further into the grid")
  G6  exfil flow stopped                            ("active outbound traffic" cut)
  G7  evidence-wipe job did not fire                ("before the adversary erases evidence")
  G8  all four flag fragments recovered             (evidence collected, not destroyed)

Run from the host (repo root):
    python verifier/verify.py
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(ROOT, "compose", ".env")
BASELINE = os.path.join(ROOT, "flags", "baseline.json")
REPORT = os.path.join(ROOT, "response", "recovered.txt")

CONTAINERS = {
    "relay": "sw-relay",
    "console": "sw-console",
    "mission_control": "sw-mission-control",
    "sentinel_01": "sw-sentinel-01",
    "sentinel_02": "sw-sentinel-02",
    "analyst": "sw-analyst",
}

# The fragment values are deliberately NOT in this file -- only their digests.
# Opening the verifier to see why a gate failed is a reasonable thing for an
# analyst to do, and it should not hand them the answer key. The flag is
# assembled at the end from the values the analyst actually collected, so this
# file can grade the response without ever knowing it.
#
# Listed in flag order; the second element is the location hint G8 prints.
FRAGMENTS = [
    ("e27a8c7228e475a784aa5b5762f5bee22aa40c62a51bd46c20ba9cb273ce2696",
     "implant process environment (/proc/<pid>/environ) on sentinel-01"),
    ("d7d34f8de8ef5cf7cddda126c45f59df33e9b06c9038ca76c678f0671f848b6e",
     "staged exfil export in /dev/shm on sentinel-01"),
    ("8633548126b18524b18f39b351b0c721e792dc9bb5ead4e62bd97e1a2648d0c7",
     "the partner IOC advisory"),
    ("fbb8e083bee6b364fd321ae150de6127401fea093b6b4f1ab81e566521d50ac4",
     "the reused credential at the console"),
]

# Fragment shape: four to six letters, a dash, four hex digits. Matching on
# shape first keeps us from hashing every word in the report.
FRAGMENT_RE = re.compile(r"[A-Z]{3,6}-[0-9A-F]{4}")


def fragment_digest(token):
    return hashlib.sha256(token.strip().upper().encode()).hexdigest()


def read_env():
    env = {}
    if os.path.exists(ENV_FILE):
        for line in open(ENV_FILE, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip()
    return env


def _norm(key):
    """Host keys are written as 'sentinel-01' by lab.ps1 and 'sentinel_01' by
    verifier/baseline.py. Normalize so a baseline from either writer matches."""
    return key.replace("-", "_")


def sh(args, timeout=15):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return 1, "", str(exc)


def exec_in(container, cmd, timeout=15):
    return sh(["docker", "exec", container, "sh", "-c", cmd], timeout=timeout)


def exec_py(container, script, timeout=15):
    return sh(["docker", "exec", container, "python3", "-c", script], timeout=timeout)


def inspect(container):
    rc, out, _ = sh(["docker", "inspect", container])
    if rc != 0:
        return None
    data = json.loads(out)[0]
    return {
        "started_at": data["State"]["StartedAt"],
        "restart_count": data["RestartCount"],
        "running": data["State"]["Running"],
    }


def main():
    env = read_env()
    avail_min = float(env.get("AVAILABILITY_MIN", "0.95"))
    max_gap = float(env.get("MAX_GAP_SECONDS", "15"))
    interval = float(env.get("TRACK_INTERVAL", "2"))

    results = []
    notes = {}

    def gate(name, ok, detail):
        results.append((name, ok, detail))

    # --- baseline: nothing may be restarted -------------------------------
    baseline = {}
    if os.path.exists(BASELINE):
        baseline = json.load(open(BASELINE))
    cur = {}
    for key, name in CONTAINERS.items():
        info = inspect(name)
        if info:
            cur[_norm(key)] = info
    restarted = []
    if not baseline:
        gate("G1 SENTINEL-01 never restarted", False,
             "no baseline recorded -- run `lab.ps1 up` to capture it")
    else:
        for key, base in baseline.items():
            now = cur.get(_norm(key))
            if not now:
                restarted.append(f"{key}: missing")
            elif now["restart_count"] != base["restart_count"]:
                restarted.append(f"{key}: restart_count {base['restart_count']}->{now['restart_count']}")
            elif now["started_at"] != base["started_at"]:
                restarted.append(f"{key}: StartedAt changed")
            elif not now["running"]:
                restarted.append(f"{key}: not running")
        if restarted:
            gate("G1 SENTINEL-01 never restarted", False,
                 "hosts restarted/recreated: " + "; ".join(restarted))
        else:
            gate("G1 SENTINEL-01 never restarted", True, "start time and restart count unchanged")

    # --- availability -----------------------------------------------------
    stats = None
    try:
        with urllib.request.urlopen("http://127.0.0.1:8000", timeout=5) as resp:
            stats = json.loads(resp.read())
    except Exception as exc:  # noqa: BLE001
        gate("G2 availability", False, f"mission-control unreachable: {exc}")

    if stats is not None:
        avail = stats["availability"]
        gate("G2 availability >= %.2f" % avail_min, avail >= avail_min,
             f"availability={avail:.4f} ({stats['received']}/{stats['expected']} tracks)")

        gap = stats["max_gap"]
        live = (stats["now"] - (stats["last_ts"] or 0)) <= (interval * 3 + 5)
        gate("G3 no outage > %.0fs and feed live" % max_gap, gap <= max_gap and live,
             f"max_gap={gap:.1f}s feed_live={live}")

        missing = stats["missing_sectors"]
        gate("G4 all sectors reporting", not missing,
             f"sectors_seen={stats['sectors_seen']} missing={missing}")

    # --- second sensor clean ---------------------------------------------
    planted = exec_in(CONTAINERS["sentinel_02"], "test -f /opt/sentinel/.planted")
    backcron = exec_in(CONTAINERS["sentinel_02"], "test -f /etc/cron.d/sw-back")
    proc2 = exec_in(CONTAINERS["sentinel_02"], "pgrep -f 'shadow_agent[.]py'")
    clean2 = planted[0] != 0 and backcron[0] != 0 and proc2[0] != 0
    gate("G5 SENTINEL-02 is clean", clean2,
         "foothold present" if not clean2 else "no foothold, no back-pivot, no implant")

    # --- exfil stopped ----------------------------------------------------
    script = (
        "import json,os,time\n"
        "p='/var/lib/c2/loot.jsonl'\n"
        "print(9999 if not os.path.exists(p) else "
        "(9999 if not [l for l in open(p) if l.strip()] else "
        "round(time.time()-json.loads([l for l in open(p) if l.strip()][-1])['ts'],1)))\n"
    )
    rc, out, _ = exec_py(CONTAINERS["relay"], script)
    age = float(out) if rc == 0 and out else 9999.0
    gate("G6 exfil flow stopped", age > 60,
         f"last exfil payload {age:.0f}s ago" if age != 9999 else "no exfil payloads recorded")

    # --- wipe did not fire ------------------------------------------------
    wiped = exec_in(CONTAINERS["sentinel_01"], "test -f /var/lib/.guard_done")
    gate("G7 evidence-wipe job never fired", wiped[0] != 0,
         "wipe job already ran -- evidence destroyed" if wiped[0] == 0 else "wipe job did not run")

    # --- fragments recovered ---------------------------------------------
    text = open(REPORT, encoding="utf-8").read() if os.path.exists(REPORT) else ""
    # Hash every fragment-shaped token the analyst wrote down and match by
    # digest, so the expected values never appear in this file.
    collected = {fragment_digest(t): t for t in FRAGMENT_RE.findall(text.upper())}
    recovered = [collected.get(d) for d, _ in FRAGMENTS]
    missing_frags = [hint for (_, hint), val in zip(FRAGMENTS, recovered) if val is None]
    # Name WHERE a missing fragment lives, never the fragment itself -- printing the
    # values here would let anyone pass this gate by copying the failure message,
    # skipping the evidence collection the exercise is built around.
    gate("G8 all four fragments recovered", not missing_frags,
         "missing {} of {} -- look in: {}".format(
             len(missing_frags), len(FRAGMENTS), "; ".join(missing_frags))
         if missing_frags else "all four present")

    # --- report -----------------------------------------------------------
    print("\nShadow Watch - response verification\n" + "=" * 42)
    for name, ok, detail in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}\n        {detail}")
    total = sum(1 for _, ok, _ in results if ok)
    print("=" * 42)
    print(f"gates passed: {total}/{len(results)}")

    if all(ok for _, ok, _ in results):
        # Built from the analyst's own recovered values, not from a stored copy.
        print("\n  *** DECRYPTED FLAG ***")
        print("  SHADOWWATCH{" + "-".join(recovered) + "}\n")
        return 0

    print("\nNo flag: fix the failing gates and re-run.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
