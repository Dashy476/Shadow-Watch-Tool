#!/usr/bin/env python3
"""Detection-uptime check for the three-host practice lab.

Confirms the console is up, a signed-in diagnostics export has a recent
track, and OPS-03 has retained a forwarded line. There is no flag grade.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import http.cookiejar

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASSWD = os.path.join(ROOT, "images", "console.passwd")
CONSOLE = "http://127.0.0.1:8080"
CONTAINERS = ("sw-sentinel-01", "sw-edge-02", "sw-ops-03")


def account() -> tuple[str, str]:
    with open(PASSWD, encoding="utf-8") as handle:
        line = handle.readline().strip()
    user, password = line.split(":", 1)
    return user, password


def running(name: str) -> bool:
    result = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", name],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def forwarded_line() -> str:
    result = subprocess.run(
        ["docker", "exec", "sw-ops-03", "tail", "-n", "20", "/var/log/sentinel/forwarded.log"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return ""
    for line in reversed(result.stdout.splitlines()):
        if "track " in line:
            return line.strip()
    return ""


def console_export() -> tuple[str, dict | None]:
    try:
        with urllib.request.urlopen(CONSOLE + "/health", timeout=3) as response:
            health = json.loads(response.read().decode("utf-8"))
        if not health.get("ok"):
            return "console health did not report ok", None
    except Exception as exc:  # noqa: BLE001
        return f"console health failed: {exc}", None
    user, password = account()
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    body = urllib.parse.urlencode({"username": user, "password": password}).encode("utf-8")
    try:
        opener.open(CONSOLE + "/login", body, timeout=5)
        with opener.open(CONSOLE + "/diagnostics/export", timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return f"diagnostics export returned {exc.code}", None
    except Exception as exc:  # noqa: BLE001
        return f"diagnostics export failed: {exc}", None
    if payload.get("export") != "diagnostics":
        return "diagnostics export missing", None
    return "", payload


def collect() -> list[tuple[str, bool, str]]:
    checks = []
    for name in CONTAINERS:
        up = running(name)
        checks.append((name, up, "running" if up else "not running"))
    error, payload = console_export()
    if error:
        checks.append(("console export", False, error))
    else:
        latest = payload.get("latest_unix")
        count = payload.get("track_count") or 0
        if not latest or count < 1:
            checks.append(("console export", False, "signed in, no detections yet"))
        else:
            age = time.time() - float(latest)
            fresh = age <= 30
            checks.append((
                "console export",
                fresh,
                f"{count} tracks, latest {age:.0f}s ago",
            ))
    line = forwarded_line()
    checks.append((
        "ops log vault",
        bool(line),
        line if line else "no forwarded track line in /var/log/sentinel/forwarded.log",
    ))
    return checks


def report(checks: list[tuple[str, bool, str]]) -> int:
    failed = 0
    for name, ok, detail in checks:
        mark = "PASS" if ok else "FAIL"
        if not ok:
            failed += 1
        print(f"  {mark}  {name}: {detail}")
    print()
    if failed:
        print(f"detection uptime: {failed} check(s) failed")
        return 1
    print("detection uptime: console, detections, and log forwarding are current")
    return 0


def main() -> int:
    wait = 0
    if len(sys.argv) >= 3 and sys.argv[1] == "--wait":
        wait = max(0, int(sys.argv[2]))
    deadline = time.time() + wait
    while True:
        checks = collect()
        if all(ok for _, ok, _ in checks) or time.time() >= deadline:
            return report(checks)
        time.sleep(2)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(1)
