"""Beacon and cadence checks, adapted from gg_t3 periodicity math.

Flows are socket observations and write-byte deltas. No message types are assumed.
"""

from __future__ import annotations

import statistics
from itertools import pairwise

from shadow.procparse import is_loopback, is_unspecified
from shadow.snapshot import alert


def intervals(timestamps: list[float]) -> list[float]:
    if len(timestamps) < 2:
        return []
    ordered = sorted(timestamps)
    return [b - a for a, b in pairwise(ordered)]


def is_periodic(samples: list[float], expected: float, tolerance: float) -> tuple[bool, dict]:
    """A stream is periodic when the mean is inside tolerance and CV stays under 0.5."""
    if not samples:
        return True, {"sample_count": 0}
    mean = statistics.fmean(samples)
    stdev = statistics.pstdev(samples) if len(samples) > 1 else 0.0
    cv = (stdev / mean) if mean > 0 else float("inf")
    drift = abs(mean - expected) if expected else 0.0
    ok = drift <= tolerance and cv < 0.5
    return ok, {
        "sample_count": len(samples),
        "mean_s": round(mean, 4),
        "stdev_s": round(stdev, 4),
        "cv": round(cv, 4),
        "drift_s": round(drift, 4),
        "expected_s": expected,
        "tolerance_s": tolerance,
    }


def _outbound(snapshot: dict) -> list[dict]:
    rows = []
    for row in snapshot.get("sockets") or []:
        remote = row.get("remote_ip") or ""
        if row.get("state") not in {"ESTABLISHED", "SYN_SENT"}:
            continue
        if not remote or is_loopback(remote) or is_unspecified(remote):
            continue
        rows.append(row)
    return rows


def _pid_for_inode(snapshot: dict, inode: str) -> dict | None:
    marker = f"socket:[{inode}]"
    for proc in snapshot.get("processes") or []:
        if proc.get("tool"):
            continue
        for fd in proc.get("fds") or []:
            if fd.get("target") == marker:
                return proc
    return None


def inspect(history: list[dict]) -> list[dict]:
    if len(history) < 4:
        return []
    series: dict[tuple, list[float]] = {}
    sizes: dict[tuple, list[int]] = {}
    comms: dict[tuple, str] = {}
    for snap in history:
        try:
            when = float(snap.get("operator_unix") or 0)
        except (TypeError, ValueError):
            when = 0.0
        for row in _outbound(snap):
            proc = _pid_for_inode(snap, str(row.get("inode")))
            pid = proc.get("pid") if proc else 0
            key = (row.get("proto"), row.get("remote_ip"), int(row.get("remote_port") or 0), pid)
            series.setdefault(key, []).append(when)
            comms[key] = (proc or {}).get("comm") or ""
            if proc is not None:
                sizes.setdefault(key, []).append(int(proc.get("write_bytes") or 0))

    alerts = []
    for key, times in series.items():
        ivs = intervals([item for item in times if item])
        if len(ivs) < 3:
            continue
        expected = statistics.median(ivs)
        ok, stats = is_periodic(ivs, expected, max(0.5, expected * 0.25))
        deltas = _positive_deltas(sizes.get(key) or [])
        mean_size = statistics.fmean(deltas) if deltas else 0
        if ok and mean_size and mean_size < 512:
            proto, ip, port, pid = key
            alerts.append(alert(
                "beacon", "small-periodic", "high",
                f"small periodic outbound {ip}:{port} pid={pid} comm={comms.get(key)}",
                {"proto": proto, "remote_ip": ip, "remote_port": port, "pid": pid,
                 "comm": comms.get(key), "mean_size": round(mean_size, 1), **stats},
                confidence=0.75,
            ))
        elif not ok:
            proto, ip, port, pid = key
            alerts.append(alert(
                "beacon", "cadence-divergence", "medium",
                f"cadence divergence {ip}:{port} pid={pid} comm={comms.get(key)}",
                {"proto": proto, "remote_ip": ip, "remote_port": port, "pid": pid, **stats},
                confidence=0.6,
            ))
    return alerts


def _positive_deltas(values: list[int]) -> list[int]:
    deltas = []
    for prev, cur in pairwise(values):
        if cur >= prev:
            deltas.append(cur - prev)
    return deltas
