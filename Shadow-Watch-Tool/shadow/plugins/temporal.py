"""Clock skew and track-output gaps, adapted from gg_t17 latency checks.

Guilded Guardian kill-box and intercept counters are not used. Those belonged
to a different mission. The retained signal is time: skew drift and silence.
"""

from __future__ import annotations

import statistics
from itertools import pairwise

from shadow.snapshot import alert

SKEW_DRIFT_S = 5.0
GAP_FACTOR = 3.0


def inspect(baseline: dict | None, history: list[dict]) -> list[dict]:
    if baseline is None or len(history) < 2:
        return []
    alerts = []
    alerts.extend(_skew(baseline, history[-1]))
    alerts.extend(_silence(history))
    return alerts


def _skew(baseline: dict, current: dict) -> list[dict]:
    base = baseline.get("clock_skew_s")
    cur = current.get("clock_skew_s")
    if base is None or cur is None:
        return []
    drift = abs(float(cur) - float(base))
    if drift < SKEW_DRIFT_S:
        return []
    return [alert(
        "temporal", "clock-drift", "high",
        f"node clock skew moved by {drift:.1f}s from the baseline",
        {"baseline_skew_s": base, "current_skew_s": cur, "drift_s": round(drift, 3)},
        confidence=0.7,
    )]


def _silence(history: list[dict]) -> list[dict]:
    """Flag a pipeline-like process whose writes stop for several intervals."""
    by_pid: dict[int, list[tuple[float, int, str]]] = {}
    for snap in history:
        try:
            when = float(snap.get("operator_unix") or 0)
        except (TypeError, ValueError):
            continue
        for proc in snap.get("processes") or []:
            if proc.get("tool"):
                continue
            pid = int(proc.get("pid") or 0)
            if not pid:
                continue
            by_pid.setdefault(pid, []).append((when, int(proc.get("write_bytes") or 0), proc.get("comm") or ""))
    alerts = []
    for pid, samples in by_pid.items():
        if len(samples) < 4:
            continue
        times = [item[0] for item in samples if item[0]]
        if len(times) < 4:
            continue
        ivs = [b - a for a, b in pairwise(times)]
        typical = statistics.median(ivs) if ivs else 0
        if typical <= 0:
            continue
        last_gap = times[-1] - times[-2]
        write_delta = samples[-1][1] - samples[-2][1]
        if last_gap > typical * GAP_FACTOR and write_delta <= 0:
            alerts.append(alert(
                "temporal", "output-gap", "medium",
                f"pid {pid} comm={samples[-1][2]} produced no writes across a {last_gap:.1f}s gap",
                {"pid": pid, "comm": samples[-1][2], "gap_s": round(last_gap, 3),
                 "typical_s": round(typical, 3)},
                confidence=0.65,
            ))
    return alerts
