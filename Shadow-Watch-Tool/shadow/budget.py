"""45-minute evidence timer and soft 3-hour phase nudges.

The evidence window starts at the Phase 2 baseline snapshot, not at SSH connect.
"""

from __future__ import annotations

WINDOW_S = 45 * 60
WARN_S = 10 * 60

# Soft budgets. Landing covers connect, fingerprint, module copy, and the
# human review before the baseline snapshot exists.
PHASE_BUDGET_S = {
    "land": 15 * 60,
    "observe": 60 * 60,
    "contain": 45 * 60,
    "writeup": 30 * 60,
}

PHASE_LABEL = {
    "land": "landing/snapshot/topology",
    "observe": "observation/differentiation",
    "contain": "containment",
    "writeup": "writeup",
}


def format_mmss(seconds: int) -> str:
    minutes, secs = divmod(max(0, int(seconds)), 60)
    return f"{minutes:02d}:{secs:02d}"


def remaining(baseline_unix: float | None, now: float) -> tuple[str, bool, bool]:
    """Return (mm:ss or not-started, prefix_alerts, expired)."""
    if baseline_unix is None:
        return "not-started", False, False
    left = WINDOW_S - (now - baseline_unix)
    if left <= 0:
        return "00:00", True, True
    return format_mmss(left), left <= WARN_S, False


def nudge_for(phase: str, started_unix: float | None, now: float) -> str | None:
    budget = PHASE_BUDGET_S.get(phase)
    if budget is None or started_unix is None:
        return None
    elapsed = now - started_unix
    if elapsed <= budget:
        return None
    label = PHASE_LABEL.get(phase, phase)
    return (
        f"NUDGE: {label} budget is {format_mmss(budget)} and this phase has run "
        f"{format_mmss(elapsed)}. Move on when you can."
    )


def format_alert(ts: str, text: str, timer_label: str, prefix: bool, expired: bool) -> str:
    if prefix and expired:
        head = "[T-00:00 EXPIRED] "
    elif prefix:
        head = f"[T-{timer_label}] "
    else:
        head = ""
    return f"{head}[{ts}] {text}"
