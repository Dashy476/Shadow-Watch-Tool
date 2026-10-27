"""Read-only detection plugins adapted from the Guilded Guardian defense scripts."""

from __future__ import annotations

from shadow.plugins import beacon, ipc, temporal, trust


def run_plugins(baseline: dict | None, history: list[dict], json_enabled: bool) -> list[dict]:
    if not history:
        return []
    current = history[-1]
    alerts = []
    alerts.extend(ipc.inspect(baseline, current, json_enabled))
    alerts.extend(beacon.inspect(history))
    alerts.extend(temporal.inspect(baseline, history))
    alerts.extend(trust.inspect(baseline, current))
    return alerts
