"""Trust-surface checks, adapted from gg_t10.

Signing-material permissions, new peers, and identity inventories in configs.
The collector stats a bounded path list. This module only reads that snapshot.
"""

from __future__ import annotations

from shadow.procparse import is_loopback, is_unspecified
from shadow.snapshot import alert


def inspect(baseline: dict | None, current: dict) -> list[dict]:
    alerts = []
    alerts.extend(_material(current))
    alerts.extend(_inventory(current))
    alerts.extend(_new_peers(baseline, current))
    alerts.extend(_policy_drift(baseline, current))
    return alerts


def _material(snapshot: dict) -> list[dict]:
    alerts = []
    for row in snapshot.get("perm_records") or []:
        if not row.get("signing"):
            continue
        world = bool(row.get("world_read") or row.get("world_write"))
        group = bool(row.get("group_read"))
        if not (world or group):
            continue
        alerts.append(alert(
            "trust", "trust-material", "high",
            f"signing material {row.get('path')} is readable outside the owner",
            {"path": row.get("path"), "mode": row.get("mode"), "owner": row.get("owner"),
             "group": row.get("group")},
            confidence=0.85,
        ))
    return alerts


def _inventory(snapshot: dict) -> list[dict]:
    alerts = []
    for doc in snapshot.get("configs") or []:
        raw = doc.get("data") or {}
        if not isinstance(raw, dict):
            continue
        peers = []
        for value in raw.values():
            if isinstance(value, list):
                peers.extend(item for item in value if isinstance(item, dict))
        complete = [
            peer for peer in peers
            if (peer.get("ip") or peer.get("host")) and (peer.get("public_key") or peer.get("key") or peer.get("uuid"))
        ]
        if len(complete) >= 3:
            alerts.append(alert(
                "trust", "identity-inventory", "high",
                f"config {doc.get('path')} lists {len(complete)} peer trust records",
                {"path": doc.get("path"), "peers": len(complete)},
                confidence=0.7,
            ))
    return alerts


def _peer_ips(snapshot: dict | None) -> set[str]:
    found = set()
    if not snapshot:
        return found
    for row in snapshot.get("sockets") or []:
        ip = row.get("remote_ip") or ""
        if ip and not is_loopback(ip) and not is_unspecified(ip):
            found.add(ip)
    for row in snapshot.get("arp") or []:
        ip = row.get("ip") or ""
        if ip and not is_loopback(ip):
            found.add(ip)
    return found


def _new_peers(baseline: dict | None, current: dict) -> list[dict]:
    if baseline is None:
        return []
    known = _peer_ips(baseline)
    alerts = []
    for ip in sorted(_peer_ips(current) - known):
        alerts.append(alert(
            "trust", "new-peer", "medium",
            f"trust surface expanded to {ip}",
            {"remote_ip": ip},
            confidence=0.6,
        ))
    return alerts


def _policy_drift(baseline: dict | None, current: dict) -> list[dict]:
    """Modal verify_signatures across configs in one snapshot, plus baseline drift."""
    if baseline is None:
        return []
    base_values = _verify_values(baseline)
    cur_values = _verify_values(current)
    if not base_values or not cur_values:
        return []
    base_mode = _mode(base_values)
    alerts = []
    for path, value in cur_values.items():
        if value != base_mode and (path not in base_values or base_values[path] != value):
            alerts.append(alert(
                "trust", "policy-drift", "high",
                f"verify_signatures on {path} is {value}; baseline mode is {base_mode}",
                {"path": path, "value": value, "baseline": base_mode},
                confidence=0.75,
            ))
    return alerts


def _verify_values(snapshot: dict) -> dict[str, object]:
    found = {}
    for doc in snapshot.get("configs") or []:
        data = doc.get("data") or {}
        if isinstance(data, dict) and "verify_signatures" in data:
            found[doc.get("path") or ""] = data.get("verify_signatures")
    return found


def _mode(values: dict) -> object:
    counts: dict[object, int] = {}
    for value in values.values():
        counts[value] = counts.get(value, 0) + 1
    return max(counts, key=lambda item: counts[item])


