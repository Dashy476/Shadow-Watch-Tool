"""IPC and JSON-socket checks, adapted from gg_t2.

Silent unless the baseline shows inter-node JSON. Other axes keep their weight.
This plugin never connects to a socket.
"""

from __future__ import annotations

from shadow.procparse import is_loopback, is_unspecified
from shadow.snapshot import alert

SIGNED_KEYS = {"sig", "signature", "msg_sig", "sign"}


def inter_node_json(snapshot: dict | None) -> bool:
    """True when a process both holds JSON and an established non-local socket."""
    if not snapshot:
        return False
    for proc in snapshot.get("processes") or []:
        if proc.get("tool"):
            continue
        if not any(head.get("json_keys") for head in proc.get("file_heads") or []):
            continue
        if _has_nonlocal_socket(proc, snapshot):
            return True
    return False


def _inode(target: str) -> str:
    if target.startswith("socket:[") and target.endswith("]"):
        return target[8:-1]
    return ""


def _has_nonlocal_socket(proc: dict, snapshot: dict) -> bool:
    inodes = {_inode(fd.get("target") or "") for fd in proc.get("fds") or []}
    inodes.discard("")
    for row in snapshot.get("sockets") or []:
        if row.get("inode") not in inodes:
            continue
        remote = row.get("remote_ip") or ""
        if row.get("state") == "ESTABLISHED" and remote and not is_loopback(remote) and not is_unspecified(remote):
            return True
    return False


def _unix_by_inode(snapshot: dict) -> dict[str, str]:
    return {row.get("inode"): row.get("path") or "" for row in snapshot.get("unix") or []}


def _approved(baseline: dict | None) -> dict[str, set[str]]:
    approved: dict[str, set[str]] = {}
    if not baseline:
        return approved
    paths = _unix_by_inode(baseline)
    for proc in baseline.get("processes") or []:
        if proc.get("tool"):
            continue
        for fd in proc.get("fds") or []:
            inode = _inode(fd.get("target") or "")
            path = paths.get(inode) or ""
            if not path:
                continue
            approved.setdefault(path, set()).add(proc.get("comm") or "")
    return approved


def inspect(baseline: dict | None, current: dict, json_enabled: bool) -> list[dict]:
    if not json_enabled:
        return []
    approved = _approved(baseline)
    paths = _unix_by_inode(current)
    alerts = []
    for proc in current.get("processes") or []:
        if proc.get("tool"):
            continue
        comm = proc.get("comm") or ""
        for fd in proc.get("fds") or []:
            inode = _inode(fd.get("target") or "")
            path = paths.get(inode) or ""
            if not path:
                continue
            allowed = approved.get(path) or set()
            if comm in allowed:
                continue
            mode = fd.get("mode") or "readwrite"
            kind = "unauthorized-writer" if mode in {"write", "readwrite"} else "unauthorized-reader"
            impact = "high" if kind == "unauthorized-writer" else "medium"
            alerts.append(alert(
                "ipc", kind, impact,
                f"{comm} pid={proc.get('pid')} {mode} on {path} outside the baseline set",
                {"pid": proc.get("pid"), "comm": comm, "path": path, "mode": mode,
                 "approved": sorted(allowed)},
                confidence=0.8,
            ))
        for head in proc.get("file_heads") or []:
            keys = set(head.get("json_keys") or [])
            if not keys & SIGNED_KEYS:
                continue
            if comm in {name for names in approved.values() for name in names}:
                continue
            alerts.append(alert(
                "ipc", "unapproved-signed-json", "high",
                f"signed-looking JSON from {comm} pid={proc.get('pid')} is outside the baseline writers",
                {"pid": proc.get("pid"), "comm": comm, "keys": sorted(keys), "path": head.get("path")},
                confidence=0.7,
            ))
    return alerts
