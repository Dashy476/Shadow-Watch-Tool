"""Access paths seen in memory, and the containment action that closed each one."""

from __future__ import annotations

from shadow.procparse import SHELLS, is_loopback, is_unspecified


def _key(kind: str, ident: str) -> str:
    return f"{kind}:{ident}"


def update_access_paths(paths: list[dict], snapshot: dict, baseline_peers: set[str], seen_at: str) -> list[dict]:
    current = {row["id"]: dict(row) for row in paths}
    for proc in snapshot.get("processes") or []:
        if proc.get("tool"):
            continue
        parent = proc.get("parent_comm") or ""
        remotes = _proc_remotes(proc, snapshot)
        if parent in SHELLS and remotes:
            ident = str(proc.get("pid"))
            _add(current, _key("shell-child", ident), seen_at, {
                "kind": "shell-child",
                "pid": proc.get("pid"),
                "remote_ip": remotes[0][0],
                "summary": (
                    f"pid {proc.get('pid')} comm={proc.get('comm')} parent={parent} "
                    f"connected to {remotes[0][0]}:{remotes[0][1]}"
                ),
            })
        for fd in proc.get("fds") or []:
            target = fd.get("target") or ""
            if "authorized_keys" in target or target.endswith("/id_rsa") or target.endswith("/id_ed25519"):
                _add(current, _key("cred-file", target), seen_at, {
                    "kind": "cred-file",
                    "pid": proc.get("pid"),
                    "path": target,
                    "summary": f"pid {proc.get('pid')} has {target} open",
                })
    for row in snapshot.get("sockets") or []:
        ip = row.get("remote_ip") or ""
        if not ip or is_loopback(ip) or is_unspecified(ip):
            continue
        if row.get("state") not in {"ESTABLISHED", "SYN_SENT", "CLOSE_WAIT"}:
            continue
        if baseline_peers and ip not in baseline_peers:
            _add(current, _key("new-peer", ip), seen_at, {
                "kind": "new-peer",
                "remote_ip": ip,
                "summary": f"outbound peer {ip} was not in the baseline",
            })
    return list(current.values())


def _add(current: dict, ident: str, seen_at: str, fields: dict) -> None:
    if ident in current:
        return
    row = {"id": ident, "found_ts": seen_at, "closed_ts": None, "closed_how": ""}
    row.update(fields)
    current[ident] = row


def _proc_remotes(proc: dict, snapshot: dict) -> list[tuple[str, int]]:
    inodes = set()
    for fd in proc.get("fds") or []:
        target = fd.get("target") or ""
        if target.startswith("socket:[") and target.endswith("]"):
            inodes.add(target[8:-1])
    found = []
    for row in snapshot.get("sockets") or []:
        if row.get("inode") not in inodes:
            continue
        ip = row.get("remote_ip") or ""
        if not ip or is_loopback(ip) or is_unspecified(ip):
            continue
        found.append((ip, int(row.get("remote_port") or 0)))
    return found


def close_paths(paths: list[dict], action: dict, seen_at: str) -> list[dict]:
    updated = []
    for row in paths:
        item = dict(row)
        if item.get("closed_ts"):
            updated.append(item)
            continue
        pid_match = action.get("pid") and item.get("pid") == action.get("pid")
        ip_match = action.get("remote_ip") and item.get("remote_ip") == action.get("remote_ip")
        if pid_match or ip_match:
            item["closed_ts"] = seen_at
            item["closed_how"] = action.get("summary") or action.get("action") or "containment"
        updated.append(item)
    return updated
