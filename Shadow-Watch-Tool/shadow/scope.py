"""SENTINEL-01 observations for the IOC sweep. Reads a snapshot. Opens nothing.

The diagnostics export is described from the listener, its clients, and paths
that mention it. Token material is reported by variable name only.
"""

from __future__ import annotations

from shadow.grid import CONSOLE_PORT, DETECTION_COMM, EDGE_IP, LOG_COMM, OPS_IP

TOKEN_NAMES = ("token", "session", "cookie", "authorization", "jwt", "password", "secret", "passwd")
EXPORT_WORDS = ("diagnostic", "export")


def sentinel_findings(snapshot: dict) -> dict:
    processes = snapshot.get("processes") or []
    sockets = snapshot.get("sockets") or []
    by_inode = _procs_by_inode(processes)
    console = _console(sockets, by_inode, processes)
    tokens = _tokens(processes)
    unexpected = _unexpected_peers(sockets, by_inode)
    return {"console": console, "tokens": tokens, "unexpected_peers": unexpected}


def _procs_by_inode(processes: list[dict]) -> dict[str, dict]:
    found = {}
    for proc in processes:
        if proc.get("tool"):
            continue
        for fd in proc.get("fds") or []:
            target = fd.get("target") or ""
            if target.startswith("socket:[") and target.endswith("]"):
                found[target[8:-1]] = proc
    return found


def _console(sockets: list[dict], by_inode: dict[str, dict], processes: list[dict]) -> list[str]:
    lines = []
    listeners = [
        row for row in sockets
        if row.get("state") == "LISTEN" and int(row.get("local_port") or 0) == CONSOLE_PORT
    ]
    if not listeners:
        lines.append(f"no listener on port {CONSOLE_PORT} (cUAS console / diagnostics export)")
    for row in listeners:
        proc = by_inode.get(str(row.get("inode")))
        owner = f"pid {proc.get('pid')} {proc.get('comm')}" if proc else "owner not in this snapshot"
        lines.append(f"listen {row.get('local')} — {owner}")
    clients = [
        row for row in sockets
        if row.get("state") == "ESTABLISHED" and int(row.get("local_port") or 0) == CONSOLE_PORT
    ]
    if listeners:
        lines.append(f"established clients on port {CONSOLE_PORT}: {len(clients)}")
    export_hits = []
    for proc in processes:
        if proc.get("tool"):
            continue
        blob = " ".join([
            proc.get("cmdline") or "",
            proc.get("exe") or "",
            " ".join(proc.get("named_paths") or []),
            " ".join((fd.get("target") or "") for fd in proc.get("fds") or []),
        ]).lower()
        if any(word in blob for word in EXPORT_WORDS):
            export_hits.append(f"pid {proc.get('pid')} {proc.get('comm')} references a diagnostics/export path")
    lines.extend(export_hits[:8])
    if listeners and not export_hits:
        lines.append("listener is up; no process path in this snapshot names diagnostics or export yet")
    return lines


def _tokens(processes: list[dict]) -> list[str]:
    lines = []
    for proc in processes:
        if proc.get("tool"):
            continue
        environ = proc.get("environ")
        if not isinstance(environ, dict):
            continue
        for key, value in environ.items():
            lowered = str(key).lower()
            if not any(name in lowered for name in TOKEN_NAMES):
                continue
            present = "set" if value else "empty"
            lines.append(
                f"pid {proc.get('pid')} {proc.get('comm')} environ {key} is {present} (value redacted)"
            )
    return lines


def _unexpected_peers(sockets: list[dict], by_inode: dict[str, dict]) -> list[str]:
    lines = []
    expected = {EDGE_IP: DETECTION_COMM, OPS_IP: LOG_COMM}
    reasons = {
        EDGE_IP: "detection flow with EDGE-02",
        OPS_IP: "log-forwarding flow to OPS-03",
    }
    for row in sockets:
        if row.get("state") != "ESTABLISHED":
            continue
        remote = row.get("remote_ip") or ""
        if remote not in expected:
            continue
        proc = by_inode.get(str(row.get("inode")))
        if proc is None:
            lines.append(f"established {remote}:{row.get('remote_port')} has no process in this snapshot")
            continue
        blob = " ".join([proc.get("comm") or "", proc.get("cmdline") or "", proc.get("exe") or ""]).lower()
        if any(name in blob for name in expected[remote]):
            continue
        lines.append(
            f"pid {proc.get('pid')} {proc.get('comm')} -> {remote}:{row.get('remote_port')} "
            f"is not the expected {reasons[remote]}"
        )
    return lines
