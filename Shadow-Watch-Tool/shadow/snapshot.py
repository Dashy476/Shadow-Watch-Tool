"""Diff two volatile snapshots. Alerts fire only on changes."""

from __future__ import annotations

from shadow.procparse import is_loopback, is_tool_cmdline, is_unspecified


def alert(source: str, kind: str, impact: str, summary: str,
          evidence: dict, confidence: float = 0.9) -> dict:
    return {
        "source": source,
        "kind": kind,
        "impact": impact,
        "confidence": confidence,
        "summary": summary,
        "evidence": evidence,
    }


def ancestry(processes: list[dict], pid: int, limit: int = 16) -> list[dict]:
    by_pid = {}
    for proc in processes:
        try:
            by_pid[int(proc["pid"])] = proc
        except (KeyError, TypeError, ValueError):
            continue
    chain = []
    seen = set()
    current = int(pid)
    while current and current not in seen and len(chain) < limit:
        seen.add(current)
        proc = by_pid.get(current)
        if proc is None:
            break
        chain.append(proc)
        try:
            current = int(proc.get("ppid") or 0)
        except (TypeError, ValueError):
            break
    return chain


def _tool(proc: dict) -> bool:
    return bool(proc.get("tool") or is_tool_cmdline(proc.get("cmdline") or ""))


def _socket_key(row: dict) -> tuple:
    return (row.get("proto"), row.get("local"), row.get("remote"))


def _socket_impact(row: dict) -> str:
    remote_ip = row.get("remote_ip") or ""
    state = row.get("state")
    if state == "LISTEN":
        return "medium"
    if remote_ip and not is_loopback(remote_ip) and not is_unspecified(remote_ip):
        return "high"
    return "low"


def diff_snapshots(previous: dict | None, current: dict, baseline: dict | None) -> list[dict]:
    """PID, socket, and map diffs are against the previous pass.

    Service new/missing/relocated is against the baseline, not the last pass.
    The first pass (previous is None) emits no change alerts.
    """
    if previous is None:
        return []
    found = []
    found.extend(_diff_pids(previous, current))
    found.extend(_diff_sockets(previous, current))
    found.extend(_diff_maps(previous, current))
    found.extend(_diff_services(baseline or previous, current))
    return found


def _diff_pids(previous: dict, current: dict) -> list[dict]:
    old = {int(proc["pid"]): proc for proc in previous.get("processes") or [] if not _tool(proc)}
    alerts = []
    for proc in current.get("processes") or []:
        if _tool(proc):
            continue
        pid = int(proc["pid"])
        if pid not in old:
            alerts.append(alert(
                "snapshot", "new-pid", "high" if _suspicious_proc(proc) else "medium",
                f"new pid {pid} comm={proc.get('comm')} parent={proc.get('parent_comm')}",
                {"pid": pid, "comm": proc.get("comm"), "ppid": proc.get("ppid"),
                 "cmdline": proc.get("cmdline"), "exe": proc.get("exe")},
            ))
            continue
        if (old[pid].get("cmdline") or "") != (proc.get("cmdline") or ""):
            alerts.append(alert(
                "snapshot", "process-replaced", "high",
                f"pid {pid} cmdline changed",
                {"pid": pid, "old": old[pid].get("cmdline"), "new": proc.get("cmdline")},
            ))
    return alerts


def _suspicious_proc(proc: dict) -> bool:
    from shadow.procparse import SHELLS
    if "(deleted)" in (proc.get("exe") or ""):
        return True
    if proc.get("comm") in SHELLS or proc.get("parent_comm") in SHELLS:
        return True
    return False


def _diff_sockets(previous: dict, current: dict) -> list[dict]:
    old = {_socket_key(row) for row in previous.get("sockets") or []}
    alerts = []
    for row in current.get("sockets") or []:
        key = _socket_key(row)
        if key in old:
            continue
        alerts.append(alert(
            "snapshot", "new-socket", _socket_impact(row),
            f"new {row.get('proto')} {row.get('local')} -> {row.get('remote')} {row.get('state')}",
            {"proto": row.get("proto"), "local": row.get("local"), "remote": row.get("remote"),
             "state": row.get("state"), "inode": row.get("inode")},
        ))
    return alerts


def _diff_maps(previous: dict, current: dict) -> list[dict]:
    old = {(row.get("pid"), row.get("path")) for row in previous.get("maps") or []}
    alerts = []
    for row in current.get("maps") or []:
        key = (row.get("pid"), row.get("path"))
        if key in old:
            continue
        path = row.get("path") or ""
        impact = "high" if ("/dev/shm" in path or "(deleted)" in path or "/." in path) else "medium"
        alerts.append(alert(
            "snapshot", "new-map", impact,
            f"new map pid={row.get('pid')} {path}",
            {"pid": row.get("pid"), "path": path, "perms": row.get("perms")},
        ))
    return alerts


def _service_index(snapshot: dict) -> dict[str, dict]:
    return {row["unit"]: row for row in snapshot.get("services") or [] if row.get("unit")}


def _diff_services(baseline: dict, current: dict) -> list[dict]:
    old = _service_index(baseline)
    new = _service_index(current)
    alerts = []
    for unit, row in sorted(new.items()):
        if unit not in old:
            alerts.append(alert(
                "snapshot", "service-new", "medium",
                f"new service {unit} exec={row.get('exec')}",
                {"unit": unit, "exec": row.get("exec"), "fragment": row.get("fragment")},
            ))
            continue
        old_exec = old[unit].get("exec") or ""
        new_exec = row.get("exec") or ""
        if old_exec != new_exec:
            alerts.append(alert(
                "snapshot", "service-relocated", "high",
                f"service {unit} binary moved {old_exec} -> {new_exec}",
                {"unit": unit, "old_exec": old_exec, "new_exec": new_exec},
            ))
    for unit, row in sorted(old.items()):
        if unit not in new:
            alerts.append(alert(
                "snapshot", "service-missing", "medium",
                f"service missing {unit} exec={row.get('exec')}",
                {"unit": unit, "exec": row.get("exec")},
            ))
    return alerts


def prioritize(alerts: list[dict]) -> list[dict]:
    rank = {"high": 0, "medium": 1, "low": 2}
    return sorted(alerts, key=lambda item: (rank.get(item.get("impact"), 9), -float(item.get("confidence") or 0)))
