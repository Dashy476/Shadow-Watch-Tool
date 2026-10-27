"""Timeline, eight-gate status, availability, and the paste-ready writeup."""

from __future__ import annotations

from shadow.budget import WINDOW_S
from shadow.procparse import is_loopback, is_unspecified
from shadow.timeutil import stamp

GATES = (
    (1, "Fingerprint accepted without using hostname"),
    (2, "Volatile baseline captured before eradication"),
    (3, "Topology recorded"),
    (4, "Outbound flows classified"),
    (5, "Mission uplink and core tracker not targeted"),
    (6, "Evidence pulled back to the operator bunker"),
    (7, "Evidence collected inside the 45-minute window"),
    (8, "Writeup sections present"),
)


def availability(snapshots: list[dict], protected: dict | None) -> dict:
    if not snapshots or not protected:
        return {"number": None, "why": "Mission uplink is not identified, so availability is not scored."}
    proc_up = 0
    sock_up = 0
    for snap in snapshots:
        if _process_up(snap, protected):
            proc_up += 1
        if _socket_up(snap, protected):
            sock_up += 1
    total = len(snapshots)
    number = round(min(proc_up, sock_up) / total * 100, 1)
    why = (
        f"Core tracker {protected.get('comm')} was present in {proc_up} of {total} snapshots "
        f"and the mission uplink {protected.get('remote_ip')}:{protected.get('remote_port')} "
        f"was established in {sock_up} of {total}. Availability is the lower of those two rates."
    )
    return {"number": number, "why": why, "process_up": proc_up, "socket_up": sock_up, "total": total}


def _process_up(snap: dict, protected: dict) -> bool:
    exe = protected.get("exe") or ""
    comm = protected.get("comm") or ""
    for proc in snap.get("processes") or []:
        if proc.get("tool"):
            continue
        if exe and proc.get("exe") == exe and "(deleted)" not in (proc.get("exe") or ""):
            return True
        if not exe and comm and proc.get("comm") == comm:
            return True
    return False


def _socket_up(snap: dict, protected: dict) -> bool:
    want_ip = protected.get("remote_ip")
    want_port = int(protected.get("remote_port") or 0)
    for row in snap.get("sockets") or []:
        if row.get("state") != "ESTABLISHED":
            continue
        if row.get("remote_ip") == want_ip and int(row.get("remote_port") or 0) == want_port:
            return True
        if is_loopback(row.get("remote_ip") or "") or is_unspecified(row.get("remote_ip") or ""):
            continue
    return False


def evidence_relation(evidence_ts: str, eradication_ts: str | None) -> str:
    if not eradication_ts:
        return "before eradication (none recorded)"
    if evidence_ts <= eradication_ts:
        return f"at or before eradication ({eradication_ts})"
    return f"after eradication ({eradication_ts})"


def compute_gates(ctx: dict) -> list[dict]:
    fingerprint = ctx.get("fingerprint") or {}
    baseline_ts = ctx.get("baseline_ts") or ""
    eradication = ctx.get("eradication_ts") or ""
    rows = []

    label = fingerprint.get("label")
    if label == "accept" and fingerprint.get("hostname_used") is False:
        rows.append(_gate(1, "PASS", f"score {fingerprint.get('score')} label {label}"))
    elif label:
        rows.append(_gate(1, "FAIL", fingerprint.get("report") or label))
    else:
        rows.append(_gate(1, "OPEN", "fingerprint has not been scored"))

    if baseline_ts and (not eradication or baseline_ts <= eradication):
        rows.append(_gate(2, "PASS", f"baseline {baseline_ts}"))
    elif eradication and (not baseline_ts or baseline_ts > eradication):
        rows.append(_gate(2, "FAIL", "eradication has a timestamp and the baseline does not precede it"))
    else:
        rows.append(_gate(2, "OPEN", "no baseline snapshot yet"))

    if ctx.get("topology_written"):
        rows.append(_gate(3, "PASS", "adjacency list written on the operator"))
    else:
        rows.append(_gate(3, "OPEN", "topology has not been written"))

    if ctx.get("mission_unclear"):
        rows.append(_gate(4, "PARTIAL", ctx.get("classify_note") or "flows scored, mission not separated"))
    elif ctx.get("flows_ran"):
        rows.append(_gate(4, "PASS", ctx.get("classify_note") or "flows classified"))
    else:
        rows.append(_gate(4, "OPEN", "differentiator has not been run"))

    if ctx.get("protected_touched"):
        rows.append(_gate(5, "FAIL", "an executed action targeted the mission uplink or core tracker"))
    else:
        rows.append(_gate(5, "PASS", "no executed action targeted the protected uplink or tracker"))

    if ctx.get("operator_snapshots", 0) > 0:
        rows.append(_gate(6, "PASS", f"{ctx.get('operator_snapshots')} snapshot files on the operator"))
    else:
        rows.append(_gate(6, "FAIL", "no snapshot file in the operator bunker"))

    if _window_ok(ctx):
        rows.append(_gate(7, "PASS", "evidence used here was collected inside 45 minutes of the baseline"))
    elif not baseline_ts:
        rows.append(_gate(7, "OPEN", "timer has not started"))
    else:
        rows.append(_gate(7, "FAIL", "evidence is outside the 45-minute window"))

    rows.append(_gate(8, "PASS", "this writeup includes the required sections"))
    return rows


def _window_ok(ctx: dict) -> bool:
    baseline_unix = ctx.get("baseline_unix")
    if not baseline_unix:
        return False
    latest = ctx.get("evidence_unix") or baseline_unix
    eradication_unix = ctx.get("eradication_unix")
    if eradication_unix:
        latest = min(latest, eradication_unix)
    return (latest - baseline_unix) <= WINDOW_S


def _gate(number: int, status: str, detail: str) -> dict:
    title = dict(GATES)[number]
    return {"number": number, "gate": title, "status": status, "detail": detail}


def render_writeup(ctx: dict) -> str:
    gates = compute_gates(ctx)
    avail = ctx.get("availability") or {"number": None, "why": ""}
    lines = ["# Shadow Watch writeup", ""]
    lines.append("## Gate status")
    lines.append("")
    lines.append("| # | Gate | Status | Detail |")
    lines.append("| --- | --- | --- | --- |")
    for row in gates:
        lines.append(f"| {row['number']} | {row['gate']} | {row['status']} | {row['detail']} |")
    lines.append("")
    lines.append("## Timeline")
    lines.append("")
    lines.extend(_timeline_lines(ctx.get("timeline") or []))
    lines.append("")
    lines.append("## Access paths")
    lines.append("")
    paths = ctx.get("access_paths") or []
    if not paths:
        lines.append("No access path was recorded.")
    for row in paths:
        if row.get("closed_ts"):
            lines.append(
                f"- {row.get('found_ts')} found: {row.get('summary')}. "
                f"Closed {row.get('closed_ts')}: {row.get('closed_how')}."
            )
        else:
            lines.append(f"- {row.get('found_ts')} found: {row.get('summary')}. Still open.")
    lines.append("")
    lines.append("## Evidence log")
    lines.append("")
    eradication = ctx.get("eradication_ts") or ""
    evidence = ctx.get("evidence") or []
    if not evidence:
        lines.append("No evidence files recorded.")
    for row in evidence:
        relation = evidence_relation(row.get("ts") or "", eradication or None)
        lines.append(f"- {row.get('ts')} {row.get('kind')} {row.get('ref')} — {relation}. {row.get('note') or ''}")
    lines.append("")
    lines.append("## Availability")
    lines.append("")
    if avail.get("number") is None:
        lines.append(f"Availability: n/a. {avail.get('why')}")
    else:
        lines.append(f"Availability: {avail['number']}. {avail.get('why')}")
    lines.append("")
    lines.append("## What you'd do differently")
    lines.append("")
    lines.append("")
    return "\n".join(lines)


def _timeline_lines(events: list[dict]) -> list[str]:
    if not events:
        return ["No timeline events recorded."]
    lines = []
    current = None
    for event in events:
        phase = event.get("comp_phase") or "initial"
        if phase != current:
            if current is not None:
                lines.append("")
                lines.append("---")
                lines.append("")
            lines.append(f"### {phase}")
            lines.append("")
            if event.get("phase_started"):
                lines.append(f"started {event.get('ts')}")
                lines.append("")
            current = phase
        lines.append(f"- {event.get('ts')} — {event.get('text')}")
    return lines


def phase_event(name: str, when: str | None = None) -> dict:
    return {
        "ts": when or stamp(),
        "comp_phase": name,
        "text": f"competition phase {name} started",
        "phase_started": True,
        "kind": "phase",
    }
