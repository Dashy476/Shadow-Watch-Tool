"""Score lookalike outbound flows. Pure math. Never opens a socket.

Weights are constants so the team can retune them during the window.
The JSON axis is dropped, and the others renormalized, when the baseline
has no inter-node JSON.
"""

from __future__ import annotations

import math
import statistics
from collections import Counter
from itertools import pairwise

from shadow.plugins.beacon import intervals, is_periodic
from shadow.plugins.ipc import inter_node_json
from shadow.procparse import SHELLS, is_loopback, is_unspecified
from shadow.snapshot import ancestry

WEIGHTS = {
    "payload": 0.30,
    "ancestry": 0.30,
    "destination": 0.25,
    "json": 0.15,
}

BLOCK_SCORE = 0.72
BLOCK_CONFIDENCE = 0.60
LEAVE_SCORE = 0.35
LEAVE_CONFIDENCE = 0.50
PIPELINE_LEAVE_MAX = 0.55

MISSION_KEYS = {"track", "track_id", "lat", "lon", "alt", "ts", "timestamp", "id", "plot", "range", "azimuth", "cue"}
SUSPICIOUS_KEYS = {"pass", "password", "secret", "token", "dump", "exfil", "cred", "credential", "shadow"}


def classify(snapshots: list[dict], pipeline: dict | None, iocs: set[str],
             substrings: list[str] | None = None) -> dict:
    if not snapshots:
        return {"flows": [], "protected": None, "json_enabled": False, "mission_unclear": True,
                "note": "no snapshots"}
    baseline = snapshots[0]
    json_enabled = inter_node_json(baseline)
    baseline_peers = _peer_ips(baseline)
    baseline_comms = {proc.get("comm") or "" for proc in baseline.get("processes") or []}
    flows = _extract(snapshots)
    period = _pipeline_period(flows, pipeline)
    scored = []
    for flow in flows:
        scored.append(_score_flow(flow, baseline_comms, baseline_peers, iocs, json_enabled, pipeline, period, substrings or []))
    _separate(scored)
    protected, unclear, note = _protect(scored, pipeline, snapshots[-1])
    return {
        "flows": scored,
        "protected": protected,
        "json_enabled": json_enabled,
        "mission_unclear": unclear,
        "note": note,
    }


def _extract(snapshots: list[dict]) -> list[dict]:
    grouped: dict[tuple, dict] = {}
    for snap in snapshots:
        when = _when(snap)
        for row in snap.get("sockets") or []:
            remote = row.get("remote_ip") or ""
            if row.get("state") not in {"ESTABLISHED", "SYN_SENT", "CLOSE_WAIT"}:
                continue
            if not remote or is_loopback(remote) or is_unspecified(remote):
                continue
            proc = _proc_for_inode(snap, str(row.get("inode")))
            if proc is None or proc.get("tool"):
                continue
            pid = int(proc.get("pid") or 0)
            key = (row.get("proto"), remote, int(row.get("remote_port") or 0), pid)
            flow = grouped.setdefault(key, {
                "proto": row.get("proto"),
                "remote_ip": remote,
                "remote_port": int(row.get("remote_port") or 0),
                "pid": pid,
                "comm": proc.get("comm"),
                "exe": proc.get("exe"),
                "cmdline": proc.get("cmdline"),
                "local": row.get("local"),
                "states": [],
                "times": [],
                "writes": [],
                "json_keys": [],
                "entropy": None,
                "json_sample": False,
            })
            flow["states"].append(row.get("state"))
            flow["local"] = row.get("local")
            flow["times"].append(when)
            flow["writes"].append(int(proc.get("write_bytes") or 0))
            flow["chain_source"] = snap
            for head in proc.get("file_heads") or []:
                keys = head.get("json_keys") or []
                if keys:
                    flow["json_keys"].extend(keys)
                    flow["json_sample"] = True
                if head.get("entropy") is not None:
                    flow["entropy"] = head.get("entropy")
    out = []
    for flow in grouped.values():
        flow["json_keys"] = sorted(set(flow["json_keys"]))
        flow["deltas"] = _deltas(flow["writes"])
        out.append(flow)
    return out


def _when(snap: dict) -> float:
    try:
        return float(snap.get("operator_unix") or 0)
    except (TypeError, ValueError):
        return 0.0


def _proc_for_inode(snap: dict, inode: str) -> dict | None:
    marker = f"socket:[{inode}]"
    for proc in snap.get("processes") or []:
        for fd in proc.get("fds") or []:
            if fd.get("target") == marker:
                return proc
    return None


def _deltas(values: list[int]) -> list[int]:
    found = []
    for prev, cur in pairwise(values):
        if cur >= prev:
            found.append(cur - prev)
    return found


def _peer_ips(snap: dict) -> set[str]:
    found = set()
    for row in snap.get("sockets") or []:
        ip = row.get("remote_ip") or ""
        if ip and not is_loopback(ip) and not is_unspecified(ip):
            found.add(ip)
    for row in snap.get("arp") or []:
        ip = row.get("ip") or ""
        if ip and not is_loopback(ip):
            found.add(ip)
    return found


def _pipeline_period(flows: list[dict], pipeline: dict | None) -> float | None:
    if not pipeline:
        return None
    for flow in flows:
        if _is_pipeline(flow, pipeline, []):
            ivs = intervals([item for item in flow["times"] if item])
            if len(ivs) >= 3:
                return float(statistics.median(ivs))
    return None


def _is_pipeline(flow: dict, pipeline: dict | None, substrings: list[str]) -> bool:
    if pipeline:
        if flow.get("pid") == pipeline.get("pid"):
            return True
        if pipeline.get("exe") and flow.get("exe") == pipeline.get("exe"):
            return True
        if pipeline.get("comm") and flow.get("comm") == pipeline.get("comm") and not pipeline.get("exe"):
            return True
    blob = " ".join([flow.get("comm") or "", flow.get("cmdline") or "", flow.get("exe") or ""]).lower()
    return any(item.lower() in blob for item in substrings)


def _score_flow(flow, baseline_comms, baseline_peers, iocs, json_enabled, pipeline, period, substrings) -> dict:
    pipeline_hit = _is_pipeline(flow, pipeline, substrings)
    parts = {
        "payload": _payload(flow, pipeline_hit, period),
        "ancestry": _ancestry(flow, baseline_comms),
        "destination": _destination(flow, baseline_peers, iocs),
        "json": _json_axis(flow) if json_enabled else None,
    }
    reasons = {name: item[1] for name, item in parts.items() if item is not None}
    values = {name: item[0] for name, item in parts.items() if item is not None}
    score, confidence, used = _combine(values, json_enabled)
    return {
        "proto": flow["proto"],
        "remote_ip": flow["remote_ip"],
        "remote_port": flow["remote_port"],
        "local": flow.get("local"),
        "pid": flow["pid"],
        "comm": flow.get("comm"),
        "exe": flow.get("exe"),
        "cmdline": flow.get("cmdline"),
        "pipeline": pipeline_hit,
        "theft_score": round(score, 3),
        "confidence": round(confidence, 3),
        "weights": used,
        "reasons": reasons,
        "action": "watch",
        "chain": [proc.get("comm") for proc in ancestry(flow["chain_source"].get("processes") or [], flow["pid"])],
    }


def _combine(values: dict[str, float], json_enabled: bool) -> tuple[float, float, dict]:
    active = {}
    for name, weight in WEIGHTS.items():
        if name == "json" and not json_enabled:
            continue
        if name not in values:
            continue
        active[name] = weight
    possible = 4 if json_enabled else 3
    if not active:
        return 0.5, 0.0, {}
    total = sum(active.values())
    score = sum(values[name] * (active[name] / total) for name in active)
    confidence = len(active) / possible
    used = {name: round(active[name] / total, 3) for name in active}
    return score, confidence, used


def _payload(flow: dict, pipeline_hit: bool, period: float | None) -> tuple[float, str] | None:
    deltas = flow.get("deltas") or []
    if len(deltas) < 3:
        return None
    mean = statistics.fmean(deltas)
    ivs = intervals([item for item in flow.get("times") or [] if item])
    periodic = False
    if len(ivs) >= 3:
        expected = period if (pipeline_hit and period) else statistics.median(ivs)
        periodic, _stats = is_periodic(ivs, expected, max(0.5, expected * 0.25))
    median = statistics.median(deltas) if deltas else 0
    bulk = max(deltas) > 8 * max(median, 1)
    if pipeline_hit and periodic and not bulk:
        score, reason = 0.15, "regular payload on the pipeline process"
    elif bulk:
        score, reason = 0.85, "size burst compared with the median write"
    elif periodic and mean < 512 and not pipeline_hit:
        score, reason = 0.80, "small periodic writes off the pipeline"
    elif periodic:
        score, reason = 0.20, "regular payload size"
    else:
        score, reason = 0.50, "irregular payload size"
    entropy = flow.get("entropy")
    if entropy is not None and entropy > 4.2 and not flow.get("json_sample"):
        score = min(1.0, score + 0.10)
        reason += "; high-entropy bytes"
    return score, reason


def _ancestry(flow: dict, baseline_comms: set[str]) -> tuple[float, str]:
    chain = ancestry(flow["chain_source"].get("processes") or [], flow["pid"])
    comms = [proc.get("comm") or "" for proc in chain]
    exe = flow.get("exe") or ""
    if any(comm in SHELLS for comm in comms[1:]):
        return 0.90, "a parent is a shell or transfer tool"
    if "(deleted)" in exe:
        return 0.85, "executable path is deleted"
    if comms and comms[0] not in baseline_comms:
        return 0.70, "command name was not in the baseline"
    if any(comm in {"systemd", "init", "s6-supervise"} for comm in comms[1:3]):
        return 0.10, "parent is a service supervisor"
    return 0.40, "ancestry is unremarkable"


def _destination(flow: dict, baseline_peers: set[str], iocs: set[str]) -> tuple[float, str]:
    ip = flow["remote_ip"]
    port = flow["remote_port"]
    if ip in iocs or f"{ip}:{port}" in iocs:
        return 1.0, "destination matches a local IOC"
    if ip in baseline_peers:
        return 0.10, "destination was present at baseline"
    return 0.75, "destination was not in the baseline"


def _json_axis(flow: dict) -> tuple[float, str] | None:
    keys = set(flow.get("json_keys") or [])
    if not keys:
        return None
    if keys & SUSPICIOUS_KEYS:
        return 0.85, "JSON keys look like credential or dump fields"
    if keys & MISSION_KEYS:
        return 0.20, "JSON keys look like track output"
    return 0.55, "JSON keys do not match the track shape"


def _separate(scored: list[dict]) -> None:
    if len(scored) >= 2:
        ordered = sorted(item["theft_score"] for item in scored)
        close = (ordered[-1] - ordered[0]) < 0.15
    else:
        close = False
    for flow in scored:
        confidence = flow["confidence"]
        if close:
            confidence = min(confidence, 0.45)
            flow["reasons"]["separation"] = "flow scores are close; separation is weak"
        flow["confidence"] = round(confidence, 3)
        flow["confidence_pct"] = int(round(flow["confidence"] * 100))
        flow["action"] = _action(flow)


def _action(flow: dict) -> str:
    score = flow["theft_score"]
    confidence = flow["confidence"]
    if flow.get("pipeline") and score <= PIPELINE_LEAVE_MAX and confidence >= 0.50:
        return "leave alone"
    if score <= LEAVE_SCORE and confidence >= LEAVE_CONFIDENCE:
        return "leave alone"
    if score >= BLOCK_SCORE and confidence >= BLOCK_CONFIDENCE and not flow.get("pipeline"):
        return "block"
    return "watch"


def _protect(scored: list[dict], pipeline: dict | None, last_snapshot: dict) -> tuple[dict | None, bool, str]:
    pipeline_flows = [flow for flow in scored if flow.get("pipeline")]
    if not pipeline_flows:
        for flow in scored:
            if flow["action"] == "block":
                flow["action"] = "watch"
                flow["reasons"]["guard"] = "no pipeline flow to protect, so block was downgraded to watch"
        return None, True, "mission uplink not separated; no block and no kill"
    best = min(pipeline_flows, key=lambda flow: flow["theft_score"])
    if best["theft_score"] > PIPELINE_LEAVE_MAX:
        for flow in scored:
            if flow["action"] == "block":
                flow["action"] = "watch"
                flow["reasons"]["guard"] = "pipeline flow itself looks hostile; block downgraded to watch"
        return None, True, "pipeline flow is not a clean mission uplink; containment stays closed"
    best["action"] = "leave alone"
    chain = ancestry(last_snapshot.get("processes") or [], int(best["pid"]))
    protected = {
        "pid": best["pid"],
        "comm": best.get("comm"),
        "exe": best.get("exe"),
        "cmdline": best.get("cmdline"),
        "remote_ip": best["remote_ip"],
        "remote_port": best["remote_port"],
        "local": best.get("local"),
        "ancestor_pids": [int(proc["pid"]) for proc in chain[1:]],
        "unit": "",
        "unclear": False,
    }
    note = (
        f"mission uplink is pid {best['pid']} {best.get('comm')} -> "
        f"{best['remote_ip']}:{best['remote_port']}"
    )
    return protected, False, note


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())
