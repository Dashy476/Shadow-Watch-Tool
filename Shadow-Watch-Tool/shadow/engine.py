"""Pure reduction from snapshots to alerts, topology, flows, and suggestions."""

from __future__ import annotations

import json

import calendar
import time

from shadow.access import update_access_paths
from shadow.differentiator import classify
from shadow.fingerprint import score_host
from shadow.plugins import run_plugins
from shadow.plugins.ipc import inter_node_json
from shadow.snapshot import diff_snapshots, prioritize
from shadow.topology import empty_graph, new_edge_lines, update_graph


def alert_key(item: dict) -> str:
    evidence = item.get("evidence") or {}
    ident = {
        "source": item.get("source"),
        "kind": item.get("kind"),
        "pid": evidence.get("pid"),
        "remote": evidence.get("remote") or evidence.get("remote_ip"),
        "path": evidence.get("path"),
        "unit": evidence.get("unit"),
        "summary": item.get("summary"),
    }
    return json.dumps(ident, sort_keys=True, default=str)


def fresh_watch() -> dict:
    return {
        "baseline": None,
        "previous": None,
        "history": [],
        "graph": empty_graph(),
        "access_paths": [],
        "seen_alerts": [],
        "json_enabled": False,
        "peer_ips": [],
    }


def ingest(watch: dict, snapshot: dict, seen_at: str) -> dict:
    """Fold one snapshot into watch. Returns new alerts and new topology lines."""
    if not snapshot.get("taken_at"):
        snapshot["taken_at"] = seen_at
    if not snapshot.get("operator_unix"):
        snapshot["operator_unix"] = _unix_from_stamp(snapshot.get("taken_at") or seen_at)
    baseline = watch.get("baseline")
    previous = watch.get("previous")
    changes = diff_snapshots(previous, snapshot, baseline)
    if baseline is None:
        watch["baseline"] = snapshot
        watch["json_enabled"] = inter_node_json(snapshot)
        watch["peer_ips"] = sorted(_peers(snapshot))
        baseline = snapshot
    history = watch.setdefault("history", [])
    history.append(snapshot)
    plugin_alerts = run_plugins(baseline, history, bool(watch.get("json_enabled")))
    fresh = []
    seen = set(watch.get("seen_alerts") or [])
    for item in changes + plugin_alerts:
        key = alert_key(item)
        if key in seen:
            continue
        seen.add(key)
        item = dict(item)
        item["ts"] = seen_at
        fresh.append(item)
    watch["seen_alerts"] = list(seen)
    before = watch.get("graph")
    graph = update_graph(before, snapshot, seen_at)
    edge_lines = new_edge_lines(before, graph)
    watch["graph"] = graph
    peers = set(watch.get("peer_ips") or [])
    watch["access_paths"] = update_access_paths(watch.get("access_paths") or [], snapshot, peers, seen_at)
    watch["previous"] = snapshot
    return {"alerts": prioritize(fresh), "edges": edge_lines, "graph": graph}


def _unix_from_stamp(text: str) -> float:
    try:
        return float(calendar.timegm(time.strptime(text, "%Y-%m-%dT%H:%M:%SZ")))
    except (TypeError, ValueError):
        return time.time()


def _peers(snapshot: dict) -> set[str]:
    from shadow.procparse import is_loopback, is_unspecified
    found = set()
    for row in snapshot.get("sockets") or []:
        ip = row.get("remote_ip") or ""
        if ip and not is_loopback(ip) and not is_unspecified(ip):
            found.add(ip)
    return found


def run_classification(snapshots: list[dict], pipeline: dict | None, iocs: set[str], profile: dict | None) -> dict:
    substrings = list((profile or {}).get("pipeline_substrings") or [])
    benign = dict((profile or {}).get("benign_peers") or {})
    return classify(snapshots, pipeline, iocs, substrings, benign)


def fingerprint_snapshot(snapshot: dict, profile: dict | None) -> dict:
    return score_host(snapshot, profile)
