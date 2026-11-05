"""Adjacency list from sockets, routes, and ARP. Dict-of-dicts, no networkx.

Edges keep the first-seen timestamp so a later pass can show lateral movement.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from shadow.procparse import is_loopback, is_unspecified


def empty_graph() -> dict:
    return {"edges": {}}


def _edge(graph: dict, src: str, dst: str) -> dict:
    src_row = graph["edges"].setdefault(src, {})
    return src_row.setdefault(dst, {"first_seen": "", "last_seen": "", "links": {}})


def update_graph(previous: dict | None, snapshot: dict, seen_at: str) -> dict:
    graph = {"edges": {}}
    if previous:
        # Copy so the caller's previous graph keeps its first-seen values.
        for src, dsts in previous.get("edges", {}).items():
            for dst, row in dsts.items():
                graph["edges"].setdefault(src, {})[dst] = {
                    "first_seen": row.get("first_seen") or seen_at,
                    "last_seen": row.get("last_seen") or seen_at,
                    "links": {key: dict(value) for key, value in (row.get("links") or {}).items()},
                }

    for row in snapshot.get("sockets") or []:
        remote = row.get("remote_ip") or ""
        local = row.get("local_ip") or ""
        if not remote or is_loopback(remote) or is_unspecified(remote):
            continue
        if not local or is_unspecified(local):
            local = _local_ip(snapshot) or local or "node"
        link = f"{row.get('remote_port')}/{row.get('proto')}"
        edge = _edge(graph, local, remote)
        if not edge["first_seen"]:
            edge["first_seen"] = seen_at
        edge["last_seen"] = seen_at
        item = edge["links"].setdefault(link, {"first_seen": seen_at, "state": row.get("state")})
        item["state"] = row.get("state")
        item["last_seen"] = seen_at

    local_ip = _local_ip(snapshot) or "node"
    for route in snapshot.get("routes") or []:
        gateway = route.get("gateway") or ""
        if not gateway or gateway == "0.0.0.0":
            continue
        edge = _edge(graph, local_ip, gateway)
        if not edge["first_seen"]:
            edge["first_seen"] = seen_at
        edge["last_seen"] = seen_at
        edge["links"].setdefault("route", {"first_seen": edge["first_seen"], "state": "gateway"})
        edge["links"]["route"]["last_seen"] = seen_at

    for neigh in snapshot.get("arp") or []:
        ip = neigh.get("ip") or ""
        if not ip or is_loopback(ip):
            continue
        edge = _edge(graph, local_ip, ip)
        if not edge["first_seen"]:
            edge["first_seen"] = seen_at
        edge["last_seen"] = seen_at
        edge["links"].setdefault("arp", {"first_seen": edge["first_seen"], "state": neigh.get("hw", "")})
        edge["links"]["arp"]["last_seen"] = seen_at
    return graph


def _local_ip(snapshot: dict) -> str:
    for row in snapshot.get("sockets") or []:
        ip = row.get("local_ip") or ""
        if ip and not is_loopback(ip) and not is_unspecified(ip):
            return ip
    return ""


def adjacency_list(graph: dict) -> str:
    lines = []
    edges = graph.get("edges") or {}
    for src in sorted(edges):
        for dst in sorted(edges[src]):
            row = edges[src][dst]
            links = row.get("links") or {}
            rendered = ",".join(
                f"{name}:{links[name].get('state')}" for name in sorted(links)
            )
            lines.append(
                f"{src} -> {dst}  links={rendered or '-'}  "
                f"first_seen={row.get('first_seen')}  last_seen={row.get('last_seen')}"
            )
    if not lines:
        return "(no edges)"
    return "\n".join(lines)


def to_dot(graph: dict) -> str:
    lines = ["digraph shadow {", "  rankdir=LR;"]
    edges = graph.get("edges") or {}
    for src in sorted(edges):
        for dst in sorted(edges[src]):
            row = edges[src][dst]
            label = ",".join(sorted((row.get("links") or {})))
            safe_src = src.replace('"', "")
            safe_dst = dst.replace('"', "")
            safe_label = label.replace('"', "")
            lines.append(f'  "{safe_src}" -> "{safe_dst}" [label="{safe_label}"];')
    lines.append("}")
    return "\n".join(lines)


def write_outputs(graph: dict, directory: Path) -> dict:
    """Always write the adjacency list. Write a .dot file only when `dot` exists."""
    directory.mkdir(parents=True, exist_ok=True)
    text = adjacency_list(graph)
    list_path = directory / "adjacency.txt"
    list_path.write_text(text + "\n", encoding="utf-8")
    dot_path = None
    if shutil.which("dot"):
        dot_path = directory / "topology.dot"
        dot_path.write_text(to_dot(graph) + "\n", encoding="utf-8")
    return {"adjacency": str(list_path), "dot": str(dot_path) if dot_path else None, "text": text}


def new_edge_lines(before: dict | None, after: dict) -> list[str]:
    old = set()
    if before:
        for src, dsts in before.get("edges", {}).items():
            for dst in dsts:
                old.add((src, dst))
    lines = []
    for src, dsts in after.get("edges", {}).items():
        for dst, row in dsts.items():
            if (src, dst) not in old:
                lines.append(f"new edge {src} -> {dst} first_seen={row.get('first_seen')}")
    return lines
