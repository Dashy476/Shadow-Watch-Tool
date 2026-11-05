"""Score a host from process-tree, listen, track-path, and pipeline invariants.

Hostname is collected by the node and ignored here on purpose.
"""

from __future__ import annotations

from shadow.procparse import SHELLS, is_loopback, is_tool_cmdline, is_unspecified

DEFAULT_PROFILE = {
    "pipeline_substrings": ["track", "sensor", "sentinel", "cuas", "radar", "fusion", "plot"],
    "track_path_substrings": ["track", "cue", "sentinel", "cuas", "radar", "plot"],
    "accept_score": 0.70,
    "ambiguous_score": 0.40,
}

# Common ports that do not, by themselves, make a box a cUAS node.
QUIET_LISTEN = {22, 53, 68, 123}


_EXTRA_KEYS = (
    "look_for", "role", "host", "label", "benign_peers", "listen_ports",
    "parent_not_shell", "hostname_ignored",
)


def load_profile(data: dict | None) -> dict:
    profile = dict(DEFAULT_PROFILE)
    profile["benign_peers"] = {}
    profile["look_for"] = []
    profile["listen_ports"] = []
    profile["parent_not_shell"] = True
    if data:
        for key in DEFAULT_PROFILE:
            if key in data:
                profile[key] = data[key]
        for key in _EXTRA_KEYS:
            if key in data:
                profile[key] = data[key]
    return profile


def _text_hits(text: str, needles: list[str]) -> bool:
    lowered = (text or "").lower()
    return any(needle.lower() in lowered for needle in needles)


def _processes(snapshot: dict) -> list[dict]:
    return [proc for proc in snapshot.get("processes") or [] if not proc.get("tool") and not is_tool_cmdline(proc.get("cmdline") or "")]


def _pipeline_candidates(snapshot: dict, profile: dict) -> list[dict]:
    needles = profile["pipeline_substrings"]
    found = []
    for proc in _processes(snapshot):
        blob = " ".join([proc.get("comm") or "", proc.get("cmdline") or "", proc.get("exe") or ""])
        if _text_hits(blob, needles):
            found.append(proc)
    return found


def _proc_has_data_path(proc: dict, snapshot: dict) -> bool:
    inodes = set()
    for fd in proc.get("fds") or []:
        target = fd.get("target") or ""
        if target.startswith("socket:[") and target.endswith("]"):
            inodes.add(target[8:-1])
    for row in snapshot.get("sockets") or []:
        if row.get("inode") not in inodes:
            continue
        if row.get("state") == "LISTEN" and int(row.get("local_port") or 0) not in QUIET_LISTEN:
            return True
        remote = row.get("remote_ip") or ""
        if row.get("state") == "ESTABLISHED" and remote and not is_loopback(remote) and not is_unspecified(remote):
            return True
    return False


def _track_path_hit(snapshot: dict, profile: dict) -> str:
    needles = profile["track_path_substrings"]
    fields = []
    for proc in _processes(snapshot):
        fields.append(proc.get("cwd") or "")
        fields.append(proc.get("exe") or "")
        fields.extend(fd.get("target") or "" for fd in proc.get("fds") or [])
        fields.extend(proc.get("named_paths") or [])
    for row in snapshot.get("maps") or []:
        fields.append(row.get("path") or "")
    return _best_field(fields, needles)


def _best_field(fields: list[str], needles: list[str]) -> str:
    """Prefer the longest substring so a full track path wins over 'track'."""
    for needle in sorted((needles or []), key=len, reverse=True):
        lowered = needle.lower()
        if not lowered:
            continue
        for field in fields:
            if lowered in (field or "").lower():
                return field
    return ""


def score_host(snapshot: dict, profile: dict | None = None) -> dict:
    """Return score, label, reasons, and the pipeline process if one matched.

    label is accept, ambiguous, or wrong host.
    The ambiguous label is reported to the operator as "wrong host / ambiguous".
    """
    profile = load_profile(profile)
    reasons = []
    score = 0.0
    candidates = _pipeline_candidates(snapshot, profile)
    chosen = None
    for proc in candidates:
        if _proc_has_data_path(proc, snapshot):
            chosen = proc
            break
    if chosen is None and candidates:
        chosen = candidates[0]

    if chosen is not None:
        score += 0.40
        reasons.append(f"pipeline process comm={chosen.get('comm')} pid={chosen.get('pid')}")
        parent = chosen.get("parent_comm") or ""
        if parent not in SHELLS:
            score += 0.15
            reasons.append(f"pipeline parent {parent or 'unknown'} is not a shell")
        else:
            reasons.append(f"pipeline parent {parent} is a shell")
        if _proc_has_data_path(chosen, snapshot):
            score += 0.20
            reasons.append("pipeline process has a listen port or an established outbound socket")
        else:
            reasons.append("pipeline process has no external socket")
    else:
        reasons.append("no pipeline process matched the profile substrings")

    track = _track_path_hit(snapshot, profile)
    if track:
        score += 0.25
        reasons.append(f"track-output path present: {track}")
    else:
        reasons.append("no track-output path matched")

    score = round(min(score, 1.0), 2)
    if score >= float(profile["accept_score"]):
        label = "accept"
    elif score >= float(profile["ambiguous_score"]):
        label = "ambiguous"
    else:
        label = "wrong host"

    pipeline = None
    if chosen is not None:
        pipeline = {
            "pid": chosen.get("pid"),
            "comm": chosen.get("comm"),
            "exe": chosen.get("exe"),
            "cmdline": chosen.get("cmdline"),
            "parent_comm": chosen.get("parent_comm"),
        }
    return {
        "score": score,
        "label": label,
        "report": "wrong host / ambiguous" if label == "ambiguous" else label,
        "reasons": reasons,
        "pipeline": pipeline,
        "hostname_used": False,
    }
