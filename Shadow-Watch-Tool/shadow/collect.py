"""Read-only /proc collector. Runs on the node. Stdlib only.

Order: sockets, then processes (parent chain, fds), then interesting maps,
then environ for standout processes.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

from shadow.procparse import (
    SHELLS,
    fd_mode,
    interesting_path,
    is_tool_cmdline,
    parse_arp,
    parse_environ,
    parse_io,
    parse_map_line,
    parse_proc_net,
    parse_route,
    parse_ss,
    parse_stat,
    parse_systemctl_list,
    parse_systemctl_show,
    parse_unix,
)

_QUOTED_PATH = re.compile(r"""["'](/[^"'\\\s]{1,240})["']""")
_PRIV_SCRIPT = r"""
import json, os, sys
out = {}
for pid in sys.argv[1:]:
    base = "/proc/" + pid
    if not os.path.isdir(base):
        continue
    def link(name, root=base):
        try:
            return os.readlink(os.path.join(root, name))
        except OSError:
            return ""
    fds = []
    fd_dir = os.path.join(base, "fd")
    try:
        names = os.listdir(fd_dir)
    except OSError:
        names = []
    for name in names:
        try:
            target = os.readlink(os.path.join(fd_dir, name))
        except OSError:
            continue
        flags = ""
        if target.startswith("socket:"):
            try:
                text = open(os.path.join(base, "fdinfo", name), encoding="utf-8", errors="replace").read()
            except OSError:
                text = ""
            for line in text.splitlines():
                if line.startswith("flags:"):
                    flags = line.split(":", 1)[1].strip()
                    break
        fds.append({"fd": name, "target": target, "flags": flags})
    try:
        maps = open(os.path.join(base, "maps"), encoding="utf-8", errors="replace").read()
    except OSError:
        maps = ""
    out[pid] = {"exe": link("exe"), "cwd": link("cwd"), "fds": fds, "maps": maps}
json.dump(out, sys.stdout)
"""

KEY_NAME_HINTS = ("key.pem", "private.pem", "id_rsa", "id_ed25519", "id_ecdsa")
FIXED_TRUST_PATHS = (
    "/etc/ssh/ssh_host_rsa_key",
    "/etc/ssh/ssh_host_ecdsa_key",
    "/etc/ssh/ssh_host_ed25519_key",
    "/root/.ssh/authorized_keys",
    "/root/.ssh/id_rsa",
    "/root/.ssh/id_ed25519",
)


def hash_files(paths: list[str]) -> dict:
    found = {}
    for raw in paths:
        path = Path(raw)
        if not path.is_file():
            found[raw] = ""
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        found[raw] = digest
    return {"ok": True, "hashes": found}


def disk_free(path: str) -> dict:
    candidate = Path(path)
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    usage = shutil.disk_usage(str(candidate))
    return {"ok": True, "path": str(candidate), "free": usage.free, "total": usage.total}


def build_snapshot(operator_unix: float = 0.0) -> dict:
    errors = []
    started = _now()
    sockets = _read_sockets(errors)
    unix_rows = _read_text("/proc/net/unix", parse_unix, errors)
    routes = _read_text("/proc/net/route", parse_route, errors)
    arp_rows = _read_text("/proc/net/arp", parse_arp, errors)
    processes, maps = _read_processes(sockets, errors)
    services = _read_services(processes, errors)
    timers = _read_timers(errors)  # <-- NEW: Capture systemd timers
    perms = _read_perms(processes, errors)
    configs = _read_configs(processes, errors)
    skew = None
    if operator_unix:
        skew = round(started - float(operator_unix), 3)
    return {
        "ok": True,
        "taken_at_node": started,
        "operator_unix": float(operator_unix or 0),
        "clock_skew_s": skew,
        "hostname_ignored": _hostname(),
        "sockets": sockets,
        "unix": unix_rows,
        "routes": routes,
        "arp": arp_rows,
        "processes": processes,
        "maps": maps,
        "services": services,
        "timers": timers,  # <-- NEW: Expose to the JSON snapshot
        "perm_records": perms,
        "configs": configs,
        "errors": errors[:20],
    }


def _now() -> float:
    import time
    return time.time()


def _hostname() -> str:
    try:
        return Path("/proc/sys/kernel/hostname").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _read_text(path: str, parser, errors: list) -> list:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        errors.append(f"{path}: {exc.__class__.__name__}")
        return []
    return parser(text)


def _read_sockets(errors: list) -> list[dict]:
    rows = []
    rows.extend(_read_text("/proc/net/tcp", lambda text: parse_proc_net(text, "tcp", False), errors))
    rows.extend(_read_text("/proc/net/tcp6", lambda text: parse_proc_net(text, "tcp6", True), errors))
    rows.extend(_read_text("/proc/net/udp", lambda text: parse_proc_net(text, "udp", False), errors))
    rows.extend(_read_text("/proc/net/udp6", lambda text: parse_proc_net(text, "udp6", True), errors))
    seen = {(row.get("proto"), row.get("local"), row.get("remote")) for row in rows}
    extra = []
    if shutil.which("ss"):
        extra = _read_ss(errors)
    elif shutil.which("netstat"):
        errors.append("ss missing; netstat present but /proc sockets were used")
    for row in extra:
        key = (row.get("proto"), row.get("local"), row.get("remote"))
        if key not in seen:
            rows.append(row)
            seen.add(key)
    return rows


def _read_ss(errors: list) -> list[dict]:
    """Supplement /proc. Failures are recorded and ignored. No packet is sent."""
    try:
        completed = subprocess.run(
            ["ss", "-H", "-tanu"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        errors.append(f"ss: {exc.__class__.__name__}")
        return []
    if completed.returncode != 0:
        return []
    return parse_ss(completed.stdout or "")


def _read_processes(sockets: list[dict], errors: list) -> tuple[list[dict], list[dict]]:
    proc_root = Path("/proc")
    basics = []
    if not proc_root.is_dir():
        errors.append("/proc is not a directory")
        return [], []
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        parsed = _one_process(entry, errors)
        if parsed is not None:
            basics.append(parsed)
    by_pid = {row["pid"]: row for row in basics}
    for row in basics:
        parent = by_pid.get(row["ppid"])
        row["parent_comm"] = parent.get("comm") if parent else ""
    denied = []
    staged: dict[int, tuple[list[dict], list[dict]]] = {}
    for row in basics:
        if row["tool"]:
            continue
        fds, fd_denied = _read_fds(row["pid"])
        proc_maps, map_denied = _read_maps(row["pid"])
        staged[row["pid"]] = (fds, proc_maps)
        if fd_denied or map_denied:
            denied.append(row["pid"])
    views = _privileged_views(denied, errors) if denied else {}
    maps = []
    for row in basics:
        if row["tool"]:
            row["fds"] = []
            row["file_heads"] = []
            row["environ"] = None
            continue
        fds, proc_maps = staged[row["pid"]]
        view = views.get(row["pid"])
        if view:
            if view.get("exe"):
                row["exe"] = view["exe"]
            if view.get("cwd"):
                row["cwd"] = view["cwd"]
            fds = view.get("fds") or fds
            proc_maps = view.get("maps") or proc_maps
        elif row["pid"] in denied:
            errors.append(f"/proc/{row['pid']}/fd: PermissionError")
        row["fds"] = fds
        for item in proc_maps:
            item["pid"] = row["pid"]
            maps.append(item)
        if _standout(row, fds, proc_maps):
            row["environ"] = _read_environ(row["pid"], errors)
            row["standout"] = True
        else:
            row["environ"] = None
            row["standout"] = False
        if row["standout"] or _has_external_fd(fds, sockets):
            row["file_heads"] = _file_heads(fds, errors)
        else:
            row["file_heads"] = []
    return basics, maps


def _one_process(entry: Path, errors: list) -> dict | None:
    pid = int(entry.name)
    try:
        stat_text = (entry / "stat").read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        errors.append(f"/proc/{pid}/stat: {exc.__class__.__name__}")
        return None
    parsed = parse_stat(stat_text)
    if parsed is None:
        return None
    pid, comm, ppid = parsed
    cmdline = _cmdline(entry / "cmdline")
    exe = _readlink(entry / "exe")
    cwd = _readlink(entry / "cwd")
    io = {}
    try:
        io = parse_io((entry / "io").read_text(encoding="utf-8", errors="replace"))
    except OSError:
        pass
    return {
        "pid": pid,
        "ppid": ppid,
        "comm": comm,
        "cmdline": cmdline,
        "exe": exe,
        "cwd": cwd,
        "write_bytes": int(io.get("write_bytes") or 0),
        "read_bytes": int(io.get("read_bytes") or 0),
        "tool": is_tool_cmdline(cmdline),
        "parent_comm": "",
        "named_paths": _named_paths(cmdline),
    }


def _cmdline(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError:
        return ""
    parts = [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part]
    return " ".join(parts)


def _readlink(path: Path) -> str:
    try:
        return os.readlink(path)
    except OSError:
        return ""


def _read_fds(pid: int) -> tuple[list[dict], bool]:
    fd_dir = Path(f"/proc/{pid}/fd")
    found = []
    try:
        names = list(fd_dir.iterdir())
    except PermissionError:
        return [], True
    except OSError:
        return [], False
    for fd in names:
        try:
            target = os.readlink(fd)
        except OSError:
            continue
        mode = ""
        if target.startswith("socket:"):
            mode = _fdinfo_mode(pid, fd.name)
        found.append({"fd": fd.name, "target": target, "mode": mode})
    return found, False


def _fdinfo_mode(pid: int, fd_name: str) -> str:
    path = Path(f"/proc/{pid}/fdinfo/{fd_name}")
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    for line in text.splitlines():
        if line.startswith("flags:"):
            return fd_mode(line.split(":", 1)[1].strip())
    return ""


def _read_maps(pid: int) -> tuple[list[dict], bool]:
    path = Path(f"/proc/{pid}/maps")
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        return [], True
    except OSError:
        return [], False
    return _interesting_maps(text), False


def _interesting_maps(text: str) -> list[dict]:
    found = []
    for line in text.splitlines():
        parsed = parse_map_line(line)
        if parsed and interesting_path(parsed["path"]):
            found.append(parsed)
    return found


def _privileged_views(pids: list[int], errors: list) -> dict[int, dict]:
    """Re-read /proc with sudo -n when the SSH user gets PermissionError.

    trackd runs as root. Without this, its uplink socket is invisible and the
    fingerprint cannot reach the accept threshold.
    """
    if not pids or shutil.which("sudo") is None:
        return {}
    try:
        completed = subprocess.run(
            ["sudo", "-n", sys.executable, "-c", _PRIV_SCRIPT, *[str(pid) for pid in pids]],
            capture_output=True, text=True, timeout=8, check=False,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        errors.append(f"sudo /proc: {exc.__class__.__name__}")
        return {}
    if completed.returncode != 0 or not (completed.stdout or "").strip():
        return {}
    try:
        raw = json.loads(completed.stdout)
    except json.JSONDecodeError:
        errors.append("sudo /proc: bad json")
        return {}
    views = {}
    for key, item in raw.items():
        try:
            pid = int(key)
        except (TypeError, ValueError):
            continue
        fds = []
        for fd in item.get("fds") or []:
            target = fd.get("target") or ""
            mode = fd_mode(fd.get("flags") or "") if target.startswith("socket:") else ""
            fds.append({"fd": str(fd.get("fd") or ""), "target": target, "mode": mode})
        views[pid] = {
            "exe": item.get("exe") or "",
            "cwd": item.get("cwd") or "",
            "fds": fds,
            "maps": _interesting_maps(item.get("maps") or ""),
        }
    return views


def _named_paths(cmdline: str) -> list[str]:
    """Absolute paths named by a readable program file on the command line.

    trackd opens /var/log/sentinel/tracks.log only for each write, so the path
    is not an fd at snapshot time. The script itself names that file.
    """
    found = []
    seen = set()
    for token in (cmdline or "").split():
        if not token.startswith("/") or os.path.basename(token).startswith("python"):
            continue
        if not os.path.isfile(token):
            continue
        try:
            if os.path.getsize(token) > 262144:
                continue
            text = Path(token).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in _QUOTED_PATH.finditer(text):
            path = match.group(1)
            if path in seen or not os.path.isfile(path):
                continue
            seen.add(path)
            found.append(path)
            if len(found) >= 20:
                return found
    return found


def _standout(proc: dict, fds: list[dict], maps: list[dict]) -> bool:
    if proc.get("tool"):
        return False
    if "(deleted)" in (proc.get("exe") or ""):
        return True
    if proc.get("parent_comm") in SHELLS or proc.get("comm") in SHELLS:
        return True
    if any(interesting_path(item.get("path") or "") for item in maps):
        return True
    return any(interesting_path(fd.get("target") or "") for fd in fds)


def _has_external_fd(fds: list[dict], sockets: list[dict]) -> bool:
    inodes = set()
    for fd in fds:
        target = fd.get("target") or ""
        if target.startswith("socket:[") and target.endswith("]"):
            inodes.add(target[8:-1])
    for row in sockets:
        if row.get("inode") in inodes and row.get("state") in {"ESTABLISHED", "SYN_SENT", "LISTEN"}:
            return True
    return False


def _file_heads(fds: list[dict], errors: list) -> list[dict]:
    ranked = []
    for fd in fds:
        target = fd.get("target") or ""
        if not target.startswith("/") or target.startswith("/proc") or target.startswith("/sys"):
            continue
        if _looks_like_key(target):
            continue
        path = target.replace(" (deleted)", "")
        try:
            st = os.stat(path)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        ranked.append(( _rank(path), path, st.st_size))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    heads = []
    for _score, path, size in ranked[:3]:
        sample = _read_sample(path, errors)
        if sample is None:
            continue
        data, where = sample
        inspected = _inspect_bytes(data)
        heads.append({
            "path": path,
            "size": size,
            "where": where,
            "entropy": round(_entropy(data), 3),
            "json_keys": inspected["json_keys"],
            "sample": inspected["sample"],
        })
    return heads


def _rank(path: str) -> int:
    lowered = path.lower()
    return sum(1 for token in ("track", "json", "shm", "log", "cue", "plot") if token in lowered)


def _read_sample(path: str, errors: list) -> tuple[bytes, str] | None:
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            if size > 512:
                handle.seek(size - 512)
                where = "tail"
            else:
                handle.seek(0)
                where = "head"
            return handle.read(512), where
    except OSError as exc:
        errors.append(f"{path}: {exc.__class__.__name__}")
        return None


def _inspect_bytes(data: bytes) -> dict:
    text = data.decode("utf-8", "replace").strip()
    keys = []
    candidate = text
    if "\n" in text:
        candidate = text.splitlines()[-1]
    try:
        obj = json.loads(candidate)
    except json.JSONDecodeError:
        obj = None
    if isinstance(obj, dict):
        keys = sorted(str(key) for key in obj.keys())[:40]
    elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
        keys = sorted(str(key) for key in obj[0].keys())[:40]
    return {"json_keys": keys, "sample": text[:160]}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    from collections import Counter
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _read_environ(pid: int, errors: list) -> dict:
    try:
        raw = Path(f"/proc/{pid}/environ").read_bytes()
    except OSError as exc:
        errors.append(f"/proc/{pid}/environ: {exc.__class__.__name__}")
        return {}
    return parse_environ(raw)


def _read_services(processes: list[dict], errors: list) -> list[dict]:
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return _services_from_ppid(processes)
    try:
        listed = subprocess.run(
            [systemctl, "list-units", "--type=service", "--state=running",
             "--no-legend", "--plain", "--no-pager"],
            capture_output=True, text=True, timeout=8, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        errors.append(f"systemctl list: {exc.__class__.__name__}")
        return _services_from_ppid(processes)
    units = parse_systemctl_list(listed.stdout or "")
    if not units:
        return _services_from_ppid(processes)
    shown = []
    for offset in range(0, len(units), 40):
        chunk = units[offset:offset + 40]
        try:
            completed = subprocess.run(
                [systemctl, "show", "--no-pager", "-p", "Id", "-p", "FragmentPath", "-p", "ExecStart", *chunk],
                capture_output=True, text=True, timeout=8, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"systemctl show: {exc.__class__.__name__}")
            continue
        shown.extend(parse_systemctl_show(completed.stdout or ""))
    return shown or _services_from_ppid(processes)


def _services_from_ppid(processes: list[dict]) -> list[dict]:
    rows = []
    for proc in processes:
        if proc.get("tool") or proc.get("ppid") != 1:
            continue
        rows.append({
            "unit": f"pid:{proc['pid']}",
            "exec": proc.get("exe") or "",
            "fragment": "",
            "source": "ppid1",
        })
    return rows


def _trust_paths(processes: list[dict]) -> list[str]:
    paths = list(FIXED_TRUST_PATHS)
    home = Path("/home")
    if home.is_dir():
        try:
            for path in home.glob("*/.ssh/*"):
                if path.name in {"authorized_keys", "id_rsa", "id_ed25519", "id_ecdsa", "known_hosts"}:
                    paths.append(str(path))
        except OSError:
            pass
    for proc in processes:
        for fd in proc.get("fds") or []:
            target = fd.get("target") or ""
            if _looks_like_key(target):
                paths.append(target.replace(" (deleted)", ""))
    unique = []
    seen = set()
    for path in paths:
        if path not in seen:
            seen.add(path)
            unique.append(path)
    return unique[:80]


def _looks_like_key(path: str) -> bool:
    name = path.lower()
    return any(hint in name for hint in KEY_NAME_HINTS) or name.endswith(".pem")


def _read_perms(processes: list[dict], errors: list) -> list[dict]:
    records = []
    for path in _trust_paths(processes):
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode):
            continue
        mode = stat.S_IMODE(st.st_mode)
        records.append({
            "path": path,
            "mode": oct(mode),
            "owner": str(st.st_uid),
            "group": str(st.st_gid),
            "signing": _looks_like_key(path),
            "world_read": bool(mode & stat.S_IROTH),
            "world_write": bool(mode & stat.S_IWOTH),
            "group_read": bool(mode & stat.S_IRGRP),
        })
    return records


def _read_configs(processes: list[dict], errors: list) -> list[dict]:
    docs = []
    seen = set()
    for proc in processes:
        for fd in proc.get("fds") or []:
            target = fd.get("target") or ""
            if not target.startswith("/"):
                continue
            lowered = target.lower()
            if not lowered.endswith((".yml", ".yaml", ".json")):
                continue
            if target in seen:
                continue
            seen.add(target)
            parsed = _parse_config(target, errors)
            if parsed is not None:
                docs.append({"path": target, "data": parsed})
            if len(docs) >= 5:
                return docs
    return docs


def _parse_config(path: str, errors: list) -> dict | None:
    try:
        if os.path.getsize(path) > 65536:
            return None
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        errors.append(f"{path}: {exc.__class__.__name__}")
        return None
    if path.lower().endswith(".json"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else None
    return _parse_yaml_minimal(text)


def _parse_yaml_minimal(text: str) -> dict:
    """Small YAML subset: top-level keys, booleans, and one-level lists of maps."""
    out: dict = {}
    current = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if line.startswith((" ", "\t")):
            stripped = line.strip()
            if current and stripped.startswith("- "):
                inner = stripped[2:].strip()
                item = _yaml_item(inner)
                if item is not None:
                    out.setdefault(current, []).append(item)
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key, value = key.strip(), value.strip()
        if value == "":
            current = key
            out.setdefault(key, [])
            continue
        current = None
        out[key] = _yaml_scalar(value)
    return out


def _yaml_item(inner: str) -> dict | None:
    if not (inner.startswith("{") and inner.endswith("}")):
        return None
    item = {}
    for part in inner[1:-1].split(","):
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        item[key.strip()] = value.strip().strip('"').strip("'")
    return item or None


def _yaml_scalar(value: str):
    clean = value.strip().strip('"').strip("'")
    lowered = clean.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    try:
        return int(clean)
    except ValueError:
        return clean


def _read_timers(errors: list) -> list[dict]:
    """Capture all systemd timers to catch evasive persistence."""
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return []
    try:
        completed = subprocess.run(
            [systemctl, "list-timers", "--all", "--no-pager", "--no-legend"],
            capture_output=True, text=True, timeout=8, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        errors.append(f"systemctl timers: {exc.__class__.__name__}")
        return []
    
    timers = []
    for line in (completed.stdout or "").splitlines():
        line = line.strip()
        if line:
            timers.append({"raw": line})
    return timers