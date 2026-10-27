"""Parsers for /proc and systemctl text. No /proc access at import time."""

from __future__ import annotations

import socket

TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}

SHELLS = {
    "bash", "sh", "dash", "ash", "rbash", "zsh", "ksh", "csh",
    "nc", "ncat", "netcat", "curl", "wget", "socat",
}

TOOL_MARK = "node_agent.py"


def decode_ipv4(hex_ip: str) -> str:
    raw = bytes.fromhex(hex_ip)
    return socket.inet_ntop(socket.AF_INET, raw[::-1])


def decode_ipv6(hex_ip: str) -> str:
    buf = bytearray()
    for offset in range(0, 32, 8):
        word = bytes.fromhex(hex_ip[offset:offset + 8])
        buf.extend(word[::-1])
    return socket.inet_ntop(socket.AF_INET6, bytes(buf))


def is_loopback(ip: str) -> bool:
    return ip.startswith("127.") or ip == "::1" or ip.startswith("::ffff:127.")


def is_unspecified(ip: str) -> bool:
    return ip in {"0.0.0.0", "::", "*"}


def _parse_addr(field: str, ipv6: bool) -> tuple[str, int]:
    ip_hex, port_hex = field.split(":")
    ip = decode_ipv6(ip_hex) if ipv6 else decode_ipv4(ip_hex)
    return ip, int(port_hex, 16)


def parse_proc_net(text: str, proto: str, ipv6: bool = False) -> list[dict]:
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 10 or parts[0] in {"sl", "sl:"} or "local_address" in line:
            continue
        if ":" not in parts[1] or ":" not in parts[2]:
            continue
        try:
            local_ip, local_port = _parse_addr(parts[1], ipv6)
            remote_ip, remote_port = _parse_addr(parts[2], ipv6)
        except (ValueError, OSError):
            continue
        state = TCP_STATES.get(parts[3].upper(), parts[3])
        rows.append({
            "proto": proto,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "local": f"{local_ip}:{local_port}",
            "remote": f"{remote_ip}:{remote_port}",
            "state": state,
            "uid": int(parts[7]) if parts[7].isdigit() else -1,
            "inode": parts[9],
        })
    return rows


def parse_unix(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 7 or parts[0] == "Num":
            continue
        path = parts[7] if len(parts) > 7 else ""
        rows.append({
            "inode": parts[6],
            "path": path,
            "flags": parts[3],
            "type": parts[4],
        })
    return rows


def parse_route(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            dest = decode_ipv4(parts[1])
            gateway = decode_ipv4(parts[2])
        except (ValueError, OSError):
            continue
        rows.append({"iface": parts[0], "destination": dest, "gateway": gateway})
    return rows


def parse_arp(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4 or parts[0] == "IP":
            continue
        rows.append({"ip": parts[0], "hw": parts[3], "device": parts[-1]})
    return rows


def parse_stat(text: str) -> tuple[int, str, int] | None:
    left = text.find("(")
    right = text.rfind(")")
    if left < 0 or right < left:
        return None
    pid_text = text[:left].strip()
    if not pid_text.isdigit():
        return None
    rest = text[right + 1:].split()
    if len(rest) < 2:
        return None
    return int(pid_text), text[left + 1:right], int(rest[1])


def parse_map_line(line: str) -> dict | None:
    parts = line.split()
    if len(parts) < 5:
        return None
    path = " ".join(parts[5:]) if len(parts) > 5 else ""
    return {"perms": parts[1], "path": path}


def interesting_path(path: str) -> bool:
    if not path:
        return False
    if "(deleted)" in path or path.startswith("/dev/shm") or "/dev/shm/" in path:
        return True
    if "tmpfs" in path:
        return True
    parts = [part for part in path.split("/") if part not in ("", ".", "..")]
    return any(part.startswith(".") for part in parts)


def parse_io(text: str) -> dict[str, int]:
    out = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        value = value.strip()
        if value.isdigit():
            out[key.strip()] = int(value)
    return out


def parse_environ(raw: bytes) -> dict[str, str]:
    text = raw.decode("utf-8", "replace")
    out = {}
    for item in text.split("\0"):
        if not item or "=" not in item:
            continue
        key, value = item.split("=", 1)
        out[key] = value[:500]
        if len(out) >= 100:
            break
    return out


def parse_systemctl_list(text: str) -> list[str]:
    units = []
    for line in text.splitlines():
        parts = line.split()
        if parts and parts[0].endswith(".service"):
            units.append(parts[0])
    return units


def parse_execstart(text: str) -> str:
    marker = "path="
    index = text.find(marker)
    if index < 0:
        return ""
    rest = text[index + len(marker):]
    stop = len(rest)
    for sep in (" ", ";", "}"):
        pos = rest.find(sep)
        if pos >= 0:
            stop = min(stop, pos)
    return rest[:stop]


def parse_systemctl_show(text: str) -> list[dict]:
    """Split `systemctl show` blocks into unit, fragment path, and exec path."""
    blocks = []
    current: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            if current.get("unit"):
                blocks.append({
                    "unit": current.get("unit", ""),
                    "exec": parse_execstart(current.get("ExecStart", "")),
                    "fragment": current.get("FragmentPath", ""),
                    "source": "systemctl",
                })
            current = {}
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key == "Id":
            current["unit"] = value.strip()
        else:
            current[key] = value
    if current.get("unit"):
        blocks.append({
            "unit": current.get("unit", ""),
            "exec": parse_execstart(current.get("ExecStart", "")),
            "fragment": current.get("FragmentPath", ""),
            "source": "systemctl",
        })
    return blocks


def fd_mode(flags_octal: str) -> str:
    try:
        access = int(flags_octal, 8) & 0x3
    except ValueError:
        return ""
    if access == 0:
        return "read"
    if access == 1:
        return "write"
    return "readwrite"


def is_tool_cmdline(cmdline: str) -> bool:
    return TOOL_MARK in (cmdline or "")


def _split_endpoint(token: str) -> tuple[str, int]:
    if token.startswith("["):
        host, _, port = token[1:].rpartition("]:")
        return host, int(port or 0)
    if token.endswith(":*"):
        return token[:-2], 0
    host, _, port = token.rpartition(":")
    if not port.isdigit():
        return token, 0
    return host, int(port)


def parse_ss(text: str) -> list[dict]:
    """Best-effort parser for `ss -H -tanu`. Rows without a process inode."""
    rows = []
    for line in text.splitlines():
        parts = line.split()
        endpoints = [part for part in parts if ":" in part and not part.startswith("users:")]
        if len(endpoints) < 2:
            continue
        proto = "tcp"
        state = parts[0]
        if parts[0] in {"tcp", "udp"}:
            proto = parts[0]
            state = parts[1] if len(parts) > 1 else ""
        local_ip, local_port = _split_endpoint(endpoints[0])
        remote_ip, remote_port = _split_endpoint(endpoints[1])
        rows.append({
            "proto": proto,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "local": f"{local_ip}:{local_port}",
            "remote": f"{remote_ip}:{remote_port}",
            "state": state.replace("-", "_") if state != "ESTAB" else "ESTABLISHED",
            "uid": -1,
            "inode": "",
        })
    return rows
