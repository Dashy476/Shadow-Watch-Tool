"""Operation Phantom Grid, team Bits_N_Bytes.

In-scope hosts only. The SENSOR that feeds EDGE-02 is not in this map.
"""

from __future__ import annotations

HOSTS = (
    {
        "label": "sentinel",
        "name": "SENTINEL-01",
        "ip": "10.80.40.11",
        "port": 22,
        "user": "operator",
        "bunker": "bunker-sentinel",
        "profile": "profiles/sentinel01.json",
    },
    {
        "label": "edge",
        "name": "EDGE-02",
        "ip": "10.80.40.12",
        "port": 22,
        "user": "operator",
        "bunker": "bunker-edge",
        "profile": "profiles/edge02.json",
    },
    {
        "label": "ops",
        "name": "OPS-03",
        "ip": "10.80.40.13",
        "port": 22,
        "user": "operator",
        "bunker": "bunker-ops",
        "profile": "profiles/ops03.json",
    },
)

SENTINEL_IP = "10.80.40.11"
EDGE_IP = "10.80.40.12"
OPS_IP = "10.80.40.13"
CONSOLE_PORT = 8080

# Comms that are allowed to hold the expected peer socket. Anything else is flagged.
DETECTION_COMM = ("track", "detect", "cuas", "sentinel", "console", "telemetry", "edge", "fusion")
LOG_COMM = ("rsyslog", "syslog", "logger", "journal", "forward", "log")


def normalize_label(label: str) -> str:
    text = (label or "").strip().lower().replace("_", "-")
    aliases = {
        "sentinel": "sentinel",
        "sentinel-01": "sentinel",
        "sentinel01": "sentinel",
        "s1": "sentinel",
        "edge": "edge",
        "edge-02": "edge",
        "edge02": "edge",
        "e2": "edge",
        "ops": "ops",
        "ops-03": "ops",
        "ops03": "ops",
        "o3": "ops",
    }
    return aliases.get(text, text)


def host_by_label(label: str) -> dict | None:
    key = normalize_label(label)
    for host in HOSTS:
        if host["label"] == key:
            return host
    return None


def host_by_ip(ip: str) -> dict | None:
    for host in HOSTS:
        if host["ip"] == (ip or "").strip():
            return host
    return None


def bunker_for(label: str) -> str:
    host = host_by_label(label)
    return host["bunker"] if host else ""


def profile_for(label: str) -> str:
    host = host_by_label(label)
    return host["profile"] if host else ""


def parse_hosts(text: str) -> list[dict]:
    """hosts.txt lines are: IP port user label. Blank lines and # comments are skipped."""
    found = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 4:
            raise ValueError(f"hosts.txt line {lineno}: expected 'IP port user label'")
        ip, port, user, label = parts
        if not port.isdigit():
            raise ValueError(f"hosts.txt line {lineno}: port is not a number")
        found.append({
            "ip": ip,
            "port": int(port),
            "user": user,
            "label": normalize_label(label),
            "line": lineno,
        })
    return found


def format_hosts_env(hosts: list[dict], password: str) -> str:
    """One prefixed block per host. The file is local and must not be committed."""
    lines = ["# Local only. Do not commit.", ""]
    for host in hosts:
        label = host["label"]
        lines.append(f"# {label}")
        lines.append(f"{label}.SW_SSH_HOST={host['ip']}")
        lines.append(f"{label}.SW_SSH_PORT={host['port']}")
        lines.append(f"{label}.SW_SSH_USER={host['user']}")
        lines.append(f"{label}.SW_SSH_PASSWORD={password}")
        lines.append(f"{label}.SW_HOST_LABEL={label}")
        lines.append(f"{label}.SW_SSH_JUMP=")
        lines.append("")
    return "\n".join(lines)


def env_file_text(host: dict, password: str) -> str:
    values = {
        "SW_SSH_HOST": host["ip"],
        "SW_SSH_PORT": str(host["port"]),
        "SW_SSH_USER": host["user"],
        "SW_SSH_PASSWORD": password,
        "SW_HOST_LABEL": host["label"],
        "SW_SSH_JUMP": "",
        "SW_SSH_JUMP_PASSWORD": "",
        "SW_SSH_KEY": "",
    }
    return "".join(f"{key}={value}\n" for key, value in values.items())
