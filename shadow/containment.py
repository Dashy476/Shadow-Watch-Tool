"""Containment suggestions ranked by uptime risk.

Nothing in this module runs a command. The operator asks for a human YES
and then node_agent runs only an argv that validate_exec accepts.
Host reboot, reimage, and docker restart are never suggested.
"""

from __future__ import annotations

import re

BANNED_UNIT_WORDS = ("reboot", "shutdown", "halt", "poweroff", "docker", "reimage")
UNIT_RE = re.compile(r"^[A-Za-z0-9:@._\-]+$")
PATH_RE = re.compile(r"^/[A-Za-z0-9._+\-/]+$")


def suggest(classification: dict, services: list[dict], alerts: list[dict], timers: list[dict] = None) -> dict:
    if timers is None:
        timers = []
        
    protected = classification.get("protected")
    if classification.get("mission_unclear") or not protected:
        return {
            "suggestions": [],
            "refused": ["destructive actions refused until a mission uplink is identified"],
            "note": classification.get("note") or "mission uplink unknown",
        }
    _bind_unit(protected, services)
    suggestions = []
    refused = []
    
    # 1. Network flow containment
    for flow in classification.get("flows") or []:
        if flow.get("action") != "block":
            continue
        for item in _for_flow(flow, services, alerts):
            reason = touches_protected(item, protected)
            if reason:
                refused.append(f"{item['id']} refused: {reason}")
                continue
            suggestions.append(item)
            
    # 2. File and trust containment
    for item in _for_trust(alerts, protected):
        reason = touches_protected(item, protected)
        if reason:
            refused.append(f"{item['id']} refused: {reason}")
            continue
        suggestions.append(item)
        
    # 3. Evasive systemd timer containment
    for item in _for_timers(timers):
        reason = touches_protected(item, protected)
        if reason:
            refused.append(f"{item['id']} refused: {reason}")
            continue
        suggestions.append(item)
        
    suggestions.sort(key=lambda item: (item["risk"], -float(item.get("confidence") or 0)))
    for index, item in enumerate(suggestions, start=1):
        item["id"] = f"c{index}"
    return {"suggestions": suggestions, "refused": refused, "note": classification.get("note") or ""}


def _bind_unit(protected: dict, services: list[dict]) -> None:
    exe = protected.get("exe") or ""
    for service in services:
        if exe and service.get("exec") == exe:
            protected["unit"] = service.get("unit") or ""
            return


def _for_flow(flow: dict, services: list[dict], alerts: list[dict]) -> list[dict]:
    pid = flow.get("pid")
    ip = flow.get("remote_ip")
    port = flow.get("remote_port")
    confidence = flow.get("confidence") or 0
    items = []
    if ip and port:
        items.append(_item(
            "drop-connection", 1, confidence, pid, ip, port, "",
            f"drop the outbound connection to {ip}:{port}",
            ["ss", "-K", "dst", ip, "dport", "=", str(port)],
            "If this peer was needed, do nothing. A live process will reconnect. "
            "Restore from the pre-action snapshot if a later step is worse. Do not reboot the host.",
        ))
    if pid:
        items.append(_item(
            "kill-process", 2, confidence, pid, ip, port, "",
            f"terminate pid {pid} comm={flow.get('comm')}",
            ["kill", "-TERM", str(pid)],
            "If the process was a child of a legitimate unit, restart that unit from the "
            "pre-action snapshot. Do not restart the core tracker. Do not reboot the host.",
        ))
    unit = _unit_for_exe(flow.get("exe") or "", services)
    relocated = any(
        alert.get("kind") == "service-relocated" and alert.get("evidence", {}).get("unit") == unit
        for alert in alerts
    )
    if unit and relocated:
        items.append(_item(
            "restart-service", 3, confidence, pid, ip, port, unit,
            f"restart {unit} after the foreign process is gone",
            ["systemctl", "restart", unit],
            "If the service comes up wrong, restart it again from the pre-action unit path. "
            "Do not reboot the host.",
        ))
    return items


def _unit_for_exe(exe: str, services: list[dict]) -> str:
    if not exe:
        return ""
    for service in services:
        if service.get("exec") == exe:
            return service.get("unit") or ""
    return ""


def _for_trust(alerts: list[dict], protected: dict) -> list[dict]:
    items = []
    for found in alerts:
        if found.get("kind") != "trust-material":
            continue
        path = (found.get("evidence") or {}).get("path") or ""
        mode = (found.get("evidence") or {}).get("mode") or ""
        if not path:
            continue
        items.append(_item(
            "modify-config", 4, found.get("confidence") or 0.5,
            None, "", 0, "",
            f"tighten permissions on {path}",
            ["chmod", "600", path],
            f"If a service loses access, restore the previous mode ({mode or 'see pre-action snapshot'}) "
            f"with chmod. The pre-action snapshot records the old mode. Do not reboot the host.",
            extra={"path": path},
        ))
    return items


def _for_timers(timers: list[dict]) -> list[dict]:
    items = []
    # Hardcoded baseline of standard Ubuntu system timers
    safe_timers = {
        "apt-daily-upgrade.timer", "apt-daily.timer", "dpkg-db-backup.timer",
        "e2scrub_all.timer", "fstrim.timer", "fwupd-refresh.timer",
        "logrotate.timer", "man-db.timer", "motd-news.timer",
        "systemd-tmpfiles-clean.timer", "update-notifier-download.timer",
        "update-notifier-motd.timer", "phpsessionclean.timer",
        "apport-autoreport.timer", "snapd.snap-repair.timer",
        "ua-timer.timer", "snapd.aa-prompt-listener.timer"
    }
    
    for t in timers:
        line = t.get("raw", "")
        parts = line.split()
        timer_unit = ""
        # Find the timer unit in the space-delimited string
        for part in parts:
            if part.endswith(".timer"):
                timer_unit = part
                break
        
        if not timer_unit or timer_unit in safe_timers:
            continue
            
        items.append(_item(
            "disable-timer", 1, 0.9, None, "", 0, timer_unit,
            f"disable non-standard timer {timer_unit} driving evasive callbacks",
            ["systemctl", "disable", "--now", timer_unit],
            f"If this timer is legitimate, re-enable it with: systemctl enable --now {timer_unit}. Do not reboot."
        ))
    return items


def _item(action, risk, confidence, pid, ip, port, unit, why, argv, rollback, extra=None) -> dict:
    item = {
        "id": action,
        "action": action,
        "risk": risk,
        "confidence": confidence,
        "pid": pid,
        "remote_ip": ip or "",
        "remote_port": port or 0,
        "unit": unit,
        "why": why,
        "argv": argv,
        "command_preview": " ".join(argv),
        "rollback": rollback,
        "executable": True,
    }
    if extra:
        item.update(extra)
    return item


def touches_protected(item: dict, protected: dict | None) -> str:
    if not protected:
        return "mission uplink is not identified"
    pid = item.get("pid")
    if pid and int(pid) == int(protected.get("pid") or -1):
        return "pid is the core tracking process"
    if pid and int(pid) in {int(value) for value in protected.get("ancestor_pids") or []}:
        return "pid is an ancestor of the core tracking process"
    if item.get("remote_ip") and item.get("remote_port"):
        if item["remote_ip"] == protected.get("remote_ip") and int(item["remote_port"]) == int(protected.get("remote_port") or -1):
            if item.get("action") in {"drop-connection", "kill-process"}:
                return "socket is the mission uplink"
    unit = item.get("unit") or ""
    if unit and unit == (protected.get("unit") or ""):
        return "unit is the core tracker service"
    exe = protected.get("exe") or ""
    path = item.get("path") or ""
    if path and exe and path == exe:
        return "path is the core tracker binary"
    return ""


def validate_exec(argv: list[str]) -> str:
    """Return an empty string when argv is allowlisted, else the refusal reason."""
    if not argv:
        return "empty command"
    joined = " ".join(argv).lower()
    for word in ("reboot", "shutdown", "poweroff", "halt", "reimage", "docker", "mkfs", "init"):
        if word in joined.split():
            return f"{word} is forbidden"
    head = argv[0]
    if head == "ss":
        if argv[1:] and argv[1] == "-K" and len(argv) == 7 and argv[2] == "dst" and argv[4] == "dport" and argv[5] == "=":
            if _ip_ok(argv[3]) and argv[6].isdigit():
                return ""
        return "ss invocation is not the allowlisted drop form"
    if head == "kill":
        if len(argv) == 3 and argv[1] == "-TERM" and argv[2].isdigit() and int(argv[2]) > 1:
            return ""
        return "kill is only allowlisted as TERM for a single pid above 1"
    if head == "systemctl":
        if len(argv) >= 3 and argv[1] in ("restart", "stop", "disable") and UNIT_RE.match(argv[-1]):
            lowered = argv[-1].lower()
            if any(word in lowered for word in BANNED_UNIT_WORDS):
                return "that unit is forbidden"
            if argv[1] == "restart" and len(argv) == 3:
                return ""
            if argv[1] in ("stop", "disable"):
                if len(argv) == 3:
                    return ""
                if len(argv) == 4 and argv[2] == "--now":
                    return ""
        return "systemctl is only allowlisted for restart/stop/disable on one unit, optionally with --now"
    if head == "chmod":
        if len(argv) == 3 and argv[1] == "600" and PATH_RE.match(argv[2]) and ".." not in argv[2]:
            return ""
        return "chmod is only allowlisted as mode 600 on one absolute path"
    return "command is not allowlisted"


def _ip_ok(value: str) -> bool:
    if not value or any(char.isspace() for char in value):
        return False
    parts = value.split(".")
    if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
        return True
    return ":" in value and all(char in "0123456789abcdefABCDEF:" for char in value)