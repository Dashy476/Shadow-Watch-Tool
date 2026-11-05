"""Operator bash history. Never copied to a node.

Updates ~/.bashrc in place. Existing HISTSIZE, HISTFILESIZE, HISTTIMEFORMAT,
HISTCONTROL, and PROMPT_COMMAND lines are replaced. Other lines stay.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

HISTORY_LINES = (
    "export HISTSIZE=100000",
    "export HISTFILESIZE=200000",
    "export HISTTIMEFORMAT='%F %T '",
    "shopt -s histappend",
    "export HISTCONTROL=",
    "unset HISTIGNORE",
    'PROMPT_COMMAND="history -a${PROMPT_COMMAND:+; $PROMPT_COMMAND}"',
)

_COMMENT = re.compile(r"^\s*#")
_ASSIGN = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")
_SHOPT = re.compile(r"^\s*shopt\s+-[su]\s+histappend\s*$")
_UNSET_IGNORE = re.compile(r"^\s*unset\s+HISTIGNORE\s*$")

_REPLACEMENTS = {
    "HISTSIZE": HISTORY_LINES[0],
    "HISTFILESIZE": HISTORY_LINES[1],
    "HISTTIMEFORMAT": HISTORY_LINES[2],
    "HISTCONTROL": HISTORY_LINES[4],
    "PROMPT_COMMAND": HISTORY_LINES[6],
}


def bashrc_path(home: Path | None = None) -> Path:
    """Bash reads these settings. PowerShell and other shells do not."""
    if home is None:
        raw = os.environ.get("HOME") or os.environ.get("USERPROFILE") or str(Path.home())
        home = Path(raw)
    return home / ".bashrc"


def render_history(text: str) -> tuple[str, list[str]]:
    """Return the updated file text and the history lines that changed."""
    newline = "\r\n" if "\r\n" in text else "\n"
    had_final_newline = text.endswith("\n") or text == ""
    seen: set[str] = set()
    out: list[str] = []
    changes: list[str] = []

    for line in text.splitlines():
        if _COMMENT.match(line):
            out.append(line)
            continue
        if _SHOPT.match(line):
            _take(out, changes, seen, "histappend", HISTORY_LINES[3], line)
            continue
        if _UNSET_IGNORE.match(line):
            _take(out, changes, seen, "HISTIGNORE", HISTORY_LINES[5], line)
            continue
        match = _ASSIGN.match(line)
        if match and match.group(1) == "HISTIGNORE":
            changes.append("removed HISTIGNORE")
            continue
        if match and match.group(1) in _REPLACEMENTS:
            name = match.group(1)
            _take(out, changes, seen, name, _REPLACEMENTS[name], line)
            continue
        out.append(line)

    missing = {
        "HISTSIZE": HISTORY_LINES[0],
        "HISTFILESIZE": HISTORY_LINES[1],
        "HISTTIMEFORMAT": HISTORY_LINES[2],
        "histappend": HISTORY_LINES[3],
        "HISTCONTROL": HISTORY_LINES[4],
        "HISTIGNORE": HISTORY_LINES[5],
        "PROMPT_COMMAND": HISTORY_LINES[6],
    }
    for key, desired in missing.items():
        if key not in seen:
            out.append(desired)
            changes.append(f"added {key}")

    if not changes:
        return text, []
    body = newline.join(out)
    if out and (had_final_newline or not text.endswith("\n")):
        body += newline
    return body, changes


def _take(out: list[str], changes: list[str], seen: set[str], key: str, desired: str, line: str) -> None:
    if key in seen:
        changes.append(f"removed duplicate {key}")
        return
    seen.add(key)
    if line.strip() != desired:
        changes.append(f"updated {key}")
        out.append(desired)
    else:
        out.append(line)


def apply_user_history(path: Path | None = None) -> tuple[Path, list[str]]:
    """Write the history block. Return the path and what changed."""
    target = path or bashrc_path()
    existing = ""
    if target.is_file():
        existing = target.read_text(encoding="utf-8")
    updated, changes = render_history(existing)
    if changes:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(updated.encode("utf-8"))
    return target, changes
