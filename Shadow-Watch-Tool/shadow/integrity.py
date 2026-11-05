"""Hash our own modules and compare them to the manifest from session start."""

from __future__ import annotations

import hashlib
from pathlib import Path

# Operator-only files. They are hashed locally but never copied to the node.
OPERATOR_ONLY = {
    "HARBNGR.py",
    "shadow/session.py",
    "shadow/orchestrator.py",
    "shadow/shellhist.py",
    "shadow/grid.py",
    "shadow/scope.py",
}


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_file(path: Path) -> str:
    return hash_bytes(path.read_bytes())


def local_manifest(root: Path) -> dict[str, str]:
    files = []
    harb = root / "HARBNGR.py"
    if harb.is_file():
        files.append(harb)
    shadow = root / "shadow"
    if shadow.is_dir():
        for path in shadow.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            files.append(path)
    manifest = {}
    for path in files:
        rel = path.relative_to(root).as_posix()
        manifest[rel] = hash_file(path)
    return manifest


def upload_relpaths(manifest: dict[str, str]) -> list[str]:
    """Stdlib modules staged onto the bunker for review and node_agent."""
    return sorted(
        rel for rel in manifest
        if rel not in OPERATOR_ONLY and rel.startswith("shadow/")
    )


def compare(expected: dict[str, str], current: dict[str, str]) -> list[str]:
    changed = []
    for rel in sorted(set(expected) | set(current)):
        if expected.get(rel) != current.get(rel):
            changed.append(rel)
    return changed
