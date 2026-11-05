"""Plan an idempotent module copy. The SSH transfer itself lives in session.py."""

from __future__ import annotations

from pathlib import Path


def remote_join(root: str, rel: str) -> str:
    return root.rstrip("/") + "/" + rel.lstrip("/")


def plan_uploads(local_hashes: dict[str, str], remote_hashes: dict[str, str]) -> list[str]:
    """Relative paths whose bunker copy is missing or different. Same hash is skipped."""
    return [rel for rel in sorted(local_hashes) if remote_hashes.get(rel) != local_hashes[rel]]


def needed_bytes(paths: list[Path]) -> int:
    payload = sum(path.stat().st_size for path in paths)
    return payload * 2 + 8 * 1024 * 1024
