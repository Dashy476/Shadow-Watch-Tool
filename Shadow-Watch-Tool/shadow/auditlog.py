"""Append-only hash-chained log of commands, snapshots, and decisions.

This is a private local record for disputes. It does not call git.
"""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

from shadow.timeutil import stamp


def canon(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _digest(body: dict) -> str:
    return hashlib.sha256(canon(body).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.prev = "0" * 64
        self.seq = 0
        if self.path.exists():
            lines = [ln for ln in self.path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            if lines:
                last = json.loads(lines[-1])
                self.prev = last["hash"]
                self.seq = int(last["seq"])

    def append(self, kind: str, summary: str, detail: dict | None = None) -> dict:
        with self._lock:
            return self._append(kind, summary, detail)

    def _append(self, kind: str, summary: str, detail: dict | None) -> dict:
        self.seq += 1
        body = {
            "seq": self.seq,
            "ts": stamp(),
            "kind": kind,
            "summary": summary,
            "detail": detail or {},
            "prev": self.prev,
        }
        body["hash"] = _digest(body)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(body, sort_keys=True, default=str) + "\n")
        self.prev = body["hash"]
        return body


def verify(path: str | Path) -> bool:
    prev = "0" * 64
    expect_seq = 0
    text = Path(path).read_text(encoding="utf-8")
    for line in text.splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        got = obj.pop("hash")
        expect_seq += 1
        if obj.get("seq") != expect_seq or obj.get("prev") != prev:
            return False
        if _digest(obj) != got:
            return False
        prev = got
    return True
