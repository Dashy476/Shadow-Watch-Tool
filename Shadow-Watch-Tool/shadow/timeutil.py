"""One timestamp format for every log, snapshot, and writeup line."""

from __future__ import annotations

import time


def stamp(when: float | None = None) -> str:
    """UTC timestamp YYYY-MM-DDTHH:MM:SSZ."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(when if when is not None else time.time()))
