"""On-node entry point. Stdlib only. One JSON object on stdout.

Reviewed code is what runs: HARBNGR execs this file by its absolute path
after the human gate. It does not open sockets and it does not reboot.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in {"-h", "--help"}:
        sys.stdout.write('{"ok": false, "error": "use snapshot, space, hashes, or run"}\n')
        return 2
    command = argv[0]
    try:
        if command == "snapshot":
            result = _snapshot(argv[1:])
        elif command == "space":
            result = _space(argv[1:])
        elif command == "hashes":
            result = _hashes(argv[1:])
        elif command == "run":
            result = _run(argv[1:])
        else:
            result = {"ok": False, "error": f"unknown command {command}"}
    except Exception as exc:  # collector must still emit JSON the operator can store
        result = {"ok": False, "error": f"{exc.__class__.__name__}: {exc}"}
    sys.stdout.write(json.dumps(result))
    return 0 if result.get("ok") else 1


def _snapshot(argv: list[str]) -> dict:
    from shadow.collect import build_snapshot
    operator_unix = 0.0
    if "--operator-unix" in argv:
        operator_unix = float(argv[argv.index("--operator-unix") + 1])
    return build_snapshot(operator_unix=operator_unix)


def _space(argv: list[str]) -> dict:
    from shadow.collect import disk_free
    path = "/"
    if "--path" in argv:
        path = argv[argv.index("--path") + 1]
    return disk_free(path)


def _hashes(argv: list[str]) -> dict:
    if "--files" not in argv:
        return {"ok": False, "error": "hashes needs --files"}
    start = argv.index("--files") + 1
    paths = argv[start:]
    found = {}
    for raw in paths:
        path = Path(raw)
        if not path.is_file():
            found[raw] = ""
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        found[raw] = digest
    return {"ok": True, "hashes": found}


def _run(argv: list[str]) -> dict:
    from shadow.containment import validate_exec
    if "--" in argv:
        cmd = argv[argv.index("--") + 1:]
    else:
        cmd = argv
    reason = validate_exec(cmd)
    if reason:
        return {"ok": False, "error": reason, "argv": cmd}
    import subprocess
    completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return {
        "ok": completed.returncode == 0,
        "code": completed.returncode,
        "stdout": (completed.stdout or "")[-2000:],
        "stderr": (completed.stderr or "")[-2000:],
        "argv": cmd,
    }


if __name__ == "__main__":
    sys.exit(main())
