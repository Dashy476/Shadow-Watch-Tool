"""Shadow Watch operator entry.

SSH from this machine only. Collectors on the node are stdlib.
Secrets come from the environment and are removed before any prompt or log.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from shadow.grid import bunker_for, normalize_label, profile_for, HOSTS
from shadow.orchestrator import Operator, run_replay
from shadow.secrets import take_env
from shadow.session import RemoteSession
from shadow.timeline import merge_writeups


def main(argv: list[str] | None = None) -> int:
    secrets = take_env()
    parser = argparse.ArgumentParser(description="Shadow Watch blue-team entry (HARBNGR)")
    parser.add_argument("--host", default=secrets.get("SW_SSH_HOST") or "")
    parser.add_argument("--port", type=int, default=_port(secrets.get("SW_SSH_PORT"), 22))
    parser.add_argument("--user", default=secrets.get("SW_SSH_USER") or "")
    parser.add_argument("--host-label", default=secrets.get("SW_HOST_LABEL") or "",
                        help="sentinel, edge, or ops; tags bunker output")
    parser.add_argument("--jump", default=secrets.get("SW_SSH_JUMP") or "", help="jump host, or user@host")
    parser.add_argument("--jump-port", type=int, default=_port(secrets.get("SW_SSH_JUMP_PORT"), 22))
    parser.add_argument(
        "--remote-bunker",
        default="",
        help="remote module directory (default /home/<user>/shadow-bunker)",
    )
    parser.add_argument("--local-bunker", default="",
                        help="operator bunker (default bunker-sentinel, bunker-edge, or bunker-ops from --host-label)")
    parser.add_argument("--merge", nargs="*", default=None,
                        help="write merged-report.md from bunker writeups (default: the three host bunkers)")
    parser.add_argument("--interval", type=float, default=3.0)
    parser.add_argument("--profile", default="")
    parser.add_argument("--iocs", default="iocs.txt")
    parser.add_argument("--replay", default="", help="score a directory of snapshot JSON and exit")
    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parent
    if args.merge is not None:
        return _write_merged(root, args.merge)
    label = normalize_label(args.host_label)
    profile = Path(args.profile) if args.profile else (
        root / profile_for(label) if profile_for(label) else root / "profiles" / "sentinel01.json"
    )
    local_bunker = args.local_bunker or bunker_for(label) or "bunker"
    if args.interval < 2 or args.interval > 5:
        print("interval clamped to the 2-5 second range")

    if args.replay:
        return run_replay(Path(args.replay), Path(local_bunker), profile, Path(args.iocs))

    host = args.host or input("Host: ").strip()
    user = args.user or input("User: ").strip()
    if not host or not user:
        print("host and user are required")
        return 2
    password = secrets.get("SW_SSH_PASSWORD")
    key_path = secrets.get("SW_SSH_KEY")
    if not password and not key_path:
        password = getpass.getpass("Password: ")
    jump_host, jump_user = _jump(args.jump, secrets.get("SW_SSH_JUMP_USER") or user)
    session = RemoteSession(
        host=host,
        port=args.port,
        user=user,
        password=None if key_path else password,
        key_path=key_path,
        jump=jump_host,
        jump_port=args.jump_port,
        jump_user=jump_user,
        jump_password=secrets.get("SW_SSH_JUMP_PASSWORD") or password,
    )
    operator = Operator(
        root=root,
        local_bunker=Path(local_bunker),
        remote_bunker=args.remote_bunker or default_remote_bunker(user),
        interval=args.interval,
        profile_path=profile,
        ioc_path=Path(args.iocs),
        session=session,
        host_label=label,
    )
    return operator.run()


def _write_merged(root: Path, names: list[str]) -> int:
    chosen = names or [host["bunker"] for host in HOSTS]
    parts = []
    for name in chosen:
        folder = Path(name)
        if not folder.is_absolute():
            folder = root / name
        path = folder / "writeup.md"
        text = path.read_text(encoding="utf-8") if path.is_file() else ""
        title = folder.name
        label = folder.name
        for host in HOSTS:
            if folder.name in {host["bunker"], host["label"]}:
                title = host["name"]
                label = host["label"]
        parts.append({"label": label, "title": title, "path": str(path), "text": text})
    out = root / "merged-report.md"
    out.write_text(merge_writeups(parts), encoding="utf-8")
    print("merged report", out)
    return 0


def default_remote_bunker(user: str) -> str:
    """Home directory the login account can write. /var/bunker is often not writable."""
    return f"/home/{user}/shadow-bunker"


def _port(value: str | None, default: int) -> int:
    if not value:
        return default
    return int(value)


def _jump(text: str, default_user: str) -> tuple[str, str]:
    if not text:
        return "", default_user
    if "@" in text:
        user, host = text.split("@", 1)
        return host, user
    return text, default_user


if __name__ == "__main__":
    sys.exit(main())
