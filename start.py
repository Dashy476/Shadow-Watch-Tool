#!/usr/bin/env python3
"""
HARBNGR launcher  -  one command, ready to scan.

    python start.py            normal: splash -> confirm target -> preflight -> launch
    python start.py -y         zero-prompt: use saved target, preflight, launch
    python start.py --edit     change target/credentials
    python start.py --reset    forget saved target and start the wizard
    python start.py --fast     skip the splash animation
    python start.py --no-check skip preflight (not recommended)
    python start.py --art NAME use art/NAME.txt as the splash (if it fits the window)

Any other flags are passed straight through to HARBNGR.py.
"""
from __future__ import annotations

import os
import sys
import time
import random
import getpass
import shutil
import socket
import subprocess
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
os.chdir(HERE)  # always run from the tool's folder, no matter where it was launched

ENV_FILE = Path(".env")
BUNKER = Path("bunker")


# --------------------------------------------------------------------------- #
#  Terminal / colour helpers
# --------------------------------------------------------------------------- #
def enable_ansi() -> None:
    if os.name == "nt":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            h = k.GetStdHandle(-11)
            m = ctypes.c_ulong()
            if k.GetConsoleMode(h, ctypes.byref(m)):
                k.SetConsoleMode(h, m.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        except Exception:
            os.system("")
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def rgb(r, g, b) -> str:
    return f"\033[38;2;{r};{g};{b}m"


RST = "\033[0m"
BOLD = "\033[1m"
GREEN = rgb(80, 250, 123)
RED = rgb(255, 85, 85)
YEL = rgb(241, 250, 140)
CYAN = rgb(139, 233, 253)
PURP = rgb(189, 147, 249)
PINK = rgb(255, 121, 198)
GREY = rgb(125, 125, 150)


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


# --------------------------------------------------------------------------- #
#  Splash
# --------------------------------------------------------------------------- #
HAUNTER = """\
⠀⠀⠀⠲⣦⣤⣀⣀⠀⠀⠀⣀⣀⣠⣤⣀⣀⠀⢀⣀⣠⣤⣶⣶⠟⠀⠀⠀
⠀⠀⠀⠀⠙⣿⣿⣿⣿⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠋⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠈⢿⣿⣿⠻⣿⣿⣿⣿⣿⣿⣿⠟⢻⣿⣿⡿⠃⠀⠀⠀⠀⠀
⠀⠀⠀⠲⣶⣶⣾⣿⣿⠀⢨⠙⢿⣿⣿⠏⣅⠀⢸⣿⣿⣷⣾⠟⠁⠀⠀⠀
⠀⠀⠀⠀⠈⠻⢿⣿⣿⢷⣶⣶⣾⣿⣿⣶⣶⣾⠟⣿⣿⣿⣋⠀⠀⠀⠀⠀
⠀⠀⢀⣀⣀⠐⢶⣿⣿⣧⠁⠀⠋⠁⠈⠋⠀⢀⣾⣿⣿⡿⣷⣶⠀⠀⠀⠀
⠀⠀⣼⣿⣿⣷⣤⣙⣿⣿⣷⣶⣶⣴⣴⣴⣶⣿⣿⣿⠟⣡⣿⣿⣧⣄⣀⡀
⢀⣤⣿⣿⣿⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⣿⣿⣿⣿⠿⢿⣿⡿⠿⣿⣿⣿⣿
⣿⡿⠛⠿⠟⠉⠉⠉⠸⠋⠀⠻⡿⣿⣿⣿⣿⠻⠇⠀⠀⠈⠀⠀⠈⠉⢸⠃
⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠈⢿⢻⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"""

QUIPS = [
    "Haunter is watching your ports.",
    "No persistence survives the gaze.",
    "Sandy says: check your cron. Then check it again.",
    "Trust no timer file.",
    "If it's named 'guard', it's probably not.",
    "Lick the intruders. Ghost-type approved.",
]


def load_art(name: str | None) -> list[str]:
    """Return art lines. Custom art lives in art/<name>.txt; falls back to Haunter
    if the file is missing or won't fit the terminal."""
    lines = HAUNTER.splitlines()
    if name:
        p = Path("art") / f"{name}.txt"
        if p.exists():
            custom = p.read_text(encoding="utf-8", errors="ignore").splitlines()
            size = shutil.get_terminal_size((100, 40))
            width = max((len(l) for l in custom), default=0)
            if custom and width <= size.columns - 2 and len(custom) <= size.lines - 12:
                return custom
            print(f"{YEL}[!] art/{name}.txt is {width}x{len(custom)}; window is "
                  f"{size.columns}x{size.lines}. Shrink the font (Ctrl+scroll) or use a smaller art file.{RST}")
    return lines


def splash(fast: bool, art_name: str | None) -> None:
    os.system("cls" if os.name == "nt" else "clear")
    art = load_art(art_name)
    n = max(len(art) - 1, 1)
    top, bot = (110, 70, 210), (235, 150, 255)
    delay = 0 if fast else 0.035
    print()
    for i, line in enumerate(art):
        r, g, b = lerp(top, bot, i / n)
        print(f"  {rgb(r, g, b)}{line}{RST}")
        if delay:
            time.sleep(delay)

    title = "H A R B N G R"
    print()
    print(f"  {PURP}╭{'─' * 44}╮{RST}")
    print(f"  {PURP}│{RST}  {BOLD}{PINK}{title}{RST}  {GREY}·{RST}  {CYAN}blue-team IOC scanner{RST}   {PURP}│{RST}")
    print(f"  {PURP}╰{'─' * 44}╯{RST}")
    quip = random.choice(QUIPS)
    if delay:
        print("  ", end="")
        for ch in quip:
            print(f"{GREY}{ch}{RST}", end="", flush=True)
            time.sleep(0.012)
        print("\n")
    else:
        print(f"  {GREY}{quip}{RST}\n")


# --------------------------------------------------------------------------- #
#  Prompt helpers
# --------------------------------------------------------------------------- #
def ask(label: str, default: str = "", secret: bool = False) -> str:
    hint = f" {GREY}[{default}]{RST}" if default and not secret else ""
    prompt = f"  {PURP}›{RST} {label}{hint}: "
    val = getpass.getpass(prompt) if secret else input(prompt)
    return val.strip() or default


def ok(msg):   print(f"  {GREEN}✔{RST} {msg}")
def warn(msg): print(f"  {YEL}!{RST} {msg}")
def bad(msg):  print(f"  {RED}✘{RST} {msg}")
def info(msg): print(f"  {CYAN}·{RST} {msg}")


# --------------------------------------------------------------------------- #
#  Config (.env)
# --------------------------------------------------------------------------- #
def load_env() -> dict:
    cfg = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    return cfg


def save_env(cfg: dict) -> None:
    ENV_FILE.write_text(
        "".join(f"{k}={cfg.get(k, '')}\n" for k in
                ("SW_SSH_HOST", "SW_SSH_PORT", "SW_SSH_USER", "SW_SSH_PASSWORD")),
        encoding="utf-8",
    )
    try:
        os.chmod(ENV_FILE, 0o600)
    except OSError:
        pass


def wizard(cfg: dict) -> dict:
    print(f"  {BOLD}{CYAN}TARGET SETUP{RST}  {GREY}(ENTER keeps the value in brackets){RST}\n")
    cfg["SW_SSH_HOST"] = ask("Target IP / hostname", cfg.get("SW_SSH_HOST", "127.0.0.1"))
    cfg["SW_SSH_PORT"] = ask("SSH port", cfg.get("SW_SSH_PORT", "2224"))
    cfg["SW_SSH_USER"] = ask("SSH username", cfg.get("SW_SSH_USER", "analyst"))
    old_pw = cfg.get("SW_SSH_PASSWORD", "")
    pw = ask("Password (hidden, ENTER keeps saved)" if old_pw else "Password (hidden)", secret=True)
    cfg["SW_SSH_PASSWORD"] = pw or old_pw
    save_env(cfg)
    print()
    ok("Saved to .env  " + GREY + "(local only - never commit this file)" + RST)
    return cfg


def show_target(cfg: dict) -> None:
    pw = "●" * min(len(cfg.get("SW_SSH_PASSWORD", "")), 8) or "(none)"
    print(f"  {BOLD}TARGET{RST}  {CYAN}{cfg.get('SW_SSH_USER')}{RST}{GREY}@{RST}"
          f"{CYAN}{cfg.get('SW_SSH_HOST')}{RST}{GREY}:{RST}{CYAN}{cfg.get('SW_SSH_PORT')}{RST}"
          f"   {GREY}pw {pw}{RST}\n")


# --------------------------------------------------------------------------- #
#  Previous-session handling (backs up instead of destroying evidence)
# --------------------------------------------------------------------------- #
def handle_old_session(assume_yes: bool) -> None:
    state = BUNKER / "session_state.json"
    if not (BUNKER.exists() and state.exists()):
        return
    age = int((time.time() - state.stat().st_mtime) / 60)
    warn(f"Previous session found {GREY}(last activity ~{age} min ago){RST}")
    if assume_yes:
        info("Keeping it and resuming. " + GREY + "(type YES when HARBNGR asks)" + RST + "\n")
        return
    choice = input(f"  {PURP}›{RST} [{BOLD}R{RST}]esume  /  [{BOLD}N{RST}]ew clean session "
                   f"{GREY}(old data is backed up first){RST}: ").strip().lower()
    if choice.startswith("n"):
        backup = Path(f"bunker_backup_{datetime.now():%Y%m%d_%H%M%S}")
        try:
            shutil.copytree(BUNKER, backup)
            shutil.rmtree(BUNKER, ignore_errors=True)
            ok(f"Old data saved to {CYAN}{backup}{RST}, starting fresh.\n")
        except Exception as e:
            bad(f"Backup failed ({e}); keeping existing data instead.\n")
    else:
        info("Resuming. " + GREY + "(type YES when HARBNGR asks)" + RST + "\n")


# --------------------------------------------------------------------------- #
#  Preflight
# --------------------------------------------------------------------------- #
def run_step(label: str, fn):
    """Run a check, show a live line, then rewrite it as pass/warn/fail.
    fn returns (True|False|None, message): None = warning."""
    print(f"  {GREY}◦ {label:<26}…{RST}", end="", flush=True)
    try:
        res, msg = fn()
    except Exception as e:  # never let a check crash the launcher
        res, msg = False, f"{type(e).__name__}: {e}"
    mark = {True: f"{GREEN}✔", None: f"{YEL}!", False: f"{RED}✘"}[res]
    print(f"\r  {mark}{RST} {label:<26}{GREY}{msg}{RST}\033[K")
    return res


def tcp_open(host: str, port: int, timeout: float = 4.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def find_ssh_ports(host: str) -> list[int]:
    found = []
    for p in (22, 2222, 2224, 2200, 22022, 222, 2022):
        try:
            with socket.create_connection((host, p), timeout=1.2) as s:
                s.settimeout(1.0)
                if s.recv(16).startswith(b"SSH-"):
                    found.append(p)
        except OSError:
            pass
    return found


def ensure_paramiko() -> tuple[bool | None, str]:
    try:
        import paramiko  # noqa: F401
        return True, "paramiko ready"
    except ImportError:
        pass
    print()
    if input(f"    {YEL}paramiko missing.{RST} Install it now? [Y/n]: ").strip().lower() in ("", "y", "yes"):
        r = subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "paramiko"])
        if r.returncode == 0:
            return True, "paramiko installed"
    return False, "paramiko missing  ->  pip install paramiko"


def preflight(cfg: dict) -> str:
    """Returns 'ok', 'warn', or a failure code: 'files', 'deps', 'tcp', 'auth', 'other'."""
    host, user, pw = cfg["SW_SSH_HOST"], cfg["SW_SSH_USER"], cfg.get("SW_SSH_PASSWORD", "")
    try:
        port = int(cfg["SW_SSH_PORT"])
    except ValueError:
        bad(f"Port '{cfg['SW_SSH_PORT']}' is not a number")
        return "tcp"
    ctx: dict = {}
    print(f"  {BOLD}{CYAN}PREFLIGHT{RST}")

    if not run_step("Scanner files", lambda: (
            Path("HARBNGR.py").exists(),
            "HARBNGR.py found" if Path("HARBNGR.py").exists()
            else f"HARBNGR.py not in {HERE}")):
        return "files"

    if not run_step("SSH library", ensure_paramiko):
        return "deps"

    def _reach():
        up = tcp_open(host, port)
        return up, ("port open" if up else "no response")

    if not run_step(f"Reach {host}:{port}", _reach):
        print()
        bad(f"Nothing answering on {host}:{port}")
        alt = find_ssh_ports(host)
        if alt:
            info(f"SSH IS listening on {CYAN}{', '.join(map(str, alt))}{RST} - use 'e' to change the port")
        else:
            info("Check: competition VPN connected? Right IP? WSL/port-forward running? Firewall?")
        print()
        return "tcp"

    def _login():
        import paramiko
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            c.connect(host, port=port, username=user, password=pw or None, timeout=8,
                      banner_timeout=8, auth_timeout=8, allow_agent=False, look_for_keys=not pw)
        except paramiko.AuthenticationException:
            return False, "wrong username or password"
        except Exception as e:
            return False, f"{type(e).__name__}: {str(e)[:60]}"
        ctx["client"] = c
        _, o, _ = c.exec_command("id -un", timeout=8)
        return True, f"logged in as {o.read().decode().strip()}"

    if not run_step("SSH login", _login):
        print()
        return "auth"

    def _sudo():
        c = ctx["client"]
        si, so, _ = c.exec_command("sudo -S -p '' id -un", timeout=10)
        si.write(pw + "\n")
        si.flush()
        out = so.read().decode().strip()
        if out == "root":
            return True, "root confirmed (can read /root/.ssh)"
        return None, "sudo failed - scan will be blind to /root (wrong pw / not sudoer?)"

    sudo_res = run_step("Root via sudo", _sudo)
    try:
        ctx["client"].close()
    except Exception:
        pass
    print()
    return "ok" if sudo_res else "warn"


# --------------------------------------------------------------------------- #
#  Launch
# --------------------------------------------------------------------------- #
def launch(cfg: dict, passthru: list[str]) -> int:
    # clear module manifest so edited modules don't trigger integrity locks
    try:
        (BUNKER / "module_manifest.json").unlink(missing_ok=True)
    except OSError:
        pass

    env = os.environ.copy()
    env.update({k: v for k, v in cfg.items() if v is not None})

    args = [sys.executable, "HARBNGR.py"]
    for flag, key in (("--host", "SW_SSH_HOST"), ("--port", "SW_SSH_PORT"), ("--user", "SW_SSH_USER")):
        if flag not in passthru and cfg.get(key):
            args += [flag, cfg[key]]
    if "--remote-bunker" not in passthru:  # avoids PermissionError on /var/bunker
        args += ["--remote-bunker", f"/home/{cfg.get('SW_SSH_USER', 'analyst')}/shadow-bunker"]
    args += passthru

    print(f"  {GREEN}▶ launching{RST}  {GREY}{' '.join(args[1:])}{RST}\n")
    try:
        return subprocess.run(args, env=env).returncode
    except KeyboardInterrupt:
        print(f"\n  {GREY}Shutting down.{RST}")
        return 0


# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #
def pop_flag(argv: list[str], *names: str) -> bool:
    hit = False
    for n in names:
        while n in argv:
            argv.remove(n)
            hit = True
    return hit


def pop_value(argv: list[str], name: str) -> str | None:
    if name in argv:
        i = argv.index(name)
        val = argv[i + 1] if i + 1 < len(argv) else None
        del argv[i:i + 2]
        return val
    return None


def main() -> int:
    enable_ansi()
    argv = sys.argv[1:]
    reset = pop_flag(argv, "--reset")
    edit = pop_flag(argv, "--edit")
    fast = pop_flag(argv, "--fast")
    yes = pop_flag(argv, "-y", "--yes")
    nocheck = pop_flag(argv, "--no-check")
    art = pop_value(argv, "--art")

    splash(fast or yes, art)

    if reset and ENV_FILE.exists():
        ENV_FILE.unlink()
        warn("Saved target removed.\n")

    handle_old_session(yes)

    cfg = load_env()
    if not cfg.get("SW_SSH_HOST") or edit:
        cfg = wizard(cfg)
    elif not yes:
        show_target(cfg)
        c = input(f"  {PURP}›{RST} {BOLD}ENTER{RST} launch  ·  {BOLD}e{RST} edit target  ·  "
                  f"{BOLD}q{RST} quit: ").strip().lower()
        print()
        if c == "q":
            return 0
        if c == "e":
            cfg = wizard(cfg)
    else:
        show_target(cfg)

    # preflight loop: fix problems here, not mid-scan
    while not nocheck:
        status = preflight(cfg)
        if status in ("ok",):
            break
        if status == "warn":
            if yes or input(f"  {PURP}›{RST} Launch anyway? [Y/n]: ").strip().lower() in ("", "y", "yes"):
                break
        options = f"{BOLD}r{RST} retry  ·  {BOLD}e{RST} edit target/password  ·  {BOLD}c{RST} continue anyway  ·  {BOLD}q{RST} quit"
        if yes and status in ("tcp", "auth"):
            bad("Preflight failed in -y mode. Run without -y to fix interactively.")
            return 1
        c = input(f"  {PURP}›{RST} {options}: ").strip().lower()
        print()
        if c == "q":
            return 1
        if c == "e":
            cfg = wizard(cfg)
        elif c == "c":
            break
        # anything else (incl. 'r' / ENTER) re-runs preflight

    return launch(cfg, argv)


if __name__ == "__main__":
    sys.exit(main())