#!/usr/bin/env python3
"""
HARBNGR launcher  -  one command, ready to scan.

    python start.py            normal: splash -> confirm target -> preflight -> launch
    python start.py -y         zero-prompt: use saved target, preflight, launch
    python start.py --edit     change target/credentials
    python start.py --reset    forget saved target and start the wizard
    python start.py --fast     skip the splash animation
    python start.py --no-check skip preflight (not recommended)
    python start.py --skip-integrity
                               delete bunker/module_manifest.json so INTEGRITY ACK does not fire
    python start.py --art NAME use art/NAME.txt as the splash (if it fits the window)
    python start.py --prepare  download dependency wheels to wheels/ for OFFLINE installs
    python start.py --no-venv  don't create/use .venv (use the current Python as-is)

First run builds .venv and installs requirements.txt automatically. If a wheels/ folder
exists it installs from there with no internet needed.

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

from shadow.grid import bunker_for, env_file_text, format_hosts_env, host_by_ip, parse_hosts, profile_for
from shadow.shellhist import apply_user_history

HERE = Path(__file__).resolve().parent
os.chdir(HERE)  # always run from the tool's folder, no matter where it was launched

ENV_FILE = Path(".env")
BUNKER = Path("bunker")
VENV = HERE / ".venv"
WHEELS = HERE / "wheels"
REQS = HERE / "requirements.txt"
ENV_KEYS = ("SW_SSH_HOST", "SW_SSH_PORT", "SW_SSH_USER", "SW_SSH_PASSWORD", "SW_SSH_JUMP", "SW_SSH_JUMP_PASSWORD", "SW_SSH_KEY", "SW_HOST_LABEL")


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


def ensure_gitignore() -> None:
    """Credentials live in .env: make sure git can never pick them up by accident."""
    gi = HERE / ".gitignore"
    wanted = [".env", ".env.*", "hosts.env", "bunker_backup_*/", "bunker-sentinel/", "bunker-edge/", "bunker-ops/", "merged-report.md", "wheels/"]
    try:
        have = gi.read_text(encoding="utf-8").splitlines() if gi.exists() else []
        missing = [w for w in wanted if w not in [h.strip() for h in have]]
        if missing:
            with open(gi, "a", encoding="utf-8", newline="") as f:
                if have and have[-1] != "":
                    f.write("\n")
                f.write("# added by start.py\n" + "\n".join(missing) + "\n")
            info(f".gitignore updated ({', '.join(missing)})")
    except OSError:
        pass


def save_env(cfg: dict) -> None:
    ensure_gitignore()
    ENV_FILE.write_text("".join(f"{k}={cfg.get(k, '')}\n" for k in ENV_KEYS), encoding="utf-8")
    try:
        os.chmod(ENV_FILE, 0o600)
    except OSError:
        pass


def wizard(cfg: dict) -> dict:
    print(f"  {BOLD}{CYAN}TARGET SETUP{RST}  {GREY}(ENTER keeps the value in brackets){RST}\n")
    cfg["SW_SSH_HOST"] = ask("Target IP / hostname", cfg.get("SW_SSH_HOST", "10.80.40.11"))
    cfg["SW_SSH_PORT"] = ask("SSH port", cfg.get("SW_SSH_PORT", "22"))
    cfg["SW_SSH_USER"] = ask("SSH username", cfg.get("SW_SSH_USER", "operator"))
    known = host_by_ip(cfg["SW_SSH_HOST"])
    if known:
        cfg["SW_HOST_LABEL"] = known["label"]
        info(f"Label {known['label']} ({known['name']}). WireGuard path, no jump host.")
    else:
        cfg["SW_HOST_LABEL"] = ask("Host label (sentinel, edge, ops)", cfg.get("SW_HOST_LABEL", ""))
    cfg["SW_SSH_JUMP"] = ""
    cfg["SW_SSH_JUMP_PASSWORD"] = ""
    old_pw = cfg.get("SW_SSH_PASSWORD", "")
    pw = ask("Password (hidden, ENTER keeps saved)" if old_pw else "Password (hidden)", secret=True)
    cfg["SW_SSH_PASSWORD"] = pw or old_pw
    save_env(cfg)
    print()
    ok("Saved to .env  " + GREY + "(local only - never commit this file)" + RST)
    return cfg


def preflight_hosts(saved: dict, assume_yes: bool) -> dict | None:
    """Check SSH and sudo on every hosts.txt entry. Save hosts.env and .env.<label>."""
    path = HERE / "hosts.txt"
    if not path.is_file():
        return None
    try:
        hosts = parse_hosts(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        bad(str(exc))
        return None
    if not hosts:
        return None
    print(f"  {BOLD}IN-SCOPE HOSTS{RST}  {GREY}Bits_N_Bytes, WireGuard, no jump host{RST}")
    for host in hosts:
        print(f"    {host['label']:<10} {host['user']}@{host['ip']}:{host['port']}")
    print()
    if not assume_yes:
        answer = input(f"  {PURP}›{RST} Preflight all of these before launch? [Y/n]: ").strip().lower()
        if answer in ("n", "no"):
            return None
    password = saved.get("SW_SSH_PASSWORD", "")
    if not password:
        password = ask("SSH password for operator (hidden, used for every host)", secret=True)
    if not password:
        bad("No password. SSH login and sudo cannot be checked.")
        return None
    rows = []
    for host in hosts:
        cfg = {
            "SW_SSH_HOST": host["ip"],
            "SW_SSH_PORT": str(host["port"]),
            "SW_SSH_USER": host["user"],
            "SW_SSH_PASSWORD": password,
            "SW_HOST_LABEL": host["label"],
            "SW_SSH_JUMP": "",
        }
        info(f"Preflight {host['label']} {host['ip']}")
        status = preflight(cfg)
        rows.append((host, status))
    failed = [host["label"] for host, status in rows if status not in ("ok", "warn")]
    print(f"  {BOLD}PREFLIGHT{RST}")
    for host, status in rows:
        mark = "ok" if status in ("ok", "warn") else status
        print(f"    {host['label']:<10} {mark}")
    print()
    text = format_hosts_env(hosts, password)
    (HERE / "hosts.env").write_text(text, encoding="utf-8")
    for host in hosts:
        (HERE / f".env.{host['label']}").write_text(env_file_text(host, password), encoding="utf-8")
    ensure_gitignore()
    ok("Saved hosts.env and .env.<label> for each host (local only).")
    if failed:
        bad("Not ready: " + ", ".join(failed))
        if assume_yes:
            return None
        if input(f"  {PURP}›{RST} Continue anyway? [y/N]: ").strip().lower() not in ("y", "yes"):
            return None
    chosen = None
    if assume_yes:
        chosen = hosts[0]
    else:
        raw = input(f"  {PURP}›{RST} Launch which label? [sentinel]: ").strip().lower() or "sentinel"
        for host in hosts:
            if host["label"] == raw:
                chosen = host
                break
        if chosen is None:
            bad(f"Unknown label {raw}")
            return None
    cfg = dict(saved)
    cfg.update({
        "SW_SSH_HOST": chosen["ip"],
        "SW_SSH_PORT": str(chosen["port"]),
        "SW_SSH_USER": chosen["user"],
        "SW_SSH_PASSWORD": password,
        "SW_HOST_LABEL": chosen["label"],
        "SW_SSH_JUMP": "",
        "SW_SSH_JUMP_PASSWORD": "",
    })
    save_env(cfg)
    return cfg


def show_target(cfg: dict) -> None:
    pw = "●" * min(len(cfg.get("SW_SSH_PASSWORD", "")), 8) or "(none)"
    extra = ""
    if cfg.get("SW_HOST_LABEL"):
        extra += f"   {GREY}label {cfg['SW_HOST_LABEL']}{RST}"
    if cfg.get("SW_SSH_JUMP"):
        extra += f"   {GREY}via {cfg['SW_SSH_JUMP']}{RST}"
    if cfg.get("SW_SSH_KEY"):
        extra += f"   {GREY}key {Path(cfg['SW_SSH_KEY']).name}{RST}"
    print(f"  {BOLD}TARGET{RST}  {CYAN}{cfg.get('SW_SSH_USER')}{RST}{GREY}@{RST}"
          f"{CYAN}{cfg.get('SW_SSH_HOST')}{RST}{GREY}:{RST}{CYAN}{cfg.get('SW_SSH_PORT')}{RST}"
          f"   {GREY}pw {pw}{RST}{extra}\n")


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
    jump, keyfile = cfg.get("SW_SSH_JUMP", ""), cfg.get("SW_SSH_KEY", "")
    ctx: dict = {}
    print(f"  {BOLD}{CYAN}PREFLIGHT{RST}")

    if not run_step("Scanner files", lambda: (
            Path("HARBNGR.py").exists(),
            "HARBNGR.py found" if Path("HARBNGR.py").exists()
            else f"HARBNGR.py not in {HERE}")):
        return "files"

    if not run_step("SSH library", ensure_paramiko):
        return "deps"

    if jump:
        info(f"Jump host {CYAN}{jump}{RST} configured - network/login are checked by HARBNGR at connect.\n")
        return "ok"

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
            if host in ("127.0.0.1", "localhost", "::1"):
                info(f"Practice lab not running? Start it:  powershell -ExecutionPolicy Bypass -File \"{HERE / 'lab' / 'setup.ps1'}\"   (or: bash \"{HERE / 'lab' / 'setup.sh'}\")")
            info("Check: competition VPN connected? Right IP? WSL/port-forward running? Firewall?")
        print()
        return "tcp"

    def _login():
        import paramiko
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            c.connect(host, port=port, username=user, password=pw or None, key_filename=keyfile or None, timeout=8,
                      banner_timeout=8, auth_timeout=8, allow_agent=False, look_for_keys=not pw and not keyfile)
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
def launch(cfg: dict, passthru: list[str], skip_integrity: bool = False) -> int:
    # Keep bunker/module_manifest.json so HARBNGR can ask for INTEGRITY ACK.
    # --skip-integrity is the only way to drop it.
    if skip_integrity:
        try:
            (BUNKER / "module_manifest.json").unlink(missing_ok=True)
        except OSError:
            pass

    env = os.environ.copy()
    env.update({k: v for k, v in cfg.items() if v})

    args = [sys.executable, "HARBNGR.py"]
    for flag, key in (("--host", "SW_SSH_HOST"), ("--port", "SW_SSH_PORT"), ("--user", "SW_SSH_USER")):
        if flag not in passthru and cfg.get(key):
            args += [flag, cfg[key]]
    if cfg.get("SW_SSH_JUMP") and "--jump" not in passthru:
        args += ["--jump", cfg["SW_SSH_JUMP"]]
    label = cfg.get("SW_HOST_LABEL") or ""
    if label and "--host-label" not in passthru:
        args += ["--host-label", label]
    if "--local-bunker" not in passthru:
        args += ["--local-bunker", bunker_for(label) or "bunker"]
    if label and "--profile" not in passthru and profile_for(label):
        args += ["--profile", profile_for(label)]
    args += passthru

    print(f"  {GREEN}▶ launching{RST}  {GREY}{' '.join(args[1:])}{RST}\n")
    try:
        return subprocess.run(args, env=env).returncode
    except KeyboardInterrupt:
        print(f"\n  {GREY}Shutting down.{RST}")
        return 0


# --------------------------------------------------------------------------- #
#  First-run bootstrap: .venv + dependencies (online or from wheels/)
# --------------------------------------------------------------------------- #
def venv_python() -> Path:
    return VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def in_venv() -> bool:
    return sys.prefix != getattr(sys, "base_prefix", sys.prefix)


def pip_install_cmd(py: str) -> list[str]:
    cmd = [py, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", "--retries", "1", "--timeout", "8"]
    if WHEELS.exists() and any(WHEELS.iterdir()):
        cmd += ["--no-index", "--find-links", str(WHEELS)]
    cmd += ["-r", str(REQS)] if REQS.exists() else ["paramiko"]
    return cmd


def prepare_offline() -> int:
    """Run on a machine WITH internet; wheels are OS/Python-version specific."""
    WHEELS.mkdir(exist_ok=True)
    cmd = [sys.executable, "-m", "pip", "download", "--disable-pip-version-check", "-d", str(WHEELS)]
    cmd += ["-r", str(REQS)] if REQS.exists() else ["paramiko"]
    info("Downloading dependency wheels to wheels/ ...")
    rc = subprocess.run(cmd).returncode
    if rc == 0:
        ok(f"Done. Ship the whole folder; installs now work offline on the same OS + Python {sys.version_info.major}.{sys.version_info.minor}.")
    else:
        bad("Download failed - are you online?")
    return rc


def bootstrap() -> int | None:
    """Make sure we're running inside .venv with deps installed.
    Returns an exit code if the launcher re-ran itself inside the venv,
    or None to carry on in the current interpreter."""
    if in_venv():
        return None
    py = venv_python()
    if not py.exists():
        info("First run: building private environment (.venv) ...")
        r = subprocess.run([sys.executable, "-m", "venv", str(VENV)])
        if r.returncode != 0 or not py.exists():
            warn("Could not create .venv (Linux: apt install python3-venv). Using system Python instead.")
            return None
    if subprocess.run([str(py), "-c", "import paramiko"], capture_output=True).returncode != 0:
        src = "wheels/ (offline)" if WHEELS.exists() and any(WHEELS.iterdir()) else "the internet"
        info(f"Installing dependencies from {src} ...")
        if subprocess.run(pip_install_cmd(str(py))).returncode != 0:
            bad("Dependency install failed.")
            info("No internet? On a connected machine run:  python start.py --prepare   then copy the folder over.")
            return None
        ok("Dependencies ready.\n")
    try:
        return subprocess.run([str(py), str(Path(__file__).resolve()), *sys.argv[1:]]).returncode
    except KeyboardInterrupt:
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


def _ensure_bash_history() -> None:
    """Persist a large timestamped bash history for this user. Quiet when already set."""
    try:
        path, changes = apply_user_history()
    except OSError as exc:
        warn(f"Could not update bash history config: {exc}")
        return
    if not changes:
        return
    ok(f"Bash history updated in {path}")
    for item in changes:
        info(item)
    info(f'Apply it in an open Git Bash window:  source "{path}"')


def main() -> int:
    enable_ansi()
    if sys.version_info < (3, 10):
        bad(f"Python 3.10+ required (this is {sys.version.split()[0]}). Install from python.org and re-run.")
        return 1
    _ensure_bash_history()
    argv = sys.argv[1:]
    if "--prepare" in argv:
        return prepare_offline()
    if not pop_flag(argv, "--no-venv"):
        rc = bootstrap()
        if rc is not None:
            return rc
    else:
        sys.argv = [a for a in sys.argv if a != "--no-venv"]
    reset = pop_flag(argv, "--reset")
    edit = pop_flag(argv, "--edit")
    fast = pop_flag(argv, "--fast")
    yes = pop_flag(argv, "-y", "--yes")
    nocheck = pop_flag(argv, "--no-check")
    skip_integrity = pop_flag(argv, "--skip-integrity")
    art = pop_value(argv, "--art")

    splash(fast or yes, art)

    if reset and ENV_FILE.exists():
        ENV_FILE.unlink()
        warn("Saved target removed.\n")

    handle_old_session(yes)

    cfg = load_env()
    if not edit and (HERE / "hosts.txt").is_file():
        picked = preflight_hosts(cfg, yes)
        if picked is None and yes:
            bad("Host preflight did not pass.")
            return 1
        if picked is not None:
            cfg = picked
            edit = False
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

    return launch(cfg, argv, skip_integrity=skip_integrity)


if __name__ == "__main__":
    sys.exit(main())
