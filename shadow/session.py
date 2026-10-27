"""Operator-side SSH session. Paramiko stays in this module.

One transport, keepalive on, a lock around every channel so the observation
loop and the human command loop do not use Paramiko at the same time.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shlex
import socket
import time
from pathlib import Path

from shadow.secrets import scrub

CONNECT_TIMEOUT = 8
ATTEMPTS = 5
BACKOFF_START = 1.0
BACKOFF_CAP = 16.0
SFTP_TIMEOUT = 30
EXEC_TIMEOUT = 25
KEEPALIVE_S = 15
COMMON_PORTS = (22, 2222, 2022, 80, 443, 8080, 8443, 53)
PYTHON_CANDIDATES = ("/usr/bin/python3", "/usr/local/bin/python3", "/bin/python3", "python3")

PREBOOT_FILES = (
    "shadow/__init__.py",
    "shadow/procparse.py",
    "shadow/collect.py",
)

_RUNNER = """
import base64, json, sys, types
req = json.loads(base64.b64decode(__BLOB__))
for name, src in req["modules"]:
    parts = name.split(".")
    if len(parts) == 1:
        mod = types.ModuleType(name)
        mod.__path__ = []
        sys.modules[name] = mod
    else:
        parent = sys.modules[".".join(parts[:-1])]
        mod = types.ModuleType(name)
        setattr(parent, parts[-1], mod)
        sys.modules[name] = mod
    mod.__name__ = name
    exec(compile(src, name + ".py", "exec"), mod.__dict__)
fn = getattr(sys.modules[req["module"]], req["fn"])
sys.stdout.write(json.dumps(fn(**req["kwargs"])))
"""


def build_embedded_script(root: Path, module: str, fn: str, kwargs: dict) -> str:
    """Stdin script that loads our collector without writing it to the node."""
    modules = []
    for rel in PREBOOT_FILES:
        name = "shadow" if rel.endswith("__init__.py") else rel[:-3].replace("/", ".")
        modules.append([name, (root / rel).read_text(encoding="utf-8")])
    payload = {"modules": modules, "module": module, "fn": fn, "kwargs": kwargs}
    blob = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    return _RUNNER.replace("__BLOB__", json.dumps(blob))


def tcp_probe(host: str, ports: tuple[int, ...] = COMMON_PORTS, timeout: float = 2.0) -> list[dict]:
    """Connect and close. No payload is sent."""
    results = []
    for port in ports:
        sock = socket.socket()
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            results.append({"port": port, "open": True})
        except OSError as exc:
            results.append({"port": port, "open": False, "error": exc.__class__.__name__})
        finally:
            sock.close()
    return results


class RemoteSession:
    def __init__(self, host: str, port: int, user: str, password: str | None,
                 key_path: str | None, jump: str | None = None, jump_port: int = 22,
                 jump_user: str | None = None, jump_password: str | None = None):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.key_path = key_path
        self.jump = jump or ""
        self.jump_port = jump_port
        self.jump_user = jump_user or user
        self.jump_password = jump_password
        self.python = ""
        self.shell = {}
        self.hostkey = ""
        self.client = None
        self.jump_client = None
        self._secrets = [password or "", jump_password or ""]
        import threading
        self._lock = threading.Lock()

    def connect(self) -> None:
        with self._lock:
            self._connect_retry_locked()

    def _connect_retry_locked(self) -> None:
        last = None
        delay = BACKOFF_START
        for attempt in range(1, ATTEMPTS + 1):
            try:
                self._connect_once()
                return
            except Exception as exc:
                last = exc
                self.close()
                if attempt == ATTEMPTS:
                    break
                time.sleep(delay)
                delay = min(delay * 2, BACKOFF_CAP)
        raise RuntimeError(self._scrub(str(last)))

    def close(self) -> None:
        for client in (self.client, self.jump_client):
            if client is not None:
                try:
                    client.close()
                except Exception:
                    pass
        self.client = None
        self.jump_client = None

    def alive(self) -> bool:
        if self.client is None:
            return False
        transport = self.client.get_transport()
        return bool(transport and transport.is_active())

    def ensure(self) -> None:
        with self._lock:
            if not self.alive():
                self._connect_retry_locked()

    def probe_shell(self) -> dict:
        """Find python and name the shell. Later commands use the absolute python path."""
        self.python = self._find_python()
        code = (
            "import json,os\n"
            "shell=os.environ.get('SHELL','')\n"
            "name=os.path.basename(shell) if shell else ''\n"
            "print(json.dumps({'shell': shell or 'unknown', 'name': name, "
            "'restricted_name': name in {'rbash','rksh'}}))\n"
        )
        result = self._exec_json([self.python, "-c", code], EXEC_TIMEOUT)
        self.shell = result
        return result

    def call_embedded(self, root: Path, module: str, fn: str, kwargs: dict, timeout: float = EXEC_TIMEOUT) -> dict:
        script = build_embedded_script(root, module, fn, kwargs)
        return self._python_stdin(script, timeout)

    def call_agent(self, remote_agent: str, args: list[str], timeout: float = EXEC_TIMEOUT) -> dict:
        return self._exec_json([self.python, remote_agent, *args], timeout)

    def disk_free_remote(self, path: str) -> dict:
        return self.call_embedded(self._root_for_embed(), "shadow.collect", "disk_free", {"path": path})

    def mkdir_p(self, remote_dir: str) -> None:
        with self._lock:
            sftp = self._sftp()
            try:
                current = ""
                for part in remote_dir.strip("/").split("/"):
                    current += "/" + part
                    try:
                        sftp.stat(current)
                    except IOError:
                        sftp.mkdir(current)
            finally:
                sftp.close()

    def put_atomic(self, local: Path, remote: str) -> None:
        """Upload to name.partial, then rename over the destination."""
        with self._lock:
            sftp = self._sftp()
            temporary = remote + ".partial"
            try:
                sftp.put(str(local), temporary)
                try:
                    sftp.posix_rename(temporary, remote)
                except IOError:
                    try:
                        sftp.remove(remote)
                    except IOError:
                        pass
                    sftp.rename(temporary, remote)
            finally:
                sftp.close()

    def _root_for_embed(self) -> Path:
        return Path(__file__).resolve().parent.parent

    def _connect_once(self) -> None:
        import paramiko
        self.close()
        pkey = _load_key(paramiko, self.key_path) if self.key_path else None
        jump_sock = None
        if self.jump:
            jump = paramiko.SSHClient()
            jump.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            jump_kwargs = {
                "hostname": self.jump,
                "port": self.jump_port,
                "username": self.jump_user,
                "timeout": CONNECT_TIMEOUT,
                "banner_timeout": CONNECT_TIMEOUT,
                "auth_timeout": CONNECT_TIMEOUT,
                "look_for_keys": False,
                "allow_agent": False,
            }
            if self.jump_password:
                jump_kwargs["password"] = self.jump_password
            elif pkey is not None:
                jump_kwargs["pkey"] = pkey
            jump.connect(**jump_kwargs)
            self.jump_client = jump
            jump_sock = jump.get_transport().open_channel(
                "direct-tcpip", (self.host, self.port), ("127.0.0.1", 0),
            )
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = {
            "hostname": self.host,
            "port": self.port,
            "username": self.user,
            "timeout": CONNECT_TIMEOUT,
            "banner_timeout": CONNECT_TIMEOUT,
            "auth_timeout": CONNECT_TIMEOUT,
            "look_for_keys": False,
            "allow_agent": False,
        }
        if jump_sock is not None:
            kwargs["sock"] = jump_sock
        if pkey is not None:
            kwargs["pkey"] = pkey
        else:
            kwargs["password"] = self.password
        client.connect(**kwargs)
        transport = client.get_transport()
        transport.set_keepalive(KEEPALIVE_S)
        key = transport.get_remote_server_key()
        self.hostkey = hashlib.sha256(key.asbytes()).hexdigest()
        self.client = client

    def _find_python(self) -> str:
        for candidate in PYTHON_CANDIDATES:
            try:
                result = self._exec_json(
                    [candidate, "-c", "import json,sys; print(json.dumps({'exe': sys.executable}))"],
                    10,
                )
            except Exception:
                continue
            exe = result.get("exe") or candidate
            return exe
        raise RuntimeError("python3 was not found on the node")

    def _sftp(self):
        sftp = self.client.open_sftp()
        sftp.get_channel().settimeout(SFTP_TIMEOUT)
        return sftp

    def _exec_json(self, argv: list[str], timeout: float) -> dict:
        code, out, err = self._exec(argv, timeout, stdin=None)
        text = out.decode("utf-8", "replace").strip()
        if not text:
            raise RuntimeError(self._scrub(err.decode("utf-8", "replace") or f"empty output, exit {code}"))
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(self._scrub(f"{exc}; stdout={text[:300]}; stderr={err[:300]!r}"))

    def _python_stdin(self, script: str, timeout: float) -> dict:
        code, out, err = self._exec([self.python, "-"], timeout, stdin=script.encode("utf-8"))
        text = out.decode("utf-8", "replace").strip()
        if not text:
            raise RuntimeError(self._scrub(err.decode("utf-8", "replace") or f"empty output, exit {code}"))
        return json.loads(text)

    def _exec(self, argv: list[str], timeout: float, stdin: bytes | None) -> tuple[int, bytes, bytes]:
        with self._lock:
            self.ensure_locked()
            transport = self.client.get_transport()
            channel = transport.open_session(timeout=timeout)
            channel.settimeout(1.0)
            command = " ".join(shlex.quote(part) for part in argv)
            channel.exec_command(command)
            if stdin:
                view = memoryview(stdin)
                while view:
                    sent = channel.send(view[:32768])
                    view = view[sent:]
                channel.shutdown_write()
            return _read_channel(channel, timeout)

    def ensure_locked(self) -> None:
        """Caller holds the lock. Reconnect with backoff if the transport died."""
        if not self.alive():
            self._connect_retry_locked()

    def _scrub(self, text: str) -> str:
        return scrub(text, self._secrets)


def _load_key(paramiko, path: str):
    errors = []
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return cls.from_private_key_file(path)
        except Exception as exc:
            errors.append(exc.__class__.__name__)
    raise RuntimeError("could not load the SSH key (" + ", ".join(errors) + ")")


def _read_channel(channel, timeout: float) -> tuple[int, bytes, bytes]:
    deadline = time.time() + timeout
    out = bytearray()
    err = bytearray()
    while True:
        if channel.recv_ready():
            out += channel.recv(65535)
        if channel.recv_stderr_ready():
            err += channel.recv_stderr(65535)
        if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
            break
        if time.time() > deadline:
            channel.close()
            raise TimeoutError("remote command timed out")
        time.sleep(0.02)
    code = channel.recv_exit_status()
    return code, bytes(out), bytes(err)
