"""Human-gated phases. Observation runs in the background and does not own the keyboard."""

from __future__ import annotations

import os
import json
import shutil
import threading
import time
import uuid
import paramiko
from pathlib import Path

from shadow.access import close_paths
from shadow.auditlog import AuditLog
from shadow.bootstrap import needed_bytes, plan_uploads, remote_join
from shadow.budget import format_alert, nudge_for, remaining
from shadow.containment import suggest, touches_protected, validate_exec
from shadow.engine import fresh_watch, ingest, run_classification
from shadow.fingerprint import load_profile, score_host
from shadow.integrity import compare, local_manifest, upload_relpaths
from shadow.session import RemoteSession, tcp_probe
from shadow.timeutil import stamp
from shadow.grid import host_by_label
from shadow.scope import sentinel_findings
from shadow.timeline import availability, phase_event, render_writeup
from shadow.topology import adjacency_list, write_outputs

# ANSI Color Codes for terminal readability
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

HELP = """
status (s)          timer, phase, availability
alerts (a)          highest impact first
topo (t)            adjacency list
flows (f)           phase 3, classifies outbound flows
contain (c)         phase 4 suggestions, does not execute
do <id>             asks YES, then runs one allowlisted action
phase <name>        log a competition-phase divider
restore (r)         copy modules to the bunker again
writeup (w)         phase 5 markdown
hunt <args> (h)     search snapshots (e.g., hunt --regex "flag{.*}" --scope environ)
scan (x)            dashboard view of potential IOCs, processes, IPs, and timers
mute (m)            toggle background logs on/off (still writes to events.log)
quit (q)            save and close
""".strip()


class Operator:
    def __init__(self, root: Path, local_bunker: Path, remote_bunker: str, interval: float,
                 profile_path: Path, ioc_path: Path, session: RemoteSession | None,
                 host_label: str = ""):
        self.root = root
        self.local = local_bunker
        self.remote_bunker = remote_bunker.rstrip("/")
        self.host_label = host_label or ""
        self.interval = min(5.0, max(2.0, interval))
        self.profile = load_profile(_read_json(profile_path))
        self.iocs = _load_iocs(ioc_path)
        self.session = session
        self.local.mkdir(parents=True, exist_ok=True)
        (self.local / "snapshots").mkdir(exist_ok=True)
        (self.local / "pre-action").mkdir(exist_ok=True)
        self.audit = AuditLog(self.local / "audit.jsonl")
        self.manifest = local_manifest(root)
        self.watch = fresh_watch()
        self.state = _fresh_state(remote_bunker, str(local_bunker), self.interval)
        self.remote_agent = remote_join(self.remote_bunker, "shadow/node_agent.py")
        self._stop = threading.Event()
        self._thread = None
        self._print_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._accepted_remote: dict[str, str] = {}

    def run(self) -> int:
        self._integrity_at_start()
        resumed = self._maybe_resume()
        if self.session is None:
            return 1
        try:
            self._connect()
        except Exception as exc:
            self._say(f"SSH failed: {exc}")
            self._say("TCP probe (connect and close, no payload):")
            for row in tcp_probe(self.session.host):
                self._say(f"  port {row['port']}: {'open' if row['open'] else 'closed'} {row.get('error', '')}")
            self.audit.append("command", "ssh failed", {"error": str(exc)})
            return 1
        self._say(f"host key sha256 {self.session.hostkey}")
        self.audit.append("command", "ssh connected", {"host": self.session.host, "hostkey": self.session.hostkey})
        try:
            shell = self.session.probe_shell()
        except Exception as exc:
            self._say(f"python probe failed: {exc}")
            return 1
        self.state["shell"] = shell
        self.state["python_path"] = self.session.python
        self._say(f"shell {shell.get('name') or 'unknown'} python {self.session.python}")
        if shell.get("restricted_name"):
            self._say("restricted shell name; later commands use the absolute python path")
        fingerprint = self._fingerprint()
        self.state["fingerprint"] = fingerprint
        if fingerprint.get("label") != "accept":
            self._say(f"{fingerprint.get('report')} score={fingerprint.get('score')}. Stopped.")
            self._say("Hostname was not used. Edit profiles/sentinel01.json only if this is the right node.")
            for reason in fingerprint.get("reasons") or []:
                self._say(f"  {reason}")
            self._save_state()
            self.session.close()
            return 2
        self.state["pipeline"] = fingerprint.get("pipeline") or {}
        for reason in fingerprint.get("reasons") or []:
            self._say(f"  {reason}")
        self._event(f"fingerprint accept score={fingerprint.get('score')}", "land")
        if not resumed or self.state.get("phase") == "land":
            if not self._bootstrap():
                return 1
            self._say("Bootstrap copied modules and exited. Nothing else is running.")
            self._say("Review the bunker copy. The evidence timer is not started yet.")
            self._say("It starts at the Phase 2 baseline, not at connect. Do not linger.")
            self._say("Landing budget is 15:00 including this review.")
            input("Press enter to start Phase 2: ")
            self._enter_observe()
        else:
            self._say(f"resumed at phase {self.state.get('phase')}")
            self._rebuild_watch()
        self._start_observe()
        try:
            self._command_loop()
        except KeyboardInterrupt:
            self._say("interrupted")
        finally:
            self._stop.set()
            if self._thread:
                self._thread.join(timeout=5)
            self._save_state()
            if self.session:
                self.session.close()
        return 0

    def _connect(self) -> None:
        assert self.session is not None
        self.state["phase_started_unix"]["land"] = time.time()
        self.session.connect()

    def _maybe_resume(self) -> bool:
        path = self.local / "session_state.json"
        if not path.is_file():
            return False
        answer = input("Saved session found. Type YES to resume it: ").strip()
        if answer != "YES":
            self.state["session_id"] = uuid.uuid4().hex[:12]
            return False
        self.state.update(json.loads(path.read_text(encoding="utf-8")))
        self.audit.append("decision", "resumed session", {"session_id": self.state.get("session_id")})
        return True

    def _integrity_at_start(self) -> None:
        path = self.local / "module_manifest.json"
        if not path.is_file():
            _write_json(path, self.manifest)
            return
        previous = json.loads(path.read_text(encoding="utf-8"))
        changed = compare(previous, self.manifest)
        if not changed:
            return
        self._say("local modules differ from the last manifest: " + ", ".join(changed))
        if input("Type INTEGRITY ACK to continue: ").strip() != "INTEGRITY ACK":
            raise SystemExit(2)
        self.audit.append("decision", "integrity ack at start", {"changed": changed})
        _write_json(path, self.manifest)

    def _fingerprint(self) -> dict:
        assert self.session is not None
        pipes = ", ".join(self.profile.get("pipeline_substrings") or [])
        tracks = ", ".join(self.profile.get("track_path_substrings") or [])
        self._say(
            f"fingerprint substrings pipeline=[{pipes}] track=[{tracks}] "
            f"accept={self.profile.get('accept_score')}"
        )
        raw = self.session.call_embedded(
            self.root, "shadow.collect", "build_snapshot", {"operator_unix": time.time()},
        )
        self._say(
            f"collected hostname {raw.get('hostname_ignored') or 'unknown'} "
            f"is not used in the score; ssh target {self.session.host}:{self.session.port}"
        )
        raw["role"] = "fingerprint"
        raw["taken_at"] = stamp()
        raw["session_id"] = self.state["session_id"]
        path = self._save_json(self.local / "snapshots" / f"fingerprint-{_file_stamp()}.json", raw)
        self._evidence("snapshot", str(path), "phase 1 fingerprint, before any eradication")
        self.audit.append("snapshot", "fingerprint", {"path": str(path)})
        return score_host(raw, self.profile)

    def _bootstrap(self) -> bool:
        assert self.session is not None
        rels = upload_relpaths(self.manifest)
        local_hashes = {rel: self.manifest[rel] for rel in rels}
        remote_paths = [remote_join(self.remote_bunker, rel) for rel in rels]
        try:
            free = self.session.call_embedded(
                self.root, "shadow.collect", "disk_free", {"path": self.remote_bunker},
            )
            hashed = self.session.call_embedded(
                self.root, "shadow.collect", "hash_files", {"paths": remote_paths},
            )
        except Exception as exc:
            self._say(f"remote pre-check failed: {exc}")
            return False
        remote_by_rel = {}
        for rel, remote in zip(rels, remote_paths):
            remote_by_rel[rel] = (hashed.get("hashes") or {}).get(remote, "")
        todo = plan_uploads(local_hashes, remote_by_rel)
        need = needed_bytes([self.root / rel for rel in todo]) if todo else 0
        if need and int(free.get("free") or 0) < need:
            self._say(f"not enough free space on {free.get('path')}: {free.get('free')} bytes free, need {need}")
            return False
        self.session.mkdir_p(self.remote_bunker)
        for rel in todo:
            remote = remote_join(self.remote_bunker, rel)
            self.session.mkdir_p(remote.rsplit("/", 1)[0])
            self.session.put_atomic(self.root / rel, remote)
            self.audit.append("command", "upload", {"rel": rel})
        checked = self._remote_hashes(rels)
        if checked is None:
            return False
        bad = [rel for rel in rels if checked.get(rel) != local_hashes[rel]]
        if bad:
            self._say("remote hash mismatch after copy: " + ", ".join(bad))
            return False
        self._accepted_remote = dict(local_hashes)
        self._event("modules copied to bunker; bootstrap exited without starting collectors", "land")
        self._save_state()
        return True

    def _remote_hashes(self, rels: list[str]) -> dict[str, str] | None:
        assert self.session is not None
        paths = [remote_join(self.remote_bunker, rel) for rel in rels]
        try:
            result = self.session.call_agent(self.remote_agent, ["hashes", "--files", *paths])
        except Exception as exc:
            self._say(f"remote hash check failed: {exc}")
            return None
        found = result.get("hashes") or {}
        return {rel: found.get(remote, "") for rel, remote in zip(rels, paths)}

    def _enter_observe(self) -> None:
        text = nudge_for("land", self.state["phase_started_unix"].get("land"), time.time())
        if text:
            self._say(text)
            self.state["nudged"].append("land")
        self.state["phase"] = "observe"
        self.state["phase_started_unix"]["observe"] = time.time()
        self._event("phase 2 started", "phase")
        self._save_state()

    def _start_observe(self) -> None:
        self._thread = threading.Thread(target=self._observe, name="shadow-observe", daemon=True)
        self._thread.start()

    def _observe(self) -> None:
        while not self._stop.is_set():
            started = time.time()
            try:
                snap = self._take_snapshot()
                self._ingest(snap, quiet=False)
            except Exception as exc:
                self._say(f"observe error: {exc}")
                self.audit.append("command", "observe error", {"error": str(exc)})
                try:
                    assert self.session is not None
                    self.session.ensure()
                    self._event("session reconnected", "session")
                except Exception as again:
                    self._say(f"reconnect failed: {again}")
            self._nudge()
            self._stop.wait(max(0.2, self.interval - (time.time() - started)))

    def _take_snapshot(self) -> dict:
        assert self.session is not None
        self._local_space()
        raw = self.session.call_agent(
            self.remote_agent, ["snapshot", "--operator-unix", str(time.time())],
        )
        if raw.get("ok") is False:
            raise RuntimeError(raw.get("error") or "snapshot failed")
        raw["role"] = "observe"
        raw["taken_at"] = stamp()
        raw["session_id"] = self.state["session_id"]
        return raw

    def _ingest(self, snap: dict, quiet: bool) -> None:
        path = self._save_json(self.local / "snapshots" / f"{_file_stamp()}.json", snap)
        first = self.watch.get("baseline") is None
        result = ingest(self.watch, snap, snap["taken_at"])
        topo = write_outputs(self.watch["graph"], self.local / "topology")
        
        speeches = []
        with self._state_lock:
            self.state["topology_written"] = True
            self.state["access_paths"] = self.watch["access_paths"]
            self.state["operator_snapshots"] = len(list((self.local / "snapshots").glob("*.json")))
            if first and not self.state.get("baseline_ts"):
                self.state["baseline_ts"] = snap["taken_at"]
                self.state["baseline_unix"] = snap.get("operator_unix")
                speeches.append(("baseline snapshot recorded; 45-minute evidence timer started", "snapshot", False, True))
            alerts = self.state.setdefault("alerts", [])
            for item in result["alerts"]:
                alerts.append(item)
                summary = item["summary"]
                is_spam = "new tcp" in summary.lower() or "time_wait" in summary.lower()
                speeches.append((summary, "alert", not is_spam, is_spam))
            del alerts[:-200]
            for line in result["edges"]:
                speeches.append((line, "topology", False, True))
                
        note = "baseline" if first else "observation pass"
        self._evidence("snapshot", str(path), note)
        self.audit.append("snapshot", note, {"path": str(path)})
        
        if not quiet:
            for text, kind, is_alert, is_routine in speeches:
                self._event(text, kind)
                self._say(text, alert=is_alert, routine=is_routine)
            if topo.get("dot"):
                self._say(f"graphviz {topo['dot']}", routine=True)
        self._save_state()

    def _rebuild_watch(self) -> None:
        for snap in _load_observe_snapshots(self.local / "snapshots", self.state["session_id"]):
            ingest(self.watch, snap, snap.get("taken_at") or stamp())
        write_outputs(self.watch["graph"], self.local / "topology")
        self.state["topology_written"] = True
        if self.state.get("flows_ran") and self.watch.get("history"):
            result = run_classification(
                self.watch["history"], self.state.get("pipeline"), self.iocs, self.profile,
            )
            self.state["classification"] = result
            self.state["protected"] = result["protected"]
            self.state["mission_unclear"] = result["mission_unclear"]
            self.state["classify_note"] = result["note"]

    def _command_loop(self) -> None:
        with self._print_lock:
            print(f"\n{CYAN}{HELP}{RESET}\n", flush=True)
        while not self._stop.is_set():
            try:
                line = input(f"{CYAN}shadow>{RESET} ").strip()
            except EOFError:
                break
            if not line:
                continue
            self.audit.append("command", line, {})
            if not self._dispatch(line):
                break

    def _dispatch(self, line: str) -> bool:
        if line in ("help", "h", "?"):
            with self._print_lock:
                print(f"\n{CYAN}{HELP}{RESET}\n", flush=True)
        elif line in ("status", "s"):
            self._status()
        elif line in ("alerts", "a"):
            self._print_alerts()
        elif line in ("topo", "t"):
            self._say(adjacency_list(self.watch.get("graph") or {}))
        elif line in ("flows", "f"):
            self._flows()
        elif line in ("contain", "c"):
            self._contain()
        elif line.startswith("do "):
            self._do(line.split(None, 1)[1].strip())
        elif line.startswith("phase "):
            self._comp_phase(line.split(None, 1)[1].strip())
        elif line in ("restore", "r"):
            self._bootstrap()
        elif line in ("writeup", "w"):
            self._writeup()
        elif line.startswith("hunt ") or line.startswith("hu "):
            cmd_len = 5 if line.startswith("hunt ") else 3
            self._hunt(line[cmd_len:].strip())
        elif line in ("scan", "x"):
            self._scan()
        elif line in ("mute", "m"):
            is_muted = self.state.get("muted", False)
            self.state["muted"] = not is_muted
            self._say(f"Quiet mode {'ON' if not is_muted else 'OFF'}. Routine network logs hidden.")
            self.state["spam_count"] = 0 
        elif line in ("quit", "q"):
            return False
        else:
            self._say("unknown command. Type help or ?")
        return True

    def _scan(self) -> None:
        latest = (self.watch.get("history") or [None])[-1]
        if not latest:
            self._say("No snapshots available to scan.")
            return
            
        if self.watch.get("history"):
            classification = run_classification(
                self.watch["history"], self.state.get("pipeline"), self.iocs, self.profile,
            )
            self.state["classification"] = classification
            self.state["flows_ran"] = True

        # =========================================================================
        # THE SESSION HIJACK BYPASS (Independent SSH Path Check)
        # Separates root and home lookups to prevent wildcard/path dropouts.
        # =========================================================================
        import os, shlex, re
        pwd = os.environ.get("SW_SSH_PASSWORD", "")
        if not pwd:
            for _attr in ("password", "passwd", "pwd", "_password"):
                _v = getattr(self.session, _attr, None)
                if isinstance(_v, str) and _v:
                    pwd = _v
                    break
        if not pwd:
            if getattr(self, "_cached_sudo_pwd", None) is None:
                import getpass
                try:
                    self._cached_sudo_pwd = getpass.getpass("sudo password for remote host (needed to read /root/.ssh): ")
                except Exception:
                    self._cached_sudo_pwd = ""
            pwd = self._cached_sudo_pwd
        safe_pwd = shlex.quote(pwd)
        
        sudo_prefix = f"echo {safe_pwd} | sudo -S -p '' " if pwd else ""
        
        find_out = ""
        keys_out = ""
        hijack_err = ""
        
        try:
            ssh_client = None
            if hasattr(self.session, "exec_command") and callable(getattr(self.session, "exec_command")):
                ssh_client = self.session
            else:
                for attr_name in dir(self.session):
                    attr_val = getattr(self.session, attr_name)
                    if hasattr(attr_val, "exec_command") and callable(getattr(attr_val, "exec_command")):
                        ssh_client = attr_val
                        break
                        
            if ssh_client:
                # payload: find footholds + split + explicit root and home .ssh listing
                cmd = f"{sudo_prefix}sh -c 'find /usr/local/sbin /opt /srv /tmp /dev/shm /etc/systemd/system -type f 2>/dev/null; echo \":::SPLIT:::\"; ls -la /root/.ssh 2>/dev/null; ls -la /home/*/.ssh 2>/dev/null'"
                _, stdout, _ = ssh_client.exec_command(cmd)
                raw_out = stdout.read().decode("utf-8", errors="ignore").strip()
                
                if ":::SPLIT:::" in raw_out:
                    parts = raw_out.split(":::SPLIT:::")
                    find_out = parts[0].strip()
                    keys_out = parts[1].strip() if len(parts) > 1 else ""
                else:
                    find_out = raw_out 
            else:
                hijack_err = "Could not locate active SSH client in session object."
                
        except Exception as e:
            hijack_err = f"Hijack execution failed: {e}"

        # ---- Dedicated SSH key collection (separate exec so errors are visible) ----
        key_entries = []   # list of (path, meta, [fingerprint lines])
        key_err = ""
        key_user = "?"
        try:
            if ssh_client:
                key_script = (
                    'for d in /root/.ssh /home/*/.ssh; do '
                    '[ -d "$d" ] || continue; '
                    'for f in "$d"/*; do '
                    '[ -f "$f" ] || continue; '
                    'echo ":::FILE:::$f|$(stat -c "%A %U %s bytes" "$f")"; '
                    'case "$f" in *known_hosts*|*config) continue;; esac; '
                    'ssh-keygen -lf "$f" </dev/null 2>&1; '
                    'done; done'
                )
                key_script = 'echo ":::WHOAMI:::$(id -un)"; ' + key_script
                key_cmd = f"{sudo_prefix}sh -c {shlex.quote(key_script)}"
                _, k_out, k_err = ssh_client.exec_command(key_cmd, timeout=20)
                k_text = k_out.read().decode("utf-8", errors="ignore")
                k_etxt = k_err.read().decode("utf-8", errors="ignore").strip()
                if "a password is required" in k_etxt or "incorrect password" in k_etxt:
                    key_err = "sudo failed (is SW_SSH_PASSWORD set in the shell running the scanner?)"
                elif k_etxt and not k_text.strip():
                    key_err = k_etxt.splitlines()[-1][:120]
                cur = None
                for ln in k_text.splitlines():
                    ln = ln.rstrip()
                    if ln.startswith(":::WHOAMI:::"):
                        key_user = ln[len(":::WHOAMI:::"):]
                    elif ln.startswith(":::FILE:::"):
                        path, _, meta = ln[len(":::FILE:::"):].partition("|")
                        cur = (path, meta, [])
                        key_entries.append(cur)
                    elif ln and cur is not None:
                        cur[2].append(ln)
        except Exception as e:
            key_err = f"key listing failed: {e}"

        with self._print_lock:
            print(f"\n{MAGENTA}=== HARBNGR IOC SCANNER ==={RESET}")

            # 1. Open Listening Ports
            print(f"\n{CYAN}[*] OPEN LISTENING PORTS:{RESET}")
            listen = [s for s in latest.get("sockets", []) if s.get("state") == "LISTEN"]
            if not listen:
                print("  None detected.")
            for s in listen[:15]:
                print(f"  {YELLOW}{s.get('proto')}{RESET} {s.get('local')}")

            # 2. Anomalous Processes
            print(f"\n{CYAN}[*] POTENTIAL MALICIOUS PROCESSES (Live Memory Execution):{RESET}")
            
            sus_keywords = ["wipe", "shadow", "miner", "nc ", "ncat", "pwn", "c2", "beacon", "sw-respawn", "sw-wipe", "sw-", "guard"]
            sus_paths = ["/tmp/", "/dev/shm/", "/var/tmp/", "/home/", "/opt/", "/srv/", "/usr/local/sbin/"]
            
            procs = []
            for p in latest.get("processes", []):
                cmd = p.get("cmdline", "").lower()
                exe = p.get("exe", "").lower()
                if "shadow-watch" in cmd or "harbngr" in cmd or "node_agent.py" in cmd:
                    continue
                if p.get("standout"):
                    procs.append(p)
                elif any(k in cmd for k in sus_keywords) or any(path in exe for path in sus_paths):
                    procs.append(p)

            unique_procs = {p["pid"]: p for p in procs}.values()
            for p in list(unique_procs)[:15]:
                print(f"  {RED}PID:{p.get('pid')}{RESET} | {YELLOW}{p.get('comm')}{RESET} | {p.get('cmdline')[:80]}")
                
            if not unique_procs:
                print("  None detected.")

            # 3. Active Directory Scrub
            print(f"\n{CYAN}[*] ACTIVE ROOT DIRECTORY SCRUB (Hunting dormant payloads on disk):{RESET}")
            if hijack_err:
                print(f"  {YELLOW}SSH Hijack Error:{RESET} {hijack_err}")
            elif find_out:
                lines = find_out.strip().split("\n")
                scrub_hits = 0
                for line in lines:
                    line = line.strip()
                    if not line: continue
                    # Route systemd files to Section 5
                    if "/etc/systemd/system" in line: continue
                    
                    if any(k in line.lower() for k in sus_keywords):
                        print(f"  {RED}[CRITICAL]{RESET} {line}")
                        scrub_hits += 1
                    elif line.startswith("/usr/local/sbin") or line.startswith("/srv") or line.startswith("/opt"):
                        print(f"  {YELLOW}[SUSPICIOUS]{RESET} {line}")
                        scrub_hits += 1
                        
                    if scrub_hits >= 20:
                        print(f"  ... {YELLOW}and more (output truncated){RESET}")
                        break
                        
                if not scrub_hits:
                    print("  None detected in common footholds.")
            else:
                print(f"  {YELLOW}Hijacked query executed but returned empty.{RESET}")

            # 4. Suspect C2 IPs
            print(f"\n{CYAN}[*] POTENTIAL C2 IPs (Outbound Flow Anomalies):{RESET}")
            classification = self.state.get("classification", {})
            flows = classification.get("flows", [])
            protected_ip = classification.get("protected", {}).get("remote_ip")
            
            c2_found = False
            for f in flows:
                ip = f.get("remote_ip")
                if ip and ip != protected_ip:
                    c2_found = True
                    print(f"  {RED}{ip}:{f.get('remote_port')}{RESET} | {YELLOW}Theft Score:{RESET} {f.get('theft_score')} | {YELLOW}Engine Action:{RESET} {f.get('action')} {RED}[POTENTIAL BEACON]{RESET}")
            
            if not c2_found:
                print("  None detected.")

            # 5. Potential Evasive Timers & Services
            print(f"\n{CYAN}[*] POTENTIAL EVASIVE PERSISTENCE (Root Systemd Timers & Services):{RESET}")
            safe_timers = {
                "apt-daily-upgrade.timer", "apt-daily.timer", "dpkg-db-backup.timer",
                "e2scrub_all.timer", "fstrim.timer", "fwupd-refresh.timer",
                "logrotate.timer", "man-db.timer", "motd-news.timer",
                "systemd-tmpfiles-clean.timer", "update-notifier-download.timer",
                "update-notifier-motd.timer", "phpsessionclean.timer",
                "apport-autoreport.timer", "snapd.snap-repair.timer",
                "ua-timer.timer", "snapd.aa-prompt-listener.timer"
            }
            persistence_found = 0
            
            # Parse raw files found in /etc/systemd/system
            if find_out:
                for line in find_out.strip().split("\n"):
                    line = line.strip()
                    if "/etc/systemd/system" in line:
                        file_name = line.split("/")[-1]
                        if file_name.endswith(".timer") and file_name not in safe_timers:
                            print(f"  {RED}Anomalous Timer File:{RESET} {line}")
                            persistence_found += 1
                        elif file_name.endswith(".service") and any(k in file_name for k in sus_keywords):
                            print(f"  {RED}Anomalous Service File:{RESET} {line}")
                            persistence_found += 1
                        
            # Standard Service Parsing from Agent Snapshot
            for s in latest.get("services") or []:
                s_str = json.dumps(s).lower() if isinstance(s, dict) else str(s).lower()
                if any(k in s_str for k in sus_keywords):
                    if isinstance(s, dict):
                        unit = s.get("unit", "Unknown")
                        exec_cmd = s.get("exec", "")
                        print(f"  {RED}Malicious Service:{RESET} {unit} | {YELLOW}Exec:{RESET} {exec_cmd[:60]}")
                    else:
                        print(f"  {RED}Malicious Service:{RESET} {s_str[:100]}")
                    persistence_found += 1

            if not persistence_found:
                print("  None detected.")

            # 6. Rogue SSH Keys
            print(f"\n{CYAN}[*] SSH DIRECTORY CONTENTS (Manually audit for backdoors):{RESET}")
            if key_err:
                print(f"  {YELLOW}Key listing error:{RESET} {key_err}")
            elif key_user != "root":
                print(f"  {YELLOW}Scan ran as '{key_user}', not root - cannot read /root/.ssh. "
                      f"Sudo password missing or wrong.{RESET}")
            elif not key_entries:
                print("  Ran as root; no key files found.")
            for path, meta, fps in key_entries:
                name = path.rsplit("/", 1)[-1].lower()
                hot = any(k in name for k in ("sensor_trust", "shadow", "authorized_keys", "id_"))
                tag = f"{RED}[CRITICAL]{RESET}" if hot else f"{YELLOW}[KEY FILE]{RESET}"
                print(f"  {tag} {path}  ({meta})")
                for fp in fps:
                    if "not a public key file" in fp or "invalid format" in fp or "No such file" in fp:
                        print(f"      {YELLOW}-> not a parseable key (config/other){RESET}")
                    else:
                        print(f"      {CYAN}->{RESET} {fp}")

            self._print_sentinel_scope(latest)
            print(f"{MAGENTA}==========================={RESET}\n", flush=True)

    def _print_sentinel_scope(self, latest: dict) -> None:
        role = (self.profile.get("role") or "")
        label = (self.host_label or self.profile.get("label") or "")
        if role != "SENTINEL-01" and label not in {"sentinel", "sentinel-01"}:
            return
        found = sentinel_findings(latest)
        print(f"\n{CYAN}[*] SENTINEL-01 CONSOLE AND DIAGNOSTICS EXPORT:{RESET}")
        for line in found["console"]:
            print(f"  {line}")
        print(f"\n{CYAN}[*] AUTH MATERIAL IN PROCESS ENVIRON (values redacted):{RESET}")
        if found["tokens"]:
            for line in found["tokens"]:
                print(f"  {RED}{line}{RESET}")
        else:
            print("  No session, token, or password variable names in captured process environ.")
        print(f"\n{CYAN}[*] UNEXPECTED FLOWS TO EDGE-02 OR OPS-03:{RESET}")
        if found["unexpected_peers"]:
            for line in found["unexpected_peers"]:
                print(f"  {RED}{line}{RESET}")
        else:
            print("  No established connection to 10.80.40.12 or 10.80.40.13 outside the expected detection or log-forwarding flow.")

    def _hunt(self, args_str: str) -> None:
        import argparse, shlex, re
        parser = argparse.ArgumentParser(prog="hunt", add_help=False)
        parser.add_argument("term", nargs="?", default="")
        parser.add_argument("--regex", action="store_true")
        parser.add_argument("--scope", default="", help="Filter by JSON key (e.g., 'environ' or 'maps')")
        
        try:
            args = parser.parse_args(shlex.split(args_str))
        except SystemExit:
            self._say("usage: hunt <term> [--regex] [--scope str]")
            return

        if not args.term:
            self._say("hunt requires a search term")
            return

        pattern = re.compile(args.term) if args.regex else None
        snaps = _load_observe_snapshots(self.local / "snapshots", self.state.get("session_id"))
        
        if not snaps:
            self._say("No snapshots available to hunt through.")
            return

        self._say(f"Hunting for '{args.term}' across {len(snaps)} snapshots...")
        
        matches = []
        for snap in snaps:
            ts = snap.get("taken_at")
            
            def _search(obj, current_scope=""):
                if isinstance(obj, dict):
                    if args.scope and current_scope != args.scope and args.scope in obj:
                        _search(obj[args.scope], args.scope)
                    else:
                        for k, v in obj.items():
                            _search(v, k)
                elif isinstance(obj, list):
                    for item in obj:
                        _search(item, current_scope)
                elif isinstance(obj, str):
                    if (pattern and pattern.search(obj)) or (not pattern and args.term in obj):
                        matches.append(f"[{ts}] Match in <{current_scope}>: {obj[:200]}")

            _search(snap)

        unique_matches = list(dict.fromkeys(matches))
        if not unique_matches:
            self._say("No matches found.")
        else:
            for match in unique_matches:
                self._say(match)         

    def _flows(self) -> None:
        if not self._check_integrity():
            return
            
        self._say("Classifying outbound flows...")
        
        result = run_classification(
            self.watch.get("history") or [], self.state.get("pipeline"), self.iocs, self.profile,
        )
        self.state["flows_ran"] = True
        self.state["mission_unclear"] = result["mission_unclear"]
        self.state["classify_note"] = result["note"]
        self.state["protected"] = result["protected"]
        self.state["classification"] = result
        self._event("differentiator: " + result["note"], "decision")
        self.audit.append("decision", "flows classified", {"note": result["note"]})
        if not result["flows"]:
            self._say("no outbound flows in the snapshots")
        for flow in result["flows"]:
            self._print_flow(flow)
        self._say(result["note"])
        self._save_state()

    def _print_flow(self, flow: dict) -> None:
        self._say(
            f"{flow['action']}  {flow.get('confidence_pct')}%  "
            f"pid={flow.get('pid')} {flow.get('comm')} -> {flow.get('remote_ip')}:{flow.get('remote_port')}  "
            f"theft_score={flow.get('theft_score')}"
        )
        for name, reason in (flow.get("reasons") or {}).items():
            self._say(f"  {name}: {reason}")

    def _contain(self) -> None:
        if not self.state.get("flows_ran"):
            self._say("Run flows first. Destructive suggestions are refused until the mission uplink is identified.")
            return
        if not self._check_integrity():
            return
        if "contain" not in self.state["phase_started_unix"]:
            self.state["phase"] = "contain"
            self.state["phase_started_unix"]["contain"] = time.time()
            self._event("phase 4 containment suggestions", "phase")
        latest = (self.watch.get("history") or [None])[-1] or {}
        report = suggest(
            self.state.get("classification") or {},
            latest.get("services") or [],
            self.state.get("alerts") or [],
            latest.get("timers") or []
        )
        self.state["suggestions"] = report["suggestions"]
        if report.get("note"):
            self._say(report["note"])
        if not report["suggestions"]:
            self._say("no executable suggestion")
        for item in report["suggestions"]:
            self._say(
                f"{item['id']} risk={item['risk']} {item['action']} {item['command_preview']}"
            )
            self._say(f"  why: {item['why']}")
            self._say(f"  rollback: {item['rollback']}")
        for line in report.get("refused") or []:
            self._say(line)
        self._say("Nothing ran. Use: do <id>")
        self._save_state()

    def _do(self, ident: str) -> None:
        if not self._check_integrity():
            return
        item = None
        for candidate in self.state.get("suggestions") or []:
            if candidate.get("id") == ident:
                item = candidate
                break
        if item is None:
            self._say("unknown suggestion. Run contain again.")
            return
        protected = self.state.get("protected")
        refusal = touches_protected(item, protected)
        if refusal:
            self._say(f"refused: {refusal}")
            self.audit.append("decision", "containment refused", {"id": ident, "reason": refusal})
            return
        bad = validate_exec(item.get("argv") or [])
        if bad:
            self._say(f"refused: {bad}")
            return
        self._say(item["command_preview"])
        self._say("rollback: " + item["rollback"])
        if input("Type YES to run this one action: ").strip() != "YES":
            self._say("cancelled")
            return
        pre = self._take_snapshot()
        pre_path = self._save_json(self.local / "pre-action" / f"{ident}-{_file_stamp()}.json", pre)
        self._evidence("snapshot", str(pre_path), f"pre-action {ident}")
        if not self.state.get("eradication_ts"):
            self.state["eradication_ts"] = stamp()
            self.state["eradication_unix"] = time.time()
            self._event("eradication marker set at first containment action", "containment")
        assert self.session is not None
        result = self.session.call_agent(self.remote_agent, ["run", "--", *item["argv"]])
        self.audit.append("command", "containment exec", {"argv": item["argv"], "result": result})
        self.state.setdefault("actions", []).append({
            "id": ident, "argv": item["argv"], "ts": stamp(), "result": result,
        })
        self._event(f"ran {item['command_preview']} ok={result.get('ok')}", "containment")
        self.state["access_paths"] = close_paths(self.state.get("access_paths") or [], {
            "pid": item.get("pid"),
            "remote_ip": item.get("remote_ip"),
            "action": item.get("action"),
            "summary": item["command_preview"],
        }, stamp())
        self.watch["access_paths"] = self.state["access_paths"]
        post = self._take_snapshot()
        self._ingest(post, quiet=False)
        if protected and not _mission_up(post, protected):
            self._say("MISSION CHECK FAILED AFTER THE ACTION")
            self._say(item["rollback"])
            self._event("mission check failed after containment; rollback note printed", "containment")
        self._save_state()

    def _comp_phase(self, name: str) -> None:
        if not name:
            self._say("usage: phase <name>")
            return
        self.state["comp_phase"] = name
        self.state["timeline"].append(phase_event(name))
        self._say(f"--- competition phase {name} ---")
        self.audit.append("decision", "competition phase", {"name": name})
        self._save_state()

    def _writeup(self) -> None:
        if "writeup" not in self.state["phase_started_unix"]:
            self.state["phase"] = "writeup"
            self.state["phase_started_unix"]["writeup"] = time.time()
        text = render_writeup(self._ctx())
        path = self.local / "writeup.md"
        path.write_text(text, encoding="utf-8")
        self.audit.append("command", "writeup", {"path": str(path)})
        self._save_state()
        self._say(f"wrote {path}")
        with self._print_lock:
            print(text, flush=True)

    def _status(self) -> None:
        label, _prefix, expired = remaining(self.state.get("baseline_unix"), time.time())
        avail = availability(self.watch.get("history") or [], self.state.get("protected"))
        number = "n/a" if avail["number"] is None else str(avail["number"])
        self._say(
            f"phase={self.state.get('phase')} comp={self.state.get('comp_phase')} "
            f"timer={label}{' EXPIRED' if expired else ''} availability={number}"
        )
        self._say(avail["why"])
        if self.state.get("classify_note"):
            self._say(self.state["classify_note"])

    def _print_alerts(self) -> None:
        from shadow.snapshot import prioritize
        alerts = prioritize(self.state.get("alerts") or [])
        if not alerts:
            self._say("no alerts")
            return
        for item in alerts[:20]:
            self._say(f"{item.get('impact')} {item.get('source')} {item.get('summary')}", alert=True)

    def _check_integrity(self) -> bool:
        current = local_manifest(self.root)
        changed = compare(self.manifest, current)
        if changed:
            self._say("local modules changed during the session: " + ", ".join(changed))
            if input("Type INTEGRITY ACK to accept them: ").strip() != "INTEGRITY ACK":
                return False
            self.manifest = current
            self.audit.append("decision", "integrity ack", {"changed": changed})
            _write_json(self.local / "module_manifest.json", current)
        rels = upload_relpaths(current)
        remote = self._remote_hashes(rels)
        if remote is None:
            return False
        expected = self._accepted_remote or {rel: current[rel] for rel in rels}
        bad = [rel for rel in rels if remote.get(rel) != expected.get(rel)]
        if bad:
            self._say("bunker modules differ from the accepted copy: " + ", ".join(bad))
            if input("Type INTEGRITY ACK to continue without restoring: ").strip() != "INTEGRITY ACK":
                return False
            self.audit.append("decision", "remote integrity ack", {"changed": bad})
            self._accepted_remote = dict(remote)
        return True

    def _ctx(self) -> dict:
        history = self.watch.get("history") or []
        evidence_unix = history[-1].get("operator_unix") if history else self.state.get("baseline_unix")
        host = host_by_label(self.host_label) or {}
        return {
            "host_label": self.host_label,
            "host_name": host.get("name") or self.profile.get("role") or "",
            "host_ip": host.get("ip") or self.profile.get("host") or "",
            "local_bunker": str(self.local),
            "fingerprint": self.state.get("fingerprint") or {},
            "baseline_ts": self.state.get("baseline_ts") or "",
            "baseline_unix": self.state.get("baseline_unix"),
            "eradication_ts": self.state.get("eradication_ts") or "",
            "eradication_unix": self.state.get("eradication_unix"),
            "evidence_unix": evidence_unix,
            "topology_written": self.state.get("topology_written"),
            "flows_ran": self.state.get("flows_ran"),
            "mission_unclear": self.state.get("mission_unclear"),
            "classify_note": self.state.get("classify_note") or "",
            "protected_touched": self.state.get("operator_snapshots") or 0,
            "operator_snapshots": self.state.get("operator_snapshots") or 0,
            "timeline": self.state.get("timeline") or [],
            "access_paths": self.state.get("access_paths") or [],
            "evidence": self.state.get("evidence") or [],
            "availability": availability(history, self.state.get("protected")),
        }

    def _nudge(self) -> None:
        phase = self.state.get("phase") or "observe"
        text = nudge_for(phase, (self.state.get("phase_started_unix") or {}).get(phase), time.time())
        if text and phase not in self.state["nudged"]:
            self.state["nudged"].append(phase)
            self._say(text)

    def _local_space(self) -> None:
        usage = shutil.disk_usage(self.local)
        if usage.free < 20 * 1024 * 1024:
            self._say(f"operator bunker low on space: {usage.free} bytes free")

    def _say(self, text: str, alert: bool = False, routine: bool = False) -> None:
        label, prefix, expired = remaining(self.state.get("baseline_unix"), time.time())
        
        if alert:
            line = format_alert(stamp(), text, label, prefix, expired)
            line = f"{RED}{line}{RESET}"
        else:
            line = f"[{stamp()}] timer={label} {text}"
            
        with open(self.local / "events.log", "a", encoding="utf-8") as log_file:
            log_file.write(line + "\n")
            
        # Hard mute: Drop everything flagged as routine (including spammy alert logs)
        if self.state.get("muted", False) and routine:
            return

        with self._print_lock:
            print("\n" + line, flush=True)
            
            # Smart spam reminder system
            if not self.state.get("muted", False) and routine:
                self.state["spam_count"] = self.state.get("spam_count", 0) + 1
                if self.state["spam_count"] == 10:
                    print(f"\n{YELLOW}[!] Pro-Tip: Type 'm' or 'mute' and press Enter to hide this routine network spam.{RESET}", flush=True)

    def _event(self, text: str, kind: str) -> None:
        with self._state_lock:
            self.state["timeline"].append({
                "ts": stamp(),
                "comp_phase": self.state.get("comp_phase") or "initial",
                "text": text,
                "kind": kind,
                "phase_started": False,
            })

    def _evidence(self, kind: str, ref: str, note: str) -> None:
        with self._state_lock:
            self.state["evidence"].append({"ts": stamp(), "kind": kind, "ref": ref, "note": note})

    def _save_json(self, path: Path, payload: dict) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        return path

    def _save_state(self) -> None:
        with self._state_lock:
            _write_json(self.local / "session_state.json", self.state)


def run_replay(snapshot_dir: Path, out_dir: Path, profile_path: Path, ioc_path: Path) -> int:
    """Score saved snapshots with no SSH and no live actions."""
    profile = load_profile(_read_json(profile_path))
    iocs = _load_iocs(ioc_path)
    snaps = _load_observe_snapshots(snapshot_dir, session_id=None)
    if not snaps:
        print("no snapshot json in", snapshot_dir)
        return 1
    watch = fresh_watch()
    timeline = []
    evidence = []
    comp = "initial"
    for snap in snaps:
        seen = snap.get("taken_at") or stamp()
        result = ingest(watch, snap, seen)
        evidence.append({"ts": seen, "kind": "snapshot", "ref": snap.get("taken_at") or "", "note": "replay"})
        for item in result["alerts"]:
            timeline.append({"ts": seen, "comp_phase": comp, "text": item["summary"], "kind": "alert"})
        for line in result["edges"]:
            timeline.append({"ts": seen, "comp_phase": comp, "text": line, "kind": "topology"})
    fingerprint = score_host(snaps[0], profile)
    pipeline = fingerprint.get("pipeline") or {}
    classified = run_classification(watch["history"], pipeline, iocs, profile)
    out_dir.mkdir(parents=True, exist_ok=True)
    write_outputs(watch["graph"], out_dir / "topology")
    report = suggest(classified, (snaps[-1].get("services") or []), [])
    (out_dir / "suggestions.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    baseline = watch["history"][0]
    ctx = {
        "fingerprint": fingerprint,
        "baseline_ts": baseline.get("taken_at") or "",
        "baseline_unix": baseline.get("operator_unix"),
        "eradication_ts": "",
        "eradication_unix": None,
        "evidence_unix": watch["history"][-1].get("operator_unix"),
        "topology_written": True,
        "flows_ran": True,
        "mission_unclear": classified["mission_unclear"],
        "classify_note": classified["note"],
        "protected_touched": False,
        "operator_snapshots": len(snaps),
        "timeline": timeline,
        "access_paths": watch["access_paths"],
        "evidence": evidence,
        "availability": availability(watch["history"], classified.get("protected")),
    }
    text = render_writeup(ctx)
    (out_dir / "writeup.md").write_text(text, encoding="utf-8")
    print(classified["note"])
    for flow in classified["flows"]:
        print(
            f"{flow['action']} {flow.get('confidence_pct')}% "
            f"pid={flow.get('pid')} {flow.get('comm')} -> {flow.get('remote_ip')}:{flow.get('remote_port')}"
        )
    print("writeup", out_dir / "writeup.md")
    return 0


def _fresh_state(remote: str, local: str, interval: float) -> dict:
    return {
        "session_id": uuid.uuid4().hex[:12],
        "phase": "land",
        "comp_phase": "initial",
        "remote_bunker": remote,
        "local_bunker": local,
        "interval": interval,
        "phase_started_unix": {},
        "nudged": [],
        "timeline": [],
        "evidence": [],
        "alerts": [],
        "actions": [],
        "access_paths": [],
        "flows_ran": False,
        "mission_unclear": False,
        "classify_note": "",
        "protected": None,
        "protected_touched": False,
        "topology_written": False,
        "operator_snapshots": 0,
        "baseline_ts": "",
        "baseline_unix": None,
        "eradication_ts": "",
        "eradication_unix": None,
        "fingerprint": {},
        "pipeline": {},
        "shell": {},
        "python_path": "",
    }


def _mission_up(snapshot: dict, protected: dict) -> bool:
    return availability([snapshot], protected)["number"] == 100.0


def _load_observe_snapshots(directory: Path, session_id: str | None) -> list[dict]:
    snaps = []
    if not directory.is_dir():
        return snaps
    for path in sorted(directory.glob("*.json")):
        try:
            snap = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if snap.get("role") == "fingerprint":
            continue
        if session_id and snap.get("session_id") not in (None, session_id):
            continue
        snaps.append(snap)
    snaps.sort(key=lambda item: item.get("taken_at") or "")
    return snaps


def _load_iocs(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    found = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            found.add(line)
    return found


def _read_json(path: Path) -> dict:
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    try:
        temporary.replace(path)
    except PermissionError:
        import time
        time.sleep(0.1)
        temporary.replace(path)


def _file_stamp() -> str:
    return stamp().replace("-", "").replace(":", "")