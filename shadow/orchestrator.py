"""Human-gated phases. Observation runs in the background and does not own the keyboard."""

from __future__ import annotations

import json
import shutil
import threading
import time
import uuid
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
from shadow.timeline import availability, phase_event, render_writeup
from shadow.topology import adjacency_list, write_outputs

HELP = """
status              timer, phase, availability
alerts              highest impact first
topo                adjacency list
flows               phase 3, asks YES, classifies outbound flows
contain             phase 4 suggestions, does not execute
do <id>             asks YES, then runs one allowlisted action
phase <name>        log a competition-phase divider
restore             copy modules to the bunker again
writeup             phase 5 markdown
quit                save and close
""".strip()


class Operator:
    def __init__(self, root: Path, local_bunker: Path, remote_bunker: str, interval: float,
                 profile_path: Path, ioc_path: Path, session: RemoteSession | None):
        self.root = root
        self.local = local_bunker
        self.remote_bunker = remote_bunker.rstrip("/")
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
                speeches.append(("baseline snapshot recorded; 45-minute evidence timer started", "snapshot", False))
            alerts = self.state.setdefault("alerts", [])
            for item in result["alerts"]:
                alerts.append(item)
                speeches.append((item["summary"], "alert", True))
            del alerts[:-200]
            for line in result["edges"]:
                speeches.append((line, "topology", False))
        note = "baseline" if first else "observation pass"
        self._evidence("snapshot", str(path), note)
        self.audit.append("snapshot", note, {"path": str(path)})
        if not quiet:
            for text, kind, is_alert in speeches:
                self._event(text, kind)
                self._say(text, alert=is_alert)
            if topo.get("dot"):
                self._say(f"graphviz {topo['dot']}")
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
        self._say("Phase 2 is running. Type help for commands.")
        while not self._stop.is_set():
            try:
                line = input("shadow> ").strip()
            except EOFError:
                break
            if not line:
                continue
            self.audit.append("command", line, {})
            if not self._dispatch(line):
                break

    def _dispatch(self, line: str) -> bool:
        if line == "help":
            self._say(HELP)
        elif line == "status":
            self._status()
        elif line == "alerts":
            self._print_alerts()
        elif line == "topo":
            self._say(adjacency_list(self.watch.get("graph") or {}))
        elif line == "flows":
            self._flows()
        elif line == "contain":
            self._contain()
        elif line.startswith("do "):
            self._do(line.split(None, 1)[1].strip())
        elif line.startswith("phase "):
            self._comp_phase(line.split(None, 1)[1].strip())
        elif line == "restore":
            self._bootstrap()
        elif line == "writeup":
            self._writeup()
        elif line == "quit":
            return False
        else:
            self._say("unknown command. Type help.")
        return True

    def _flows(self) -> None:
        if not self._check_integrity():
            return
        if input("Type YES to classify outbound flows: ").strip() != "YES":
            self._say("classification cancelled")
            return
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
        return {
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
            "protected_touched": self.state.get("protected_touched", False),
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

    def _say(self, text: str, alert: bool = False) -> None:
        label, prefix, expired = remaining(self.state.get("baseline_unix"), time.time())
        if alert:
            line = format_alert(stamp(), text, label, prefix, expired)
        else:
            line = f"[{stamp()}] timer={label} {text}"
        with self._print_lock:
            print("\n" + line, flush=True)

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
    temporary.replace(path)


def _file_stamp() -> str:
    return stamp().replace("-", "").replace(":", "")
