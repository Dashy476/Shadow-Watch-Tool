"""Stdlib tests for parsers, scoring, containment, and the writeup. No SSH."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from shadow.auditlog import AuditLog, verify  # noqa: E402
from shadow.bootstrap import needed_bytes, plan_uploads  # noqa: E402
from shadow.budget import format_alert, nudge_for, remaining  # noqa: E402
from shadow.containment import suggest, touches_protected, validate_exec  # noqa: E402
from shadow.differentiator import classify  # noqa: E402
from shadow.engine import fresh_watch, ingest  # noqa: E402
from shadow.fingerprint import score_host  # noqa: E402
from shadow.integrity import compare, upload_relpaths  # noqa: E402
from shadow.plugins.beacon import is_periodic  # noqa: E402
from shadow.plugins.ipc import inspect as ipc_inspect  # noqa: E402
from shadow.plugins.trust import inspect as trust_inspect  # noqa: E402
from shadow.procparse import parse_proc_net, parse_ss, parse_stat, parse_systemctl_show  # noqa: E402
from shadow.secrets import scrub, take_env  # noqa: E402
from shadow.session import build_embedded_script  # noqa: E402
from shadow.snapshot import diff_snapshots  # noqa: E402
from shadow.timeline import evidence_relation, render_writeup  # noqa: E402
from shadow.topology import update_graph  # noqa: E402
from shadow.orchestrator import run_replay  # noqa: E402


TCP = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    "   0: 0500000A:01BB 0800000A:0050 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0\n"
)
TCP6 = (
    "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    "   0: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 99 1 0000000000000000 100 0 0 10 0\n"
)


def proc(pid, ppid, comm, exe, parent, fds=None, writes=0, heads=None, cmdline=None):
    return {
        "pid": pid,
        "ppid": ppid,
        "comm": comm,
        "exe": exe,
        "cmdline": cmdline if cmdline is not None else exe,
        "parent_comm": parent,
        "tool": False,
        "write_bytes": writes,
        "fds": fds or [],
        "file_heads": heads or [],
    }


def sock(inode, local_ip, local_port, remote_ip, remote_port, state="ESTABLISHED"):
    return {
        "proto": "tcp",
        "local_ip": local_ip,
        "local_port": local_port,
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "local": f"{local_ip}:{local_port}",
        "remote": f"{remote_ip}:{remote_port}",
        "state": state,
        "inode": inode,
        "uid": 0,
    }


def snapshot(when, tracker_writes, curl_writes, extra_procs=None):
    tracker_fd = [{"fd": "5", "target": "socket:[10]", "mode": "readwrite"},
                  {"fd": "6", "target": "/var/lib/sentinel/tracks/current", "mode": "write"}]
    heads = [{"path": "/var/lib/sentinel/tracks/current", "json_keys": ["lat", "lon", "track_id"], "entropy": 3.1}]
    rows = [
        proc(1, 0, "systemd", "/sbin/init", ""),
        proc(40, 1, "bash", "/bin/bash", "systemd"),
        proc(20, 1, "tracker", "/usr/bin/tracker", "systemd", tracker_fd, tracker_writes, heads),
        proc(30, 40, "curl", "/usr/bin/curl", "bash",
             [{"fd": "3", "target": "socket:[11]", "mode": "readwrite"}], curl_writes),
    ]
    if extra_procs:
        rows.extend(extra_procs)
    return {
        "role": "observe",
        "taken_at": f"2026-10-26T12:00:{when % 60:02d}Z",
        "operator_unix": 1_700_000_000 + when,
        "clock_skew_s": 0.2,
        "hostname_ignored": "SENTINEL-01",
        "processes": rows,
        "sockets": [
            sock("10", "10.0.0.5", 4000, "10.0.0.8", 443),
            sock("11", "10.0.0.5", 50000, "203.0.113.9", 443),
        ],
        "services": [{
            "unit": "tracker.service", "exec": "/usr/bin/tracker",
            "fragment": "/lib/systemd/system/tracker.service", "source": "systemctl",
        }],
        "maps": [],
        "unix": [{"inode": "50", "path": "/run/sensor.sock", "flags": "0", "type": "1"}],
        "routes": [{"iface": "eth0", "destination": "0.0.0.0", "gateway": "10.0.0.1"}],
        "arp": [{"ip": "10.0.0.8", "hw": "aa:bb:cc:dd:ee:ff", "device": "eth0"}],
        "perm_records": [],
        "configs": [],
    }


def series():
    snaps = []
    tracker = 0
    curl = 0
    jumps = [0, 100, 50000, 100, 100]
    for index, jump in enumerate(jumps):
        tracker += 1000
        curl += jump
        snaps.append(snapshot(index * 3, tracker, curl))
    return snaps


class ParseTests(unittest.TestCase):
    def test_tcp_ipv4(self):
        rows = parse_proc_net(TCP, "tcp", False)
        self.assertEqual(rows[0]["local_ip"], "10.0.0.5")
        self.assertEqual(rows[0]["local_port"], 443)
        self.assertEqual(rows[0]["remote_ip"], "10.0.0.8")
        self.assertEqual(rows[0]["remote_port"], 80)
        self.assertEqual(rows[0]["state"], "ESTABLISHED")
        self.assertEqual(rows[0]["inode"], "12345")

    def test_tcp6_loopback_listen(self):
        rows = parse_proc_net(TCP6, "tcp6", True)
        self.assertEqual(rows[0]["local_ip"], "::1")
        self.assertEqual(rows[0]["state"], "LISTEN")

    def test_stat_comm_with_space(self):
        parsed = parse_stat("12 (track er) S 1 12 12 0 -1")
        self.assertEqual(parsed, (12, "track er", 1))

    def test_systemctl_show_and_ss(self):
        text = "Id=tracker.service\nExecStart={ path=/usr/bin/tracker ; argv[]=/usr/bin/tracker }\nFragmentPath=/lib/tracker.service\n\n"
        shown = parse_systemctl_show(text)
        self.assertEqual(shown[0]["exec"], "/usr/bin/tracker")
        rows = parse_ss("ESTAB 0 0 10.0.0.5:4000 10.0.0.8:443\n")
        self.assertEqual(rows[0]["state"], "ESTABLISHED")
        self.assertEqual(rows[0]["remote_port"], 443)


class FingerprintTests(unittest.TestCase):
    def test_accepts_pipeline_and_ignores_hostname(self):
        good = snapshot(0, 0, 0)
        other = json.loads(json.dumps(good))
        other["hostname_ignored"] = "not-the-node"
        left = score_host(good, {"hostname": "SENTINEL-01"})
        right = score_host(other, {"hostname": "something-else"})
        self.assertEqual(left["score"], right["score"])
        self.assertGreaterEqual(left["score"], 0.70)
        self.assertEqual(left["label"], "accept")
        self.assertFalse(left["hostname_used"])

    def test_ambiguous_and_wrong(self):
        ambiguous = {
            "processes": [proc(7, 1, "tracker", "/usr/bin/tracker", "bash")],
            "sockets": [],
            "maps": [],
        }
        result = score_host(ambiguous, None)
        self.assertEqual(result["label"], "ambiguous")
        self.assertEqual(result["report"], "wrong host / ambiguous")
        wrong = {"processes": [proc(3, 1, "nginx", "/usr/sbin/nginx", "systemd")], "sockets": [], "maps": []}
        self.assertEqual(score_host(wrong, None)["label"], "wrong host")


class DiffTopologyTests(unittest.TestCase):
    def test_first_pass_is_quiet_and_tool_pid_is_ignored(self):
        base = snapshot(0, 0, 0)
        self.assertEqual(diff_snapshots(None, base, None), [])
        nxt = snapshot(3, 1000, 100)
        nxt["processes"].append(proc(99, 1, "node_agent.py", "/usr/bin/python3", "sshd",
                                     cmdline="python3 shadow/node_agent.py snapshot"))
        nxt["processes"][-1]["tool"] = True
        alerts = diff_snapshots(base, nxt, base)
        self.assertFalse(any(item["kind"] == "new-pid" and item["evidence"]["pid"] == 99 for item in alerts))

    def test_new_socket_and_relocated_service(self):
        base = snapshot(0, 0, 0)
        nxt = snapshot(3, 1000, 100)
        nxt["sockets"].append(sock("12", "10.0.0.5", 9, "198.51.100.4", 4444))
        nxt["services"][0]["exec"] = "/tmp/tracker"
        alerts = diff_snapshots(base, nxt, base)
        kinds = {item["kind"] for item in alerts}
        self.assertIn("new-socket", kinds)
        self.assertIn("service-relocated", kinds)

    def test_topology_keeps_first_seen(self):
        first = update_graph(None, snapshot(0, 0, 0), "2026-10-26T12:00:00Z")
        second = update_graph(first, snapshot(3, 1, 1), "2026-10-26T12:00:03Z")
        edge = second["edges"]["10.0.0.5"]["10.0.0.8"]
        self.assertEqual(edge["first_seen"], "2026-10-26T12:00:00Z")
        self.assertEqual(edge["last_seen"], "2026-10-26T12:00:03Z")


class ClassifyTests(unittest.TestCase):
    def test_mission_left_alone_and_ioc_flow_blocked(self):
        result = classify(series(), {"pid": 20, "comm": "tracker", "exe": "/usr/bin/tracker"}, {"203.0.113.9"})
        by_pid = {flow["pid"]: flow for flow in result["flows"]}
        self.assertEqual(by_pid[20]["action"], "leave alone")
        self.assertEqual(by_pid[30]["action"], "block")
        self.assertGreater(by_pid[30]["theft_score"], by_pid[20]["theft_score"])
        self.assertFalse(result["mission_unclear"])
        self.assertEqual(result["protected"]["pid"], 20)
        self.assertEqual(result["protected"]["remote_ip"], "10.0.0.8")
        self.assertTrue(result["json_enabled"])

    def test_ipc_silent_without_json(self):
        self.assertEqual(ipc_inspect(series()[0], series()[-1], False), [])

    def test_beacon_period_math(self):
        ok, stats = is_periodic([3.0, 3.1, 2.9], 3.0, 0.5)
        self.assertTrue(ok)
        self.assertLess(stats["cv"], 0.5)

    def test_trust_material(self):
        snap = snapshot(0, 0, 0)
        snap["perm_records"] = [{
            "path": "/root/.ssh/id_rsa", "mode": "0o644", "owner": "0", "group": "0",
            "signing": True, "world_read": True, "world_write": False, "group_read": True,
        }]
        alerts = trust_inspect(None, snap)
        self.assertTrue(any(item["kind"] == "trust-material" for item in alerts))


class ContainmentTests(unittest.TestCase):
    def test_refuses_mission_and_reboot(self):
        classified = classify(series(), {"pid": 20, "comm": "tracker", "exe": "/usr/bin/tracker"}, {"203.0.113.9"})
        report = suggest(classified, series()[-1]["services"], [])
        self.assertTrue(report["suggestions"])
        for item in report["suggestions"]:
            joined = " ".join(item["argv"]).lower()
            self.assertNotIn("reboot", joined)
            self.assertNotIn("docker", joined)
            self.assertNotIn("reimage", joined)
            self.assertNotEqual(item.get("pid"), 20)
            self.assertNotEqual((item.get("remote_ip"), item.get("remote_port")), ("10.0.0.8", 443))
            self.assertEqual(validate_exec(item["argv"]), "")
            self.assertIn("reboot", item["rollback"].lower())
        self.assertTrue(any(item["action"] == "kill-process" and item["pid"] == 30 for item in report["suggestions"]))
        protected = classified["protected"]
        self.assertTrue(touches_protected({"pid": 20, "action": "kill-process", "remote_ip": "", "remote_port": 0, "unit": ""}, protected))
        self.assertEqual(validate_exec(["reboot"]), "reboot is forbidden")
        self.assertNotEqual(validate_exec(["kill", "-TERM", "1"]), "")
        self.assertNotEqual(validate_exec(["systemctl", "restart", "reboot.service"]), "")
        self.assertEqual(validate_exec(["chmod", "600", "/root/.ssh/id_rsa"]), "")


class WriteupTests(unittest.TestCase):
    def test_sections_and_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            snap_dir = folder / "snaps"
            snap_dir.mkdir()
            for index, snap in enumerate(series()):
                (snap_dir / f"{index}.json").write_text(json.dumps(snap), encoding="utf-8")
            out = folder / "out"
            code = run_replay(snap_dir, out, ROOT / "profiles" / "sentinel01.json", folder / "missing-iocs.txt")
            self.assertEqual(code, 0)
            text = (out / "writeup.md").read_text(encoding="utf-8")
            for heading in (
                "## Gate status",
                "## Timeline",
                "## Access paths",
                "## Evidence log",
                "## Availability",
                "## What you'd do differently",
            ):
                self.assertIn(heading, text)
            self.assertEqual(text.split("## What you'd do differently", 1)[1].strip(), "")
            self.assertEqual(text.count("| PASS |") + text.count("| PARTIAL |") + text.count("| FAIL |") + text.count("| OPEN |"), 8)
            self.assertIn("Availability:", text)
            watch = fresh_watch()
            for snap in series():
                ingest(watch, snap, snap["taken_at"])
            self.assertTrue(watch["access_paths"])

    def test_evidence_relation(self):
        self.assertIn("before eradication", evidence_relation("2026-10-26T12:00:00Z", None))
        self.assertIn("before", evidence_relation("2026-10-26T12:00:00Z", "2026-10-26T12:10:00Z"))
        self.assertIn("after", evidence_relation("2026-10-26T12:20:00Z", "2026-10-26T12:10:00Z"))


class BookkeepingTests(unittest.TestCase):
    def test_timer_and_nudge(self):
        label, prefix, expired = remaining(None, 0)
        self.assertEqual(label, "not-started")
        self.assertFalse(prefix)
        label, prefix, expired = remaining(1_000, 1_000 + 40 * 60)
        self.assertEqual(label, "05:00")
        self.assertTrue(prefix)
        self.assertFalse(expired)
        label, prefix, expired = remaining(1_000, 1_000 + 46 * 60)
        self.assertTrue(expired)
        line = format_alert("2026-10-26T12:00:00Z", "new socket", "05:00", True, False)
        self.assertTrue(line.startswith("[T-05:00] "))
        self.assertIsNone(nudge_for("observe", 0, 10))
        self.assertIn("observation/differentiation", nudge_for("observe", 0, 61 * 60))

    def test_audit_chain_and_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = AuditLog(Path(tmp) / "audit.jsonl")
            log.append("command", "snapshot", {})
            log.append("decision", "leave uplink", {"pid": 20})
            self.assertTrue(verify(Path(tmp) / "audit.jsonl"))
        self.assertEqual(plan_uploads({"a.py": "1", "b.py": "2"}, {"a.py": "1", "b.py": ""}), ["b.py"])
        self.assertEqual(compare({"a": "1"}, {"a": "2"}), ["a"])
        rels = upload_relpaths({"HARBNGR.py": "x", "shadow/session.py": "y", "shadow/collect.py": "z"})
        self.assertEqual(rels, ["shadow/collect.py"])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mod.py"
            path.write_text("x = 1\n", encoding="utf-8")
            self.assertGreater(needed_bytes([path]), path.stat().st_size)

    def test_secret_scrub_and_embedded_runner(self):
        import os
        os.environ["SW_SSH_PASSWORD"] = "s3cret-value"
        taken = take_env(("SW_SSH_PASSWORD",))
        self.assertEqual(taken["SW_SSH_PASSWORD"], "s3cret-value")
        self.assertNotIn("SW_SSH_PASSWORD", os.environ)
        self.assertNotIn("s3cret-value", scrub("password s3cret-value", ["s3cret-value"]))
        script = build_embedded_script(ROOT, "shadow.collect", "disk_free", {"path": str(ROOT)})
        completed = subprocess.run([sys.executable, "-"], input=script, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertGreater(payload["free"], 0)

    def test_writeup_direct_blank_section(self):
        text = render_writeup({
            "fingerprint": {"label": "accept", "hostname_used": False, "score": 1},
            "baseline_ts": "2026-10-26T12:00:00Z",
            "baseline_unix": 100,
            "eradication_ts": "",
            "evidence_unix": 120,
            "topology_written": True,
            "flows_ran": True,
            "mission_unclear": False,
            "classify_note": "mission uplink is pid 20",
            "protected_touched": False,
            "operator_snapshots": 2,
            "timeline": [{"ts": "2026-10-26T12:00:00Z", "comp_phase": "initial", "text": "landed"}],
            "access_paths": [],
            "evidence": [],
            "availability": {"number": 100.0, "why": "both checks passed"},
        })
        self.assertIn("| 1 |", text)
        self.assertTrue(text.rstrip().endswith("## What you'd do differently") or text.split("## What you'd do differently", 1)[1].strip() == "")


if __name__ == "__main__":
    unittest.main()
