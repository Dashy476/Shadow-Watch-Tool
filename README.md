# Shadow Watch

Blue-team tool for Operation Phantom Grid (SENTINEL-01 style sensor nodes). It collects volatile evidence, tells two lookalike outbound flows apart, and writes the graded report. It does not exploit anything.

HARBNGR runs on the operator machine and is the only place Paramiko is used. Code that runs on the node is Python stdlib.

The SSH connect, retry, and host-key handling are the kept part of HARBNGR from `recon-cve-cli`. Attack-chain generation, Exploit-DB, Vulners, Ollama, multi-host scans, and MITRE attack mapping are not in this tree. The detection math is adapted from Guilded Guardian `gg_t2`, `gg_t3`, `gg_t10`, and `gg_t17`, and it only reads.

## Install

```powershell
cd <path-to-shadow-watch>
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Python 3.10 or newer. Paramiko is the only third-party package.

## Secrets

Set these in the environment. HARBNGR removes them from the environment as soon as it starts. Do not put the password on the command line.

```powershell
$env:SW_SSH_HOST = "10.0.0.5"
$env:SW_SSH_PORT = "22"
$env:SW_SSH_USER = "operator"
$env:SW_SSH_PASSWORD = "..."
# or a key file, instead of a password
$env:SW_SSH_KEY = "C:\keys\lab.key"
# optional jump box
$env:SW_SSH_JUMP = "jumpuser@10.0.0.2"
```

A missing password is prompted with `getpass` and is not written to the audit log.

If access is a Sliver pivot, forward a local port and point HARBNGR at it. For an SSH jump, set `SW_SSH_JUMP`. This tool does not speak Sliver. Every connection, including a pivot, is fingerprinted. A weak score stops the run.

## What a run does

```powershell
python HARBNGR.py
```

Optional flags: `--host`, `--port`, `--user`, `--jump`, `--remote-bunker`, `--local-bunker`, `--interval`, `--profile`, `--iocs`, `--replay`.

Interval is clamped to 2–5 seconds.

### Phase 1 — landing

Human gate: none until the copy finishes. Then the tool waits.

1. Connect with exponential backoff (5 tries). On handshake failure it probes TCP ports 22, 2222, 2022, 80, 443, 8080, 8443, and 53, reports them, and stops. The probe only connects and closes.
2. Find `python3` by absolute path and record the shell name. Later remote commands are `python3 /full/path/...` with no bash syntax.
3. Fingerprint from `/proc`. Hostname is ignored. Score uses pipeline process name, parent (not a shell), a track-output path, and a listen or established socket. `accept` is >= 0.70. `wrong host / ambiguous` or `wrong host` stops the run before any module is copied. Edit `profiles/sentinel01.json` if the target uses different process or path names, then run again.
4. Check free space on the remote bunker. Default remote path: `/var/bunker/shadow-watch`. Copy stdlib modules once, via a `.partial` name and rename. A second run skips files whose hash matches.
5. Exit the copy. Collectors are not started.

Press Enter to start Phase 2. The 45-minute evidence timer does **not** start at connect. It starts at the Phase 2 baseline. The wipe is typically 45 minutes after the node started, so do not sit on this prompt.

### Phase 2 — observe

A background loop pulls a snapshot every 2–5 seconds over the same SSH session (keepalive, one transport, reconnect on loss). Each snapshot is saved under `bunker/snapshots/` on the operator machine. Snapshot JSON is not left on the node. Sockets are read first, then the process tree and file descriptors, then interesting maps (`/dev/shm`, tmpfs, hidden names, deleted paths), then environment for standout processes only.

Alerts print only when something changed: new PID, new socket, new map, or a service that is new, missing, or moved relative to the baseline. The node-agent process itself is ignored so the loop does not alert on itself.

Topology updates on the same loop and writes `bunker/topology/adjacency.txt`. A Graphviz `.dot` file is written only when the `dot` binary is on the operator PATH. Edges keep their first-seen time.

### Phase 3 — flows

```text
shadow> flows
```

Type `YES` to score outbound flows. The four axes are payload shape, process ancestry, destination behavior, and JSON shape. JSON is used only when the baseline shows JSON on a process that also has a non-local socket. Otherwise that axis is silent and the other weights are renormalized. Weights live at the top of `shadow/differentiator.py`.

Each flow gets `block`, `watch`, or `leave alone`, plus a confidence percent and the reasons. Nothing is sent to a live socket.

If the pipeline flow cannot be separated cleanly, every `block` is downgraded to `watch` and containment will not run destructive actions.

Put indicators in `iocs.txt`, one IP or `ip:port` per line. Lines starting with `#` are ignored. A missing file means no IOC matches.

### Phase 4 — contain

```text
shadow> contain
shadow> do c1
```

`contain` only prints suggestions, safest uptime risk first:

| Risk | Action |
| --- | --- |
| 1 | drop one connection (`ss -K`) |
| 2 | `kill -TERM` one pid above 1 |
| 3 | `systemctl restart` one unit |
| 4 | `chmod 600` one absolute path |

A suggestion that matches the mission uplink socket, the core tracker pid, its ancestors, or its unit is refused. Reboot, reimage, shutdown, and docker are never suggested and the allowlist rejects them. Service restart is allowed. Host reboot is not.

`do c1` prints the command and the rollback note, then waits for `YES`. It saves a pre-action snapshot first. The first accepted action is the eradication time used in the writeup. If the mission uplink or tracker is missing afterward, the rollback note is printed again.

### Phase 5 — writeup

```text
shadow> writeup
```

Writes `bunker/writeup.md` and prints it. Fill in **What you'd do differently** by hand. The eight gates are:

1. Fingerprint accepted without using hostname
2. Volatile baseline captured before eradication
3. Topology recorded
4. Outbound flows classified
5. Mission uplink and core tracker not targeted
6. Evidence pulled back to the operator bunker
7. Evidence collected inside the 45-minute window
8. Writeup sections present

Other commands: `status`, `alerts`, `topo`, `phase <name>`, `restore`, `help`, `quit`.

`phase <name>` logs a divider when the competition drops a new phase. Later timeline lines nest under it.

`restore` copies the modules again. Use it if the bunker copy was changed.

## Timer, budgets, integrity, audit

The main line shows the evidence timer as `mm:ss` once the baseline exists. At 10:00 or less, every alert is prefixed with the remaining time. At zero the prefix is `T-00:00 EXPIRED`. Collection does not stop by itself.

Soft nudges, once per phase: landing/snapshot/topology 15 min, observation/differentiation 60 min, containment 45 min, writeup 30 min.

On startup the tool hashes its own modules. If they differ from `bunker/module_manifest.json`, type `INTEGRITY ACK` to continue. The same check runs before `flows`, `contain`, `do`, and on the remote bunker copy.

`bunker/audit.jsonl` is a hash-chained log of commands, snapshots, and decisions. It is local only.

A dropped SSH session reconnects with the same backoff and resumes from the last saved state. Type `YES` at the resume prompt on the next launch. Put the password in the environment again; it is not stored in the state file. A reconnect is fingerprinted again and will stop if the score is no longer `accept`.

## Replay a disk image or saved snapshots

```powershell
python HARBNGR.py --replay <path-to-snaps> --local-bunker <output-dir>
```

Reads snapshot JSON, runs the same scoring, and writes suggestions plus a writeup. It does not connect and it does not run containment.

## Tests

```powershell
python -m unittest discover -s tests -v
```

No SSH and no Paramiko required for the tests.

## Layout

| Path | Role |
| --- | --- |
| `HARBNGR.py` | Operator entry |
| `shadow/session.py` | Paramiko session, retry, SFTP, TCP probe |
| `shadow/node_agent.py` | On-node entry: `snapshot`, `space`, `hashes`, `run` |
| `shadow/collect.py` | `/proc` snapshot |
| `shadow/fingerprint.py` | Host score |
| `shadow/snapshot.py` | Change detection |
| `shadow/topology.py` | Adjacency list |
| `shadow/plugins/` | IPC, beacon, temporal, trust |
| `shadow/differentiator.py` | Two-flow score |
| `shadow/containment.py` | Suggestions and the exec allowlist |
| `shadow/timeline.py` | Gates and writeup |
| `profiles/sentinel01.json` | Fingerprint substrings and thresholds |

## Never

- Reboot, reimage, or restart the host.
- Write to a live socket, including the mission uplink.
- Run containment without `YES`.
- Treat the hostname string as proof of the target node.
