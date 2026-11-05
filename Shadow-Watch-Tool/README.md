# Shadow Watch

Blue-team tool for Operation Phantom Grid (SENTINEL-01 style sensor nodes). It collects volatile evidence, tells two lookalike outbound flows apart, and writes the graded report. It does not exploit anything.

HARBNGR runs on the operator machine and is the only place Paramiko is used. Code that runs on the node is Python stdlib.

The SSH connect, retry, and host-key handling are the kept part of HARBNGR from `recon-cve-cli`. Attack-chain generation, Exploit-DB, Vulners, Ollama, multi-host scans, and MITRE attack mapping are not in this tree. The detection math is adapted from Guilded Guardian `gg_t2`, `gg_t3`, `gg_t10`, and `gg_t17`, and it only reads.

## Competition

Team **Bits_N_Bytes**. The window is **November 6, 2026, 6:00 PM–9:00 PM ET** (three hours).

Scoring is CTF challenge completion plus detection uptime. Completion time is the tiebreaker when two teams have the same score.

Access is WireGuard, then SSH. There is no jump host. SSH is port **22**, user **operator**.

1. Install the WireGuard client from [wireguard.com/install](https://www.wireguard.com/install/).
2. Open [https://swportal.shadowwatch.online/](https://swportal.shadowwatch.online/), log in, open your profile, and download the WireGuard configuration. Credentials are in the participant guide, not in this repo.
3. Import that configuration and enable the tunnel.
4. After the tunnel is up, open [https://ctf.shadowwatch.online](https://ctf.shadowwatch.online), register, and join team **Bits_N_Bytes**. The registration code and team password are in the participant guide.

| Host | Address | Role |
| --- | --- | --- |
| SENTINEL-01 | 10.80.40.11 | cUAS web console on port 8080, including a diagnostics export for authenticated users. Interprets detections from EDGE-02. |
| EDGE-02 | 10.80.40.12 | Turns aircraft telemetry into detections for SENTINEL-01. |
| OPS-03 | 10.80.40.13 | Retains logs forwarded from SENTINEL-01. |

The SENSOR that feeds EDGE-02 is out of scope. So are the access portal, CTFd, other teams, and the organizers' host. Use the portal and CTFd only to connect and to submit. Do not investigate them.

`hosts.txt` lists the three hosts as `IP port user label`. `python start.py` offers to preflight SSH and sudo on each of them before launch, then writes `hosts.env` and `.env.sentinel`, `.env.edge`, and `.env.ops`. Those files hold the password, so they are gitignored. Each launch is tagged with `--host-label` and writes that host's bunker: `bunker-sentinel`, `bunker-edge`, or `bunker-ops`.

After the three writeups exist:

```powershell
python HARBNGR.py --merge
```

That writes `merged-report.md`. Every evidence line names the host it came from.

Fingerprint profiles are `profiles/sentinel01.json`, `profiles/edge02.json`, and `profiles/ops03.json`. Accept threshold is 0.70 and the hostname is ignored. The `look_for` lists are placeholders until the first connect shows the real process names. On SENTINEL-01 the `x` sweep also reports the console listener on port 8080, redacted session or token variable names, and any established connection to 10.80.40.12 or 10.80.40.13 that is not the detection flow or the log-forwarding flow. The differentiator treats the OPS-03 log-forward as a known-benign baseline and weighs destination more heavily than payload, ancestry, or JSON, because the theft flow mimics that baseline.

## Quick start

1. Install **Python 3.10 or newer** (Windows: tick "Add Python to PATH").
2. From this folder run:

```powershell
python start.py          # Linux / macOS / WSL: python3 start.py
```

That is the whole install. On first run the launcher builds a private `.venv`, installs `requirements.txt`, asks for the target (IP, port, username, password, and a jump host or key file if you need one), runs a **preflight**, and launches HARBNGR with the right flags. Next runs: press ENTER to launch, or use `python start.py -y` for zero prompts.

Preflight checks, in order: scanner files present, SSH library installed, target port reachable, SSH login works, and `sudo` gives root (needed for `/root`). Problems are reported before the scan starts, with a retry/edit menu. If the port is dead it also lists the ports where SSH is actually listening.

| Flag | What it does |
| --- | --- |
| `-y`, `--yes` | No prompts: saved target, preflight every `hosts.txt` entry, launch. Resumes any existing session. |
| `--edit` | Change target or credentials. |
| `--reset` | Forget the saved target and re-run setup. |
| `--fast` | Skip the splash animation. |
| `--art NAME` | Use `art/NAME.txt` as the splash if it fits the window. |
| `--no-check` | Skip preflight (not recommended). |
| `--skip-integrity` | Delete `bunker/module_manifest.json` before launch so the INTEGRITY ACK check does not fire. The check is on by default. |
| `--prepare` | Download dependency wheels to `wheels/` for offline installs. |
| `--no-venv` | Use the current Python instead of `.venv`. |

Any other flag is passed to `HARBNGR.py` (`--interval`, `--profile`, `--iocs`, `--replay`, ...).

**No internet on the competition network?** On a connected machine of the same OS and Python version, run `python start.py --prepare` once. It downloads the dependency wheels into `wheels/`. Copy the whole folder over and the launcher installs from there, offline.

**Old session found?** You choose Resume or New. New copies `bunker/` to `bunker_backup_<timestamp>/` before wiping, so evidence is never lost to a stray keypress.

The launcher saves the target in `.env` (never commit it; the launcher adds it to `.gitignore` if missing). Delete `.env` when the event is over.

On startup, `start.py` also updates bash history in the operator's `~/.bashrc`. It does not change the target. The settings are a large history (`HISTSIZE=100000`, `HISTFILESIZE=200000`), timestamps (`HISTTIMEFORMAT='%F %T '`), append on exit (`shopt -s histappend`), no silent dropping of commands that start with a space (`HISTCONTROL` empty, `HISTIGNORE` unset), and a `PROMPT_COMMAND` that appends each new command to the history file. Lines for those variables are replaced in place. Every other line in the file stays. If the file is already correct, the launcher says nothing. If it writes a change, it prints the path and `source ~/.bashrc` for any Git Bash window that is already open. A new Git Bash window loads it when `~/.bash_profile` sources `~/.bashrc`.

### Practice lab

This tree is the competition scanner. Defaults are SENTINEL-01 at `operator@10.80.40.11` port 22, over WireGuard, with no jump host. A separate Docker practice lab is not included here.

## Install

`python start.py` does all of this for you. Manual steps, if you prefer:

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

Jump-box extras, if needed: `SW_SSH_JUMP_PASSWORD` (defaults to the target password), `SW_SSH_JUMP_PORT`, `SW_SSH_JUMP_USER`. The launcher asks for a jump host, key file and jump password during setup and sets these for you.

If access is a Sliver pivot, forward a local port and point HARBNGR at it. For an SSH jump, set `SW_SSH_JUMP`. This tool does not speak Sliver. Every connection, including a pivot, is fingerprinted. A weak score stops the run.

Both `start.py` and `HARBNGR.py` put remote modules in `/home/$USER/shadow-bunker`, where `$USER` is the SSH username. The login account can write that directory. Pass `--remote-bunker` to use a different path. There is no separate default for a bare `HARBNGR.py` run.

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
4. Check free space on the remote bunker. The default path is `/home/$USER/shadow-bunker` (`$USER` is the SSH username) whether you start from `start.py` or `HARBNGR.py`. Pass `--remote-bunker` to use another directory. Copy stdlib modules once, via a `.partial` name and rename. A second run skips files whose hash matches. `shadow/shellhist.py` is operator-only and is not part of that copy.
5. Exit the copy. Collectors are not started.

Press Enter to start Phase 2. The 45-minute evidence timer does **not** start at connect. It starts at the Phase 2 baseline. The wipe is typically 45 minutes after the node started, so do not sit on this prompt.

### Phase 2 — observe

A background loop pulls a snapshot every 2–5 seconds over the same SSH session (keepalive, one transport, reconnect on loss). Each snapshot is saved under `bunker/snapshots/` on the operator machine. Snapshot JSON is not left on the node. Sockets are read first, then the process tree and file descriptors, then interesting maps (`/dev/shm`, tmpfs, hidden names, deleted paths), then environment for standout processes only.

Alerts print only when something changed: new PID, new socket, new map, or a service that is new, missing, or moved relative to the baseline. The node-agent process itself is ignored so the loop does not alert on itself.

Topology updates on the same loop and writes `bunker/topology/adjacency.txt`. A Graphviz `.dot` file is written only when the `dot` binary is on the operator PATH. Edges keep their first-seen time.

### One-shot IOC sweep: `x`

```text
shadow> x
```

Prints a colour-coded dashboard in one pass. It runs read-only commands over the open SSH session with `sudo`, so it can see root-owned paths that the node agent's allowlist does not cover. It never writes to the node.

| Section | What it checks |
| --- | --- |
| Open listening ports | Listening sockets from the latest snapshot |
| Potential malicious processes | Standout processes, suspicious keywords (`wipe`, `shadow`, `sw-`, `guard`, ...), and executables under `/tmp`, `/dev/shm`, `/opt`, `/srv`, `/usr/local/sbin`, `/home` |
| Active root directory scrub | Files under `/usr/local/sbin`, `/opt`, `/srv`, `/tmp`, `/dev/shm`, `/etc/systemd/system`; flags dormant payloads such as `sw-wipe.sh`, `sw-respawn.sh`, `shadow_agent.py`, `parity.sh` |
| Potential C2 IPs | Outbound flows classified by the differentiator, with theft score and engine action |
| Evasive persistence | systemd timers and services compared with an Ubuntu baseline (catches look-alikes such as `logrotate-guard.*`) |
| SSH directory contents | Every file in `/root/.ssh` and `/home/*/.ssh` with permissions, owner, size, and `ssh-keygen -lf` fingerprint |

Needs root. If `sudo` did not work, the SSH section says "Scan ran as '<user>', not root". The sudo password is the same one used to log in; with key login you are asked for it once. A file in `.ssh` that is private-key sized and not named `id_*`, or an `authorized_keys` entry you do not recognise, is worth investigating: compare fingerprints against keys you own.

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

Other commands: `status`, `alerts`, `topo`, `phase <name>`, `restore`, `hunt <term>`, `mute`, `help`, `quit`. `hunt` searches saved snapshots. Add `--regex` to treat the term as a regular expression, and `--scope` to limit the search to one snapshot field, for example `hunt "flag{.*}" --regex --scope environ`. `mute` hides routine background logs. Both still record what they see.

`phase <name>` logs a divider when the competition drops a new phase. Later timeline lines nest under it.

`restore` copies the modules again. Use it if the bunker copy was changed.

## Timer, budgets, integrity, audit

The main line shows the evidence timer as `mm:ss` once the baseline exists. At 10:00 or less, every alert is prefixed with the remaining time. At zero the prefix is `T-00:00 EXPIRED`. Collection does not stop by itself.

Soft nudges, once per phase: landing/snapshot/topology 15 min, observation/differentiation 60 min, containment 45 min, writeup 30 min.

On startup the tool hashes its own modules and compares them with `bunker/module_manifest.json`. The check is on by default. `start.py` keeps that file. If the saved manifest and the current modules differ, type `INTEGRITY ACK` to continue. The first launch, when no manifest exists yet, writes one and does not prompt. `--skip-integrity` is the opt-out: `start.py` deletes the manifest before launch so that prompt does not fire. The same check runs before `flows`, `contain`, `do`, and on the remote bunker copy.

`bunker/audit.jsonl` is a hash-chained log of commands, snapshots, and decisions. It is local only.

A dropped SSH session reconnects with the same backoff and resumes from the last saved state. Type `YES` at the resume prompt on the next launch. Put the password in the environment again; it is not stored in the state file. A reconnect is fingerprinted again and will stop if the score is no longer `accept`.

## Replay a disk image or saved snapshots

```powershell
python HARBNGR.py --replay <path-to-snaps> --local-bunker <output-dir>
```

Reads snapshot JSON, runs the same scoring, and writes suggestions plus a writeup. It does not connect and it does not run containment.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Preflight: "no response" | WireGuard tunnel up? Right IP and port 22? The launcher lists ports where SSH is listening; press `e` to change the port. |
| Preflight: "wrong username or password" | Press `e` and re-enter. The same password is used for `sudo`. |
| Preflight: "sudo failed" | Account is not a sudoer, or the password is wrong. The scan runs but is blind to `/root`. |
| "paramiko missing" | Let the launcher install it, or run `python start.py --prepare` on a connected machine for offline use. |
| Linux: `.venv` could not be created | `sudo apt install python3-venv`, or use `--no-venv`. |
| `setup.sh: $'\r': command not found` | A shell script has Windows line endings. Run `sed -i 's/\r$//' <file>`, or see `.gitattributes`. |
| Splash art garbled | Use Windows Terminal; classic `cmd.exe` fonts lack the braille glyphs. |

## Tests

```powershell
python -m unittest discover -s tests -v
```

No SSH and no Paramiko required for the tests.

## Layout

| Path | Role |
| --- | --- |
| `start.py` | Launcher: bash history, bootstrap, host preflight, launch |
| `hosts.txt` | In-scope hosts: `IP port user label` |
| `HARBNGR.py` | Operator entry. `--host-label` selects the bunker. `--merge` writes the combined report |
| `profiles/sentinel01.json` | SENTINEL-01 fingerprint. Placeholders until first connect |
| `profiles/edge02.json` | EDGE-02 fingerprint |
| `profiles/ops03.json` | OPS-03 fingerprint |
| `shadow/grid.py` | Team host map, bunker names, `hosts.txt` parser |
| `shadow/scope.py` | SENTINEL-01 console, token-name, and peer checks used by `x` |
| `shadow/shellhist.py` | Operator `~/.bashrc` history settings. Not copied to the node |
| `bunker-sentinel/` | Local evidence for SENTINEL-01. `bunker-edge/` and `bunker-ops/` are the other two |
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
| `art/` | Optional splash art (`art/NAME.txt`) |
| `wheels/` | Optional offline dependency cache (`--prepare`) |

## Never

- Reboot, reimage, or restart the host.
- Write to a live socket, including the mission uplink.
- Run containment without `YES`.
- Treat the hostname string as proof of the target node.
- Commit `.env`, `bunker/`, or any saved credentials.
