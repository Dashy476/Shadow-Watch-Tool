# RUNBOOK — Shadow Watch live-response exercise

You are the duty analyst for the sector grid. The partner IOC advisory
(`ADVISORY-IOC-2026-114.md`) has matched active outbound traffic, and the
track telemetry has gone erratic.

## Standing orders (from the brief — these are hard rules)

1. **`SENTINEL-01` must remain online.** No reimage, no reboot, no
   `docker restart`, no `docker compose up --force-recreate`. Restarting the host
   fails the exercise. Restarting a *service* on it is fine.
2. **Live response only.** The commands you need run against the running system.
3. **Collect volatile evidence before you eradicate anything.** Order of
   volatility is a real drill: `ss`, `ps`, `/proc/<pid>/*`, the malicious
   process's environment. Kill first and you destroy the evidence your report
   needs.
4. **Cut the trust, not just the process.** Killing the malware is not
   eradication. If the actor has a way back in, it comes back. Map the access
   paths before you decide you are done — and assume there is more than one.

## Access

`lab.ps1 up` then `lab.ps1 shell <host>` for a shell, or SSH from the host:

| Host | SSH |
|---|---|
| analyst | `ssh -p 2226 analyst@localhost` (password `analyst`) |
| sentinel-01 | `ssh -p 2224 analyst@localhost` |
| sentinel-02 | `ssh -p 2225 analyst@localhost` |
| console | `ssh -p 2220 analyst@localhost` |
| relay | `ssh -p 2222 analyst@localhost` |
| mission-control | `ssh -p 2223 analyst@localhost` |

Mission Control's availability JSON is at `http://localhost:8000`.

## What "done" means

There is a clock. A disguised job is armed to shred evidence 45 minutes after
`SENTINEL-01` boots (set your own with `setup.ps1 -Minutes 60` /
`setup.sh --minutes 60`). Watch it with:

```bash
systemctl list-timers logrotate-guard.timer --no-pager
```

### Objectives

1. **Keep the tracker alive.** Availability is authenticated tracks received ÷
   tracks expected. It must stay at or above the threshold, and the feed must not
   go quiet for more than a short window.
2. **Find the blinding.** One sector is not reporting even though the sensor
   looks healthy. Fix the root cause.
3. **Explain the forged tracks.** Something is injecting records that fail
   authentication. Identify them.
4. **Cut the exfil without cutting the uplink.** Two similar outbound flows; stop
   the theft, keep the feed.
5. **Eradicate every foothold.** Leave nothing that lets the actor come back —
   including on the second sensor.
6. **Recover the evidence fragments** the actor left behind and write them to
   `/home/analyst/response/recovered.txt`, one per line, each with a note of
   where you found it and when. Some of them will not survive the clock.
   That path exists only on the analyst jump box — it is the `response/` folder
   on your own machine. Writing it from a sensor fails with
   `No such file or directory`.

## Deliverables

- `response/recovered.txt` — the recovered fragments (one per line), each with a
  note of where it was found.
- `response/report.md` — the intrusion narrative: the three hops in, the
  persistence, the blinding, the forgery, the exfil, the wipe job, and the trust
  you cut.

## Verify

```powershell
lab.ps1 verify
```

All gates passing prints the flag.
