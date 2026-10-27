```
===============================================================================
  OPERATION PHANTOM GRID — CHALLENGE 1: SHADOW WATCH
  Live-response rehearsal · VICEROY at UCCS
===============================================================================
```

> **Made with love by @j4eva. Please reach out with any issues!**

---

## SITUATION

Telemetry from **SENTINEL-01**, a cUAS sensor node on an inherited satellite
ground segment, has become erratic. The node still produces usable tracks, so
commanders have directed that it remain operational.

A partner indicator-of-compromise advisory has matched active outbound traffic
from the node. The Phantom actor is assessed to have entered through a
compromised ground-segment relay, reached the operator console, and may be
exploiting trusted connections across the sensor cluster.

Your team has live access to the environment.

## MISSION

- Preserve SENTINEL-01's mission output
- Reconstruct the intrusion
- Identify every access path
- Stop the ongoing theft
- Prevent the adversary from erasing evidence or pivoting further into the grid

## CONSTRAINT

**SENTINEL-01 must remain online.** No reimage, no reboot, no `docker restart`.
Restarting the host fails the exercise. Restarting a *service* on it is fine.

Evidence is perishable. Some of what you need exists only in memory, and the
adversary has staged something that destroys evidence on a timer. **Collect
before you eradicate.**

`Detect the unseen.`

---

## BRING THE ENVIRONMENT UP

You need **Docker** (the script can install it) and **Python 3**. Everything
runs on your own machine and tears down cleanly.

Unzip this folder, then from inside it:

**Windows**

```powershell
powershell -ExecutionPolicy Bypass -File setup.ps1
```

**macOS / Linux / WSL2**

```bash
bash setup.sh
```

The script checks Docker, starts the engine if it is stopped, builds the six
hosts (a few minutes the first time), and brings the cluster up. It is safe to
re-run.

### The clock

The adversary has staged a job that destroys evidence **45 minutes** after
SENTINEL-01 starts. That is the only deadline in the exercise; everything else
is untimed. Miss it and two gates are out of reach until you reset.

On a first run, give yourself more room:

```powershell
powershell -ExecutionPolicy Bypass -File setup.ps1 -Minutes 60
```
```bash
bash setup.sh --minutes 60
```

Anything from 5 to 240 minutes works. The clock is built into the sensor image,
so changing it rebuilds that one host (quick). Check what you have left any time
with `lab.ps1 status`.

If it fails mentioning **systemd** or **cgroups**, re-run with the fallback:

```powershell
powershell -ExecutionPolicy Bypass -File setup.ps1 -Privileged -SkipBuild
```
```bash
bash setup.sh --privileged --skip-build
```

## GET IN

Password is `analyst` on every host. Start on the analyst jump box.

```bash
ssh -p 2226 analyst@localhost     # analyst jump box — start here
ssh -p 2224 analyst@localhost     # sentinel-01  ← do NOT reboot this one
ssh -p 2222 analyst@localhost     # relay
ssh -p 2220 analyst@localhost     # console
ssh -p 2225 analyst@localhost     # sentinel-02
ssh -p 2223 analyst@localhost     # mission-control
```

Or without SSH:

```powershell
.\lab.ps1 shell analyst
```
```bash
docker exec -it sw-analyst bash -l
```

## WHERE YOUR NOTES GO

`/home/analyst/response/` exists **only on the analyst jump box**. It is the one
directory shared with your own computer — it is the `response/` folder sitting
next to this file, and it is the only place the verifier reads.

Write your fragments there as you find them:

```bash
echo "FRAG-0000 - found in /proc/<pid>/environ on sentinel-01" >> /home/analyst/response/recovered.txt
```

That path does not exist on sentinel-01, sentinel-02, the relay or the console.
Running the same command on one of those gives you
`No such file or directory` — collect your evidence wherever you find it, but
write it down from the analyst box, or straight into `response/` on your own
machine with any editor.

**Read `docs/RUNBOOK.md` for your standing orders, and
`docs/ADVISORY-IOC-2026-114.md` for the partner advisory.**

## TRACK YOUR STANDING

```powershell
.\lab.ps1 status     # availability, forged tracks, the clock
.\lab.ps1 verify     # grade the response against all eight gates
.\lab.ps1 reset      # fresh run
.\lab.ps1 down       # shut it down
```
```bash
make status
make verify
make reset
make down
```

---

## ⚠ SPOILERS

This folder contains the build context for the environment, because your machine
has to build it. **The answers are in there.** `src/` and `hosts/` contain the
planted artifacts in plaintext, and `compose/.env` contains exercise parameters.

Reading them is the same as reading the answer key. Finish the exercise first.
If you are stuck, use the progressive hints on the challenge page instead — they
are free, and they are written to unstick you without handing over the answer.

---

## SUBMIT

Graded as a **writeup** on the VICEROY site, not a flag. Submit:

1. The full output of your final `verify` run
2. A short incident report:
   - **Timeline** — what happened, in order, with timestamps
   - **Access paths** — every way in, and how you closed each one
   - **Evidence** — what you collected, and when, relative to eradication
   - **Availability** — your final number and why it landed there
   - **What you'd do differently** with more time

Partial credit is real. A 6-of-8 run with a sharp, honest report is worth more
than 8-of-8 with no analysis. In the real competition the briefing is scored as
heavily as the technical response.

---

## TROUBLESHOOTING

| Symptom | Fix |
|---|---|
| `docker: command not found` | Docker isn't installed, or open a **new** terminal after installing |
| "cannot find the file specified" / engine errors | Docker Desktop isn't running — open it and wait |
| systemd or cgroup errors on startup | Re-run with `-Privileged` / `--privileged` |
| `verify` says "no baseline recorded" | Run `lab.ps1 up` (or `make up`) to record it |
| Port already in use | Something else is on 2220–2226, 8000, 8088, or 9000 |
| Linux: permission denied on the socket | `sudo usermod -aG docker $USER`, then log out and back in |

```
VICEROY is a congressional interest item authorized by the NDAA FY2019 Sec. 1640.
```
