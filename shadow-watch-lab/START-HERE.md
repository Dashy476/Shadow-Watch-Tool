# Operation Phantom Grid practice lab

Team **Bits_N_Bytes**, team number **40**. This folder is the three-host
mission network from the participant guide. It is a local stand-in for the
WireGuard segment `10.80.40.0/24`.

There is no relay, no second sentinel, no jump box, and no planted implant.
The SENSOR that feeds EDGE-02 is out of scope, so EDGE-02 generates aircraft
telemetry itself.

```
EDGE-02  10.80.40.12
    detections --> SENTINEL-01  10.80.40.11   console :8080
                       |
                       +-- log forwarding --> OPS-03  10.80.40.13
```

Details are in `docs/TOPOLOGY.md`.

## Bring it up

Docker and Python 3. From this folder:

```powershell
powershell -ExecutionPolicy Bypass -File setup.ps1
```

```bash
bash setup.sh
```

The first build takes a few minutes. Re-running is safe.

If startup fails with a systemd or cgroup error:

```powershell
powershell -ExecutionPolicy Bypass -File setup.ps1 -Privileged -SkipBuild
```

```bash
bash setup.sh --privileged --skip-build
```

## Get in

Inside each container, SSH is port 22. This machine publishes those ports on
localhost, because Docker Desktop cannot give the host the three lab addresses.

| Host | Lab address | From this machine |
|---|---|---|
| SENTINEL-01 | 10.80.40.11:22 | `ssh -p 2211 operator@127.0.0.1` |
| EDGE-02 | 10.80.40.12:22 | `ssh -p 2212 operator@127.0.0.1` |
| OPS-03 | 10.80.40.13:22 | `ssh -p 2213 operator@127.0.0.1` |

SSH user `operator`, password `0per@t0r`.

The console is `http://127.0.0.1:8080`. User `operator`, password `c0n$0le`.
Sign in, open a track to see its path, or open the diagnostics export.

A shell without SSH:

```powershell
.\lab.ps1 shell sentinel-01
```

## Scanner

The competition scanner is `D:\Python\Shadow-Watch-Tool`. It reads `hosts.txt`
beside `start.py`, which lists the real addresses on port 22.

For one host in this lab, start the scanner, answer `n` at the preflight
prompt, and set the target to `127.0.0.1`, port `2211`, `2212`, or `2213`,
user `operator`.

`hosts.practice.txt` in this folder is the same three targets. To preflight
all of them, copy it over the scanner's `hosts.txt` for the session, then put
the real file back before the event. Type the SSH password when asked. Do not
store it in the scanner repo.

Portal, CTFd, and team-site passwords stay in the participant guide. They are
not used here.

## Standing

```powershell
.\lab.ps1 status
.\lab.ps1 verify
.\lab.ps1 reset
.\lab.ps1 down
```

`status` and `verify` check the same thing: the three containers are up, the
console export has a detection from the last 30 seconds, and OPS-03 has
retained a forwarded track line. That is the detection path. There is no
fragment grade and no wipe timer.

## Troubleshooting

| Symptom | What to do |
|---|---|
| `docker: command not found` | Install Docker Desktop, then open a new terminal |
| Engine errors | Open Docker Desktop and wait until it is running |
| systemd or cgroup errors | Re-run setup with `-Privileged` or `--privileged` |
| Port already in use | Free 2211, 2212, 2213, or 8080 |
| Linux socket permission denied | `sudo usermod -aG docker $USER`, then sign in again |
