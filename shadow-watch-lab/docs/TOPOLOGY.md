# Team 40 practice network

This lab follows the participant guide's in-scope diagram for team number 40.
The SENSOR, the VPN gateway, the portal, CTFd, other teams, and organizer
systems are not part of the lab.

| Host | Address | Role |
|---|---|---|
| SENTINEL-01 | 10.80.40.11 | cUAS console on port 8080. Interprets detections. Forwards logs. |
| EDGE-02 | 10.80.40.12 | Turns aircraft telemetry into detections for SENTINEL-01. |
| OPS-03 | 10.80.40.13 | Retains logs forwarded from SENTINEL-01. |

```
EDGE-02 10.80.40.12
    detections (TCP 9000) --> SENTINEL-01 10.80.40.11
                                  console :8080
                                  log forwarding (TCP 1514) --> OPS-03 10.80.40.13
```

Port 9000 and port 1514 stay on the lab network. They are not published on
the host. The console is published at `http://127.0.0.1:8080`.

SSH inside each container is port 22, user `operator`, password `0per@t0r`.
From this machine:

| Host | Command |
|---|---|
| SENTINEL-01 | `ssh -p 2211 operator@127.0.0.1` |
| EDGE-02 | `ssh -p 2212 operator@127.0.0.1` |
| OPS-03 | `ssh -p 2213 operator@127.0.0.1` |

Console user `operator`, password `c0n$0le`. After sign-in, open a track to
see its path, or open `/diagnostics/export`.

EDGE-02 generates telemetry locally because the SENSOR is out of scope.
