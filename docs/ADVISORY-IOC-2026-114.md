# IOC Advisory — SHADOW WATCH / case ADVS-2B88

**Distribution:** partner sharing arrangement — internal use only.
**Status:** active. Matched to outbound traffic observed in the sector grid.

## Summary

A partner range reports a multi-stage intrusion against sensor grids of our
pattern. Access is obtained through an exposed relay service, then pivoted with
reused operator credentials to the console, then across the console's trusted
connections into the sensor cluster itself. Once resident, the actor steals the
live track feed and tampers with detection, so the sensor keeps reporting
"healthy" while losing coverage.

Theft is **live exfiltration**, running alongside the legitimate uplink. Both
flows are plain TCP carrying track-shaped JSON — do not cut the uplink.

## Indicators

| Indicator | Type | Notes |
|---|---|---|
| `relay` port `4443/tcp` | C2 endpoint | Exfiltration sink. Payloads are JSON with a `feed` field and a `token` field. |
| `sysmon-telemetry` | service name | Persistence masquerading as telemetry. |
| `logrotate-guard` | timer name | Disguised wipe job. Shreds logs after boot. |
| HMAC value `forged` | forged track | Injected into the track feed; fails authentication. |
| `sensor_trust` | key name | Shared sensor-cluster key enabling lateral movement. |

## Analyst note

Two things in the recovered samples look like track data and only one of them
belongs on the wire. Confirm the direction, the destination, and the
authentication before you touch either.

Case reference: **ADVS-2B88**.
