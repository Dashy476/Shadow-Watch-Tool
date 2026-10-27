# Analyst jump box

You are on the live-response workstation. Mission Control is at
`http://mission-control:8000` (JSON availability), the sensors are on the
`sensor` network, and the relay is on `edge`.

Start with the student runbook: `docs/RUNBOOK.md` on the host mount, or the copy
the facilitator handed you. Write your recovered fragments and your report into
`/home/analyst/response/` (mounted to `response/` on the host).

Useful enough to remember under time pressure:

```bash
ss -tnp                 # who is this box talking to?
ps -ef                  # is there a process that should not be here?
curl -s mission-control:8000 | python3 -m json.tool
journalctl -u <unit> -n 50
```

Do **not** reboot or recreate `sentinel-01`. The commanders directed that it
remain operational.
