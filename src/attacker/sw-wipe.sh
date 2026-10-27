#!/bin/bash
# Disguised under the name of a log-rotation guard, this is the evidence-wipe job.
# Its systemd timer fires EXERCISE_WIPE_AFTER seconds after SENTINEL-01 boots.
#
# It shreds the track log and the staged export on sentinel-01, then drops a
# completion marker. If it runs before the analyst collects the staged export,
# the SPOOL flag fragment is gone for good.
set -u

shred -u /var/log/sentinel/*.log 2>/dev/null
shred -u /dev/shm/.cache/track_export.json 2>/dev/null
shred -u /var/lib/c2/*.jsonl 2>/dev/null

mkdir -p /var/lib
date -Is > /var/lib/.guard_done

logger -t logrotate-guard "log rotation complete"
