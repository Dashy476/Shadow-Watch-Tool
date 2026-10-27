#!/bin/bash
# Parity self-test — run INSIDE a Shadow Watch host to prove it behaves like a VM
# for everything the exercise touches.
#
#   docker exec sw-sentinel-01 bash /opt/sw-selftest/parity.sh
#   (or: lab.ps1 selftest)
set -u

fails=0
ok() {
  local desc="$1"; shift
  if bash -c "$*" >/dev/null 2>&1; then
    printf '  PASS  %s\n' "$desc"
  else
    printf '  FAIL  %s\n' "$desc"
    fails=$((fails + 1))
  fi
}

echo "parity self-test on $(hostname)"
ok "iptables can add/list/remove a rule" 'iptables -N SWTEST && iptables -F SWTEST && iptables -X SWTEST && iptables -L -n'
ok "systemd is PID 1 and running"      'test "$(cat /proc/1/comm)" = systemd && systemctl is-system-running | grep -Eq "running|degraded"'
ok "systemctl enable state readable"   'systemctl is-enabled ssh'
ok "journalctl reads the journal"      'journalctl -n 1 --no-pager'
ok "sshd is active"                    'systemctl is-active ssh || pgrep -x sshd'
ok "cron is active"                    'systemctl is-active cron'
ok "chattr +i enforces immutability"   't=/tmp/swtest; : > $t; chattr +i $t && ! echo x >> $t && chattr -i $t && rm -f $t'
ok "ss lists sockets"                  'ss -tn'
ok "ps lists processes"                'ps -ef'
ok "/proc is readable"                 'test -r /proc/1/status'
ok "SUID bit is meaningful"            'f=/tmp/swsuid; cp /bin/true $f; chmod u+s $f; test -u $f; rm -f $f'
ok "user/UID semantics present"        'id analyst'
ok "sudo works"                        'sudo -n true'

echo
if [ "$fails" -eq 0 ]; then
  echo "RESULT: full parity — everything the exercise touches behaves as on a VM."
  exit 0
fi
echo "RESULT: $fails check(s) failed."
exit 1
