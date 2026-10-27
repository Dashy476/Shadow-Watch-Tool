# SENTINEL-01 — the sensor under attack. Runs the real track generator.
# The adversary is already resident: the implant, its persistence, and the
# evidence-wipe timer are all part of the delivered (compromised) state.
FROM shadowwatch/base:latest

ARG WIPE_AFTER=2700

COPY images/lab.env /etc/sw/lab.env
COPY src/trackgen/trackd.py /usr/local/bin/trackd.py
COPY src/attacker/shadow_agent.py /usr/local/sbin/shadow_agent.py
COPY src/attacker/sw-respawn.sh /usr/local/sbin/sw-respawn.sh
COPY src/attacker/sw-wipe.sh /usr/local/sbin/sw-wipe.sh
COPY hosts/sentinel-01/rootfs/ /
COPY hosts/sentinel-01/units/ /etc/systemd/system/
COPY keys/sensor_trust /root/.ssh/sensor_trust
COPY keys/sensor_trust.pub /root/.ssh/authorized_keys

RUN chmod 0755 /usr/local/bin/trackd.py /usr/local/sbin/shadow_agent.py \
    && chmod 0755 /usr/local/sbin/sw-respawn.sh /usr/local/sbin/sw-wipe.sh \
    && mkdir -p /var/log/sentinel /run/sentinel \
    && chmod 0700 /root/.ssh \
    && chmod 0600 /root/.ssh/sensor_trust /root/.ssh/authorized_keys \
    && chmod 0644 /etc/cron.d/sw-respawn \
    && sed -i "s/@WIPE@/${WIPE_AFTER}/" /etc/systemd/system/logrotate-guard.timer \
    && systemctl enable trackd.service sysmon-telemetry.service logrotate-guard.timer
