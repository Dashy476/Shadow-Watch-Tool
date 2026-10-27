# Operator console — hop two. Holds the sensor cluster's SSH trust key and the
# reused credential the attacker took from the relay.
FROM shadowwatch/base:latest

COPY src/chain/console-sync.sh /usr/local/sbin/console-sync.sh
COPY keys/sensor_trust /root/.ssh/sensor_trust
COPY keys/relay_reuse.pub /root/.ssh/authorized_keys
COPY hosts/console/rootfs/ /

RUN chmod 0755 /usr/local/sbin/console-sync.sh \
    && chmod 0700 /root/.ssh \
    && chmod 0600 /root/.ssh/sensor_trust /root/.ssh/authorized_keys
