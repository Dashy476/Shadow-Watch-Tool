# Compromised relay — the entry point. Runs the C2 sink and the outward half of
# the re-entry chain, and exposes a small web service (the initial-access surface).
FROM shadowwatch/base:latest

COPY images/lab.env /etc/sw/lab.env
COPY src/c2/c2sink.py /usr/local/bin/c2sink.py
COPY src/chain/edge-sync.sh /usr/local/sbin/edge-sync.sh
COPY keys/relay_reuse /root/.ssh/relay_reuse
COPY hosts/relay/rootfs/ /
COPY hosts/relay/units/ /etc/systemd/system/

RUN chmod 0755 /usr/local/bin/c2sink.py /usr/local/sbin/edge-sync.sh \
    && mkdir -p /var/lib/c2 \
    && chmod 0700 /root/.ssh \
    && chmod 0600 /root/.ssh/relay_reuse \
    && systemctl enable c2sink.service relay-web.service edge-sync.service
