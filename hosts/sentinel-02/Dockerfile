# SENTINEL-02 — the pivot target. Trusts SENTINEL-01 over the sensor cluster's
# shared key. Clean on delivery; only the pivot plants a foothold here.
FROM shadowwatch/base:latest

COPY src/attacker/pivot_plant.sh /usr/local/sbin/pivot_plant.sh
COPY keys/sensor_trust /root/.ssh/sensor_trust
COPY keys/sensor_trust.pub /root/.ssh/authorized_keys

RUN chmod 0755 /usr/local/sbin/pivot_plant.sh \
    && mkdir -p /opt/sentinel \
    && chmod 0700 /root/.ssh \
    && chmod 0600 /root/.ssh/sensor_trust /root/.ssh/authorized_keys
