# EDGE-02 — turns aircraft telemetry into detections for SENTINEL-01.
# The SENSOR that would feed this host is out of scope, so telemetry is local.
FROM shadowwatch/base:latest

COPY images/lab.env /etc/sw/lab.env
COPY src/edge/telemetryd.py /usr/local/bin/telemetryd.py
COPY hosts/edge-02/units/telemetryd.service /etc/systemd/system/telemetryd.service

RUN chmod 0755 /usr/local/bin/telemetryd.py \
    && mkdir -p /var/lib/edge/detections /var/log/edge \
    && systemctl enable telemetryd.service
