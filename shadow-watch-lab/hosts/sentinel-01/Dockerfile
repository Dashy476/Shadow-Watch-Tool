# SENTINEL-01 — cUAS console, detection ingest, log forwarding.
FROM shadowwatch/base:latest

COPY images/lab.env /etc/sw/lab.env
COPY images/console.passwd /etc/sw/console.passwd
COPY src/sentinel/cuas_console.py /usr/local/bin/cuas-console.py
COPY src/sentinel/log_forward.py /usr/local/bin/log-forward.py
COPY hosts/sentinel-01/units/cuas-console.service /etc/systemd/system/cuas-console.service
COPY hosts/sentinel-01/units/log-forward.service /etc/systemd/system/log-forward.service

RUN chmod 0755 /usr/local/bin/cuas-console.py /usr/local/bin/log-forward.py \
    && chmod 0640 /etc/sw/console.passwd \
    && mkdir -p /var/lib/sentinel/tracks /var/lib/sentinel/diagnostics/export /var/log/sentinel \
    && systemctl enable cuas-console.service log-forward.service
