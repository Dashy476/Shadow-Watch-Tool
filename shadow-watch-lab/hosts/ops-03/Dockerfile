# OPS-03 — retains logs forwarded from SENTINEL-01.
FROM shadowwatch/base:latest

COPY images/lab.env /etc/sw/lab.env
COPY src/ops/syslog_vault.py /usr/local/bin/syslog-vault.py
COPY hosts/ops-03/units/syslog-vault.service /etc/systemd/system/syslog-vault.service

RUN chmod 0755 /usr/local/bin/syslog-vault.py \
    && mkdir -p /var/log/sentinel \
    && systemctl enable syslog-vault.service
