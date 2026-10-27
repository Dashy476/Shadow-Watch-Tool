# Mission Control — receives the track feed, computes availability.
FROM shadowwatch/base:latest

COPY images/lab.env /etc/sw/lab.env
COPY src/mission-control/mission_control.py /usr/local/bin/mission_control.py
COPY hosts/mission-control/units/ /etc/systemd/system/

RUN mkdir -p /var/lib/mission-control \
    && chmod 0755 /usr/local/bin/mission_control.py \
    && systemctl enable mission-control.service
