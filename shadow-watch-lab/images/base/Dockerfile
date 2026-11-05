# Shared systemd base for the Phantom Grid practice hosts.
#
# Inside the container, iptables, chattr, systemctl, journalctl, sshd, cron,
# ps/ss and /proc behave as they do on a VM. selftest/parity.sh checks that.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    container=docker \
    LANG=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
        systemd systemd-sysv \
        openssh-server \
        cron \
        sudo passwd \
        python3 \
        iptables iproute2 iputils-ping netcat-openbsd tcpdump curl ca-certificates \
        e2fsprogs attr \
        procps psmisc lsof less vim-tiny file \
    && rm -rf /var/lib/apt/lists/*

COPY selftest/parity.sh /opt/sw-selftest/parity.sh
RUN chmod 0755 /opt/sw-selftest/parity.sh

RUN systemctl mask \
        systemd-remount-fs.service \
        sys-fs-fuse-connections.mount \
        sys-kernel-config.mount \
        systemd-logind.service \
        getty.target \
        console-getty.service \
    && systemctl enable ssh cron

# Guide SSH account. The password is the exercise host password from the
# participant guide, used only so this local lab matches that document.
# Ubuntu already has a group named operator, so do not create a matching group.
RUN useradd -m -s /bin/bash -N operator \
    && echo 'operator:0per@t0r' | chpasswd \
    && usermod -aG sudo operator \
    && printf 'operator ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/operator \
    && chmod 0440 /etc/sudoers.d/operator

RUN mkdir -p /var/run/sshd /etc/sw \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config \
    && grep -q '^UseDNS' /etc/ssh/sshd_config || echo 'UseDNS no' >> /etc/ssh/sshd_config

STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
