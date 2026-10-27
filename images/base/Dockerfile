# Shared systemd base image for every Shadow Watch host.
#
# The point of this image is parity: inside it, iptables, chattr, systemctl,
# journalctl, sshd, cron, ps/ss/lsof and /proc all behave exactly as on a VM
# (given the capabilities granted in docker-compose.yml). selftest/ proves it.
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

# Parity self-test, available in every host: bash /opt/sw-selftest/parity.sh
COPY selftest/parity.sh /opt/sw-selftest/parity.sh
RUN chmod 0755 /opt/sw-selftest/parity.sh

# Units that make no sense in a container and only add boot noise.
RUN systemctl mask \
        systemd-remount-fs.service \
        sys-fs-fuse-connections.mount \
        sys-kernel-config.mount \
        systemd-logind.service \
        getty.target \
        console-getty.service \
    && systemctl enable ssh cron

# One shared analyst account. The exercise is about state and evidence, not
# password guessing.
RUN useradd -m -s /bin/bash analyst \
    && echo 'analyst:analyst' | chpasswd \
    && usermod -aG sudo analyst \
    && printf 'analyst ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/analyst \
    && chmod 0440 /etc/sudoers.d/analyst

RUN mkdir -p /var/run/sshd \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config \
    && grep -q '^UseDNS' /etc/ssh/sshd_config || echo 'UseDNS no' >> /etc/ssh/sshd_config

# Real systemd as PID 1 — this is what makes systemctl/journalctl one-to-one.
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
