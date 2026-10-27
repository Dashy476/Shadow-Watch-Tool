# Analyst jump box — your live-response workstation.
FROM shadowwatch/base:latest

RUN apt-get update && apt-get install -y --no-install-recommends \
        net-tools bsdmainutils xxd \
    && rm -rf /var/lib/apt/lists/*

COPY hosts/analyst/rootfs/ /

RUN mkdir -p /home/analyst/response \
    && chown -R analyst:analyst /home/analyst
