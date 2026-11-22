#!/bin/sh
# Starts mitmdump with the egress addon. Runs as root only to publish the CA certificate
# to the volume the claude container mounts, then drops to the mitmproxy user, as the
# stock image's entrypoint does.
set -e
CA_DIR=/home/mitmproxy/.mitmproxy

# Give the mitmproxy user the uid and gid that own the CA key (or, before it exists, the
# CA directory), as the stock image's entrypoint does, so a CA volume owned by another
# uid (e.g. restored from a backup) stays readable after dropping privileges. Unlike the
# stock entrypoint (usermod -g), groupmod also works for a gid that has no group yet.
f=$CA_DIR/mitmproxy-ca.pem
[ -f "$f" ] || f=$CA_DIR
groupmod -o -g "$(stat -c %g "$f")" mitmproxy
usermod -o -u "$(stat -c %u "$f")" mitmproxy >/dev/null  # hides "no changes"

# Publish only the CA certificate (not the private key in mitmproxy-ca.pem), once
# mitmproxy has created it. /ca-cert is the mitmproxy-ca-cert volume.
if [ -d /ca-cert ]; then
  ( until [ -s "$CA_DIR/mitmproxy-ca-cert.pem" ]; do sleep 1; done
    cp "$CA_DIR/mitmproxy-ca-cert.pem" /ca-cert/mitmproxy-ca-cert.pem
    chmod 644 /ca-cert/mitmproxy-ca-cert.pem ) &
fi

# The mitmproxy user's home is the CA volume (mitmproxy-ca), which holds the private key.
exec env HOME=/home/mitmproxy gosu mitmproxy \
  mitmdump --listen-port 8080 --scripts /opt/egress/egress.py --set flow_detail=0 "$@"
