#!/bin/sh
# Starts mitmdump with the egress addon. Runs as root only to publish the CA certificate
# to the volume the claude container mounts, then drops to the mitmproxy user, as the
# stock image's entrypoint does.
set -e
CA_DIR=/home/mitmproxy/.mitmproxy

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
