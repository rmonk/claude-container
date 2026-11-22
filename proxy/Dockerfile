# The egress proxy: mitmproxy plus the addon that enforces egress/egress.toml (egress.py), built
# and published like the claude and gate images (ghcr.io/rmonk/claude-proxy). The tests run
# during the build, so an image with a broken addon is never pushed. To build it locally:
#
#   podman build --pull -t ghcr.io/rmonk/claude-proxy:latest proxy/
#
ARG MITMPROXY_VERSION=12.3.1
FROM docker.io/mitmproxy/mitmproxy:${MITMPROXY_VERSION}

ENV PYTHONDONTWRITEBYTECODE=1 \
    # Otherwise the connection log (every host claude reaches) sits in a buffer.
    PYTHONUNBUFFERED=1

COPY egress.py test_egress.py /opt/egress/
RUN cd /opt/egress && python3 -m unittest -v test_egress && rm test_egress.py
COPY --chmod=755 entrypoint.sh /usr/local/bin/egress-proxy

# Starts as root to publish the CA certificate, then drops to the mitmproxy user.
ENTRYPOINT ["/usr/local/bin/egress-proxy"]
