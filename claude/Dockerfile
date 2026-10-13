# Claude Code workstation image for container_server. Build on the host (Podman builds natively;
# Compose builds need BuildKit, which Podman's Docker API doesn't support):
#
#   podman build --pull -t localhost/claude-code:latest claude/
#
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash git openssh-client ca-certificates curl ripgrep jq tmux less nano vim procps xz-utils \
      python3 python3-pip python3-venv pipx \
 && rm -rf /var/lib/apt/lists/*
# ttyd isn't packaged in Debian; use its static release build.
RUN set -e; base=https://github.com/tsl0922/ttyd/releases/download/1.7.7; cd /tmp; \
    curl -fsSLO --retry 3 $base/ttyd.x86_64; curl -fsSL --retry 3 $base/SHA256SUMS | grep ' ttyd.x86_64$' | sha256sum -c -; \
    install -m 755 ttyd.x86_64 /usr/local/bin/ttyd; rm ttyd.x86_64
# Node.js LTS from nodejs.org (Debian's is 20, which ignores HTTP(S)_PROXY). With
# NODE_USE_ENV_PROXY=1 (24+), fetch and http(s) in node/npm/npx go through the proxy.
RUN set -e; v=24.21.0; tar=node-v$v-linux-x64.tar.xz; base=https://nodejs.org/dist/v$v; cd /tmp; \
    curl -fsSLO --retry 3 $base/$tar; curl -fsSL --retry 3 $base/SHASUMS256.txt | grep " $tar\$" | sha256sum -c -; \
    tar xJf $tar -C /usr/local --strip-components=1 --exclude='*.md' --exclude=LICENSE; rm $tar; \
    node --version; npm --version
ENV NODE_USE_ENV_PROXY=1
# GitHub CLI (official release; Debian's lags). Its token is a placeholder the proxy
# replaces with the real one (see GH_TOKEN in compose.yaml).
RUN set -e; v=2.102.0; tar=gh_${v}_linux_amd64.tar.gz; \
    base=https://github.com/cli/cli/releases/download/v$v; cd /tmp; \
    curl -fsSLO --retry 3 $base/$tar; curl -fsSL --retry 3 $base/gh_${v}_checksums.txt | grep " $tar\$" | sha256sum -c -; \
    tar xzf $tar; install -m 755 gh_${v}_linux_amd64/bin/gh /usr/local/bin/gh; \
    cp -r gh_${v}_linux_amd64/share/man/man1 /usr/local/share/man/ 2>/dev/null || true; rm -rf gh_${v}_linux_amd64 $tar; \
    gh --version | head -1
# LeakTK secret scanner.
RUN set -e; v=0.3.10; tar=leaktk-$v-linux-x86_64.tar.xz; \
    base=https://github.com/leaktk/leaktk/releases/download/v$v; cd /tmp; \
    curl -fsSLO --retry 3 $base/$tar; curl -fsSL --retry 3 $base/leaktk_${v}_checksums.txt | grep " $tar\$" | sha256sum -c -; \
    mkdir x; tar xJf $tar -C x; install -m 755 x/leaktk /usr/local/bin/leaktk; \
    install -Dm 644 x/completions/bash/leaktk /usr/share/bash-completion/completions/leaktk; rm -rf x $tar
# Attach to (or start) a tmux session running bash, so closing the tab keeps it alive.
RUN printf '%s\n' '#!/bin/sh' 'cd "$HOME/work" && exec tmux new-session -A -s main bash -l' \
      > /usr/local/bin/session \
 && chmod 755 /usr/local/bin/session
RUN useradd --create-home --uid 1000 --shell /bin/bash rmonk
# Debian's /etc/profile resets PATH in login shells; put ours back.
RUN echo 'PATH="$HOME/.safe-chain/shims:$HOME/.safe-chain/bin:$HOME/.local/bin:$PATH"' \
      > /etc/profile.d/10-user-path.sh
USER rmonk
# safe-chain shims come first so npm/pip/uv/... are checked in every shell,
# including the non-interactive ones Claude Code runs commands in.
# NPM_CONFIG_PREFIX: `npm install -g` goes to ~/.local (bin/ is on PATH) and so lives in
# the home volume, instead of root-owned /usr/local.
ENV SHELL=/bin/bash \
    LANG=C.UTF-8 \
    NPM_CONFIG_PREFIX=/home/rmonk/.local \
    PATH=/home/rmonk/.safe-chain/shims:/home/rmonk/.safe-chain/bin:/home/rmonk/.local/bin:$PATH
# Native install into ~/.local, owned by rmonk, so Claude Code updates itself.
# /home/rmonk is a volume: Docker seeds it from the image on first deploy,
# and later updates persist there (rebuilding the image won't downgrade them).
RUN curl -fsSL --retry 3 https://claude.ai/install.sh | bash && claude --version \
 && mkdir -p /home/rmonk/work
# Aikido safe-chain: malware/age checks for npm, pip, uv, etc. Installer pinned by checksum.
RUN set -e; v=1.5.25; cd /tmp; \
    curl -fsSL --retry 3 https://github.com/AikidoSec/safe-chain/releases/download/$v/install-safe-chain.sh -o isc.sh; \
    echo "83069f6db4215cccf6a26bdd6e65a5c2366b9d24322b2d5d2862d47385e56682  isc.sh" | sha256sum -c -; \
    sh isc.sh --ci; rm isc.sh
WORKDIR /home/rmonk/work
# compose.yaml overrides this entrypoint to add the login (--credential) and styling.
ENTRYPOINT ["ttyd", "--writable", "--port", "7681", "-t", "titleFixed=claude", "/usr/local/bin/session"]
