# Claude Code workstation image for container_server, built by GitHub Actions on pushes to main
# and pulled from ghcr.io/rmonk/claude-code. To build it locally instead (Compose builds need
# BuildKit, which Podman's Docker API doesn't support):
#
#   podman build --pull -t ghcr.io/rmonk/claude-code:latest claude/
#
# CI builds it for linux/amd64 and linux/arm64. The release downloads below pick their
# binary from `dpkg --print-architecture` (amd64 or arm64), mapped to each project's naming.
#
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash git openssh-client ca-certificates curl ripgrep jq tmux less nano vim procps xz-utils make \
      python3 python3-pip python3-venv pipx \
      python3-yaml python3-requests python3-dateutil python3-jinja2 python3-tabulate \
      python3-jsonschema python3-bs4 python3-lxml python3-openpyxl python3-pandas \
      podman buildah crun \
      file unzip zip bzip2 zstd tree xxd bsdextrautils patch rsync openssl gnupg sqlite3 \
      fd-find shellcheck bc gettext-base moreutils lsof git-lfs \
      bind9-dnsutils netcat-openbsd iproute2 \
      build-essential \
 && ln -s /usr/bin/fdfind /usr/local/bin/fd \
 && rm -rf /var/lib/apt/lists/*
# Rootless image builds (podman build / buildah) inside this container. The user runs with
# no-new-privs and no capabilities, so newuidmap can't work: with no /etc/subuid entries
# podman maps only the user's own uid (files in images all end up owned by root, hence
# ignore_chown_errors). A fresh /proc can't be mounted here, so RUN steps use chroot
# isolation (which bind-mounts /proc) on the host network (whose only way out is the
# proxy); `podman run` doesn't work. Layers go in ~/.local/share/containers, on the home volume.
RUN : > /etc/subuid && : > /etc/subgid \
 && printf '%s\n' '[storage]' 'driver = "overlay"' '' '[storage.options.overlay]' 'ignore_chown_errors = "true"' \
      > /etc/containers/storage.conf \
 && printf '%s\n' '[containers]' 'netns = "host"' 'cgroups = "disabled"' '' \
      '[engine]' 'cgroup_manager = "cgroupfs"' 'events_logger = "file"' \
      > /etc/containers/containers.conf
ENV BUILDAH_ISOLATION=chroot
# ttyd isn't packaged in Debian; use its static release build.
RUN set -e; arch=$(dpkg --print-architecture); case $arch in amd64) a=x86_64;; arm64) a=aarch64;; *) echo "unsupported arch: $arch" >&2; exit 1;; esac; \
    base=https://github.com/tsl0922/ttyd/releases/download/1.7.7; cd /tmp; \
    curl -fsSLO --retry 3 $base/ttyd.$a; curl -fsSL --retry 3 $base/SHA256SUMS | grep " ttyd.$a\$" | sha256sum -c -; \
    install -m 755 ttyd.$a /usr/local/bin/ttyd; rm ttyd.$a
# Node.js LTS from nodejs.org (Debian's is 20, which ignores HTTP(S)_PROXY). With
# NODE_USE_ENV_PROXY=1 (24+), fetch and http(s) in node/npm/npx go through the proxy.
RUN set -e; arch=$(dpkg --print-architecture); case $arch in amd64) a=x64;; arm64) a=arm64;; *) echo "unsupported arch: $arch" >&2; exit 1;; esac; \
    v=24.21.0; tar=node-v$v-linux-$a.tar.xz; base=https://nodejs.org/dist/v$v; cd /tmp; \
    curl -fsSLO --retry 3 $base/$tar; curl -fsSL --retry 3 $base/SHASUMS256.txt | grep " $tar\$" | sha256sum -c -; \
    tar xJf $tar -C /usr/local --strip-components=1 --exclude='*.md' --exclude=LICENSE; rm $tar; \
    node --version; npm --version
ENV NODE_USE_ENV_PROXY=1
# Go from go.dev (Debian's lags the toolchain gate/ needs), checksum from go.dev/dl/?mode=json.
# GOPATH and the build cache default to ~/go and ~/.cache, on the home volume.
RUN set -e; arch=$(dpkg --print-architecture); case $arch in \
      amd64) sum=ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5;; \
      arm64) sum=3f4227ce7b206a513e794f1393adb473a07b46e94d18bd15d1c684bbb7319797;; \
      *) echo "unsupported arch: $arch" >&2; exit 1;; esac; \
    v=1.26.10; tar=go$v.linux-$arch.tar.gz; cd /tmp; \
    curl -fsSLO --retry 3 https://go.dev/dl/$tar; echo "$sum  $tar" | sha256sum -c -; \
    tar xzf $tar -C /usr/local; rm $tar; /usr/local/go/bin/go version
ENV PATH=/usr/local/go/bin:$PATH
# GitHub CLI (official release; Debian's lags). Its token is a placeholder the proxy
# replaces with the real one (see GH_TOKEN in compose.yaml).
RUN set -e; arch=$(dpkg --print-architecture); case $arch in amd64|arm64) ;; *) echo "unsupported arch: $arch" >&2; exit 1;; esac; \
    v=2.102.0; d=gh_${v}_linux_$arch; tar=$d.tar.gz; \
    base=https://github.com/cli/cli/releases/download/v$v; cd /tmp; \
    curl -fsSLO --retry 3 $base/$tar; curl -fsSL --retry 3 $base/gh_${v}_checksums.txt | grep " $tar\$" | sha256sum -c -; \
    tar xzf $tar; install -m 755 $d/bin/gh /usr/local/bin/gh; \
    cp -r $d/share/man/man1 /usr/local/share/man/ 2>/dev/null || true; rm -rf $d $tar; \
    gh --version | head -1
# LeakTK secret scanner.
RUN set -e; arch=$(dpkg --print-architecture); case $arch in amd64) a=x86_64;; arm64) a=arm64;; *) echo "unsupported arch: $arch" >&2; exit 1;; esac; \
    v=0.3.10; tar=leaktk-$v-linux-$a.tar.xz; \
    base=https://github.com/leaktk/leaktk/releases/download/v$v; cd /tmp; \
    curl -fsSLO --retry 3 $base/$tar; curl -fsSL --retry 3 $base/leaktk_${v}_checksums.txt | grep " $tar\$" | sha256sum -c -; \
    mkdir x; tar xJf $tar -C x; install -m 755 x/leaktk /usr/local/bin/leaktk; \
    install -Dm 644 x/completions/bash/leaktk /usr/share/bash-completion/completions/leaktk; rm -rf x $tar
# trzsz: `tsz <file>` downloads through the browser terminal and `trz` uploads (ttyd's
# enableTrzsz option in compose.yaml). Works inside tmux.
RUN set -e; arch=$(dpkg --print-architecture); case $arch in amd64) a=x86_64;; arm64) a=aarch64;; *) echo "unsupported arch: $arch" >&2; exit 1;; esac; \
    v=1.2.0; d=trzsz_${v}_linux_$a; tar=$d.tar.gz; \
    base=https://github.com/trzsz/trzsz-go/releases/download/v$v; cd /tmp; \
    curl -fsSLO --retry 3 $base/$tar; curl -fsSL --retry 3 $base/trzsz_${v}_checksums.txt | grep " $tar\$" | sha256sum -c -; \
    tar xzf $tar; install -m 755 $d/trz $d/tsz $d/trzsz /usr/local/bin/; rm -rf $d $tar
# Attach to (or start) a tmux session running bash, so closing the tab keeps it alive.
RUN printf '%s\n' '#!/bin/sh' 'cd "$HOME/work" && exec tmux new-session -A -s main bash -l' \
      > /usr/local/bin/session \
 && chmod 755 /usr/local/bin/session
# The home template: Claude Code and safe-chain are installed into /opt/home-skel as
# uid 1000. The user itself is created when the container starts (init-user, named by
# CLAUDE_USER), which copies this template into its home volume on first use.
RUN groupadd --gid 1000 skel && useradd --uid 1000 --gid 1000 --create-home --home-dir /opt/home-skel skel
# Debian's /etc/profile resets PATH in login shells; put ours back.
RUN echo 'PATH="$HOME/.safe-chain/shims:$HOME/.safe-chain/bin:$HOME/.local/bin:$HOME/go/bin:/usr/local/go/bin:$PATH"' \
      > /etc/profile.d/10-user-path.sh
USER skel
ENV SHELL=/bin/bash \
    LANG=C.UTF-8
# Native install into ~/.local, owned by uid 1000, so Claude Code updates itself in the
# home volume (rebuilding the image won't downgrade it). The launcher symlink is made
# relative so the template works under any home directory.
RUN curl -fsSL --retry 3 https://claude.ai/install.sh | bash \
 && ln -sfn "$(readlink ~/.local/bin/claude | sed "s|^$HOME/.local/|../|")" ~/.local/bin/claude \
 && ~/.local/bin/claude --version \
 && mkdir -p ~/work
# Aikido safe-chain: malware/age checks for npm, pip, uv, etc. Installer pinned by checksum.
RUN set -e; v=1.5.25; cd /tmp; \
    curl -fsSL --retry 3 https://github.com/AikidoSec/safe-chain/releases/download/$v/install-safe-chain.sh -o isc.sh; \
    echo "83069f6db4215cccf6a26bdd6e65a5c2366b9d24322b2d5d2862d47385e56682  isc.sh" | sha256sum -c -; \
    sh isc.sh --ci; rm isc.sh; rm -rf ~/.npm/_logs
USER root
# The template stays owned by uid 1000; the placeholder account goes, freeing the uid
# for CLAUDE_USER.
RUN userdel skel
COPY --chmod=755 init-user /usr/local/bin/init-user
# Without an override (compose.yaml has one) this drops to the user and opens a shell.
# Services that reuse the image with their own entrypoint (the signer) set user: 1000.
ENTRYPOINT ["/usr/local/bin/init-user"]
CMD ["/usr/local/bin/session"]
