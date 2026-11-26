# Claude Code workstation image for container_server, built by GitHub Actions on pushes to main
# and pulled from ghcr.io/rmonk/claude-code. To build it locally instead (Compose builds need
# BuildKit, which Podman's Docker API doesn't support):
#
#   podman build --pull -t ghcr.io/rmonk/claude-code:latest claude/
#
# CI builds it for linux/amd64 and linux/arm64. The release downloads below pick their
# binary from `dpkg --print-architecture` (amd64 or arm64), mapped to each project's naming.
#
# Tool versions are the `ARG *_VERSION` defaults below (one before each install step). The
# claude/versions script shows which are out of date (`check`), rewrites them to the latest
# releases (`bump [tool...]`), or prints --build-arg flags for a one-off latest build without
# editing anything (`build-args [tool...|all]`):
#
#   podman build --pull $(claude/versions build-args gh leaktk) -t ghcr.io/rmonk/claude-code:latest claude/
#
# Go and the two Go tools built from source. trzsz and leaktk publish release binaries built with
# an older Go and older x/* modules (Trivy: 1 critical + 29 high per trzsz binary, 8 high in leaktk),
# so they're built here from their release tags with this Go and those modules raised to their
# latest versions. The module downloads are verified against go.sum and the Go checksum database.
ARG GO_VERSION=1.27.4
ARG LEAKTK_VERSION=0.3.13
ARG TRZSZ_VERSION=1.2.0
FROM docker.io/library/golang:${GO_VERSION}-trixie AS gotools
ARG LEAKTK_VERSION
ARG TRZSZ_VERSION
ENV CGO_ENABLED=0 GOFLAGS=-trimpath GOTOOLCHAIN=local
# trzsz: `tsz <file>` downloads through the browser terminal and `trz` uploads (ttyd's
# enableTrzsz option in compose.yaml). Works inside tmux.
RUN set -e; git clone -q --depth 1 --branch "v$TRZSZ_VERSION" https://github.com/trzsz/trzsz-go /src/trzsz; \
    cd /src/trzsz; \
    go get golang.org/x/text@latest golang.org/x/image@latest golang.org/x/sys@latest golang.org/x/term@latest \
      github.com/klauspost/compress@latest; \
    go mod tidy; mkdir -p /out; go build -ldflags "-s -w" -o /out/ ./cmd/trz ./cmd/tsz ./cmd/trzsz
# LeakTK secret scanner, with the version stamps its Makefile sets.
RUN set -e; git clone -q --depth 1 --branch "v$LEAKTK_VERSION" https://github.com/leaktk/leaktk /src/leaktk; \
    cd /src/leaktk; commit=$(git rev-parse HEAD); \
    go get golang.org/x/crypto@latest golang.org/x/text@latest golang.org/x/net@latest golang.org/x/sys@latest \
      github.com/klauspost/compress@latest; \
    go mod tidy; \
    go build -ldflags "-s -w -X=github.com/leaktk/leaktk/pkg/version.Version=$LEAKTK_VERSION -X=github.com/leaktk/leaktk/pkg/version.Commit=$commit" \
      -o /out/leaktk .; \
    cp completions/bash/leaktk /out/leaktk.bash-completion; \
    /out/leaktk version

FROM debian:trixie-slim
# upgrade: Debian security fixes newer than the base image (e.g. zlib1g).
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends \
      bash git openssh-client ca-certificates curl ripgrep jq tmux less nano vim procps xz-utils make \
      python3 python3-pip python3-venv pipx \
      python3-yaml python3-requests python3-dateutil python3-jinja2 python3-tabulate \
      python3-jsonschema python3-bs4 python3-lxml python3-openpyxl python3-pandas \
      podman buildah crun \
      file unzip zip bzip2 zstd tree xxd bsdextrautils patch rsync openssl gnupg sqlite3 \
      fd-find shellcheck bc gettext-base moreutils lsof git-lfs \
      bind9-dnsutils netcat-openbsd iproute2 \
      build-essential skopeo shfmt \
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
ARG TTYD_VERSION=1.7.7
RUN set -e; arch=$(dpkg --print-architecture); case $arch in amd64) a=x86_64;; arm64) a=aarch64;; *) echo "unsupported arch: $arch" >&2; exit 1;; esac; \
    base=https://github.com/tsl0922/ttyd/releases/download/$TTYD_VERSION; cd /tmp; \
    curl -fsSLO --retry 3 $base/ttyd.$a; curl -fsSL --retry 3 $base/SHA256SUMS | grep " ttyd.$a\$" | sha256sum -c -; \
    install -m 755 ttyd.$a /usr/local/bin/ttyd; rm ttyd.$a
# Node.js LTS from nodejs.org (Debian's is 20, which ignores HTTP(S)_PROXY). With
# NODE_USE_ENV_PROXY=1 (24+), fetch and http(s) in node/npm/npx go through the proxy.
ARG NODE_VERSION=26.13.1
RUN set -e; arch=$(dpkg --print-architecture); case $arch in amd64) a=x64;; arm64) a=arm64;; *) echo "unsupported arch: $arch" >&2; exit 1;; esac; \
    v=$NODE_VERSION; tar=node-v$v-linux-$a.tar.xz; base=https://nodejs.org/dist/v$v; cd /tmp; \
    curl -fsSLO --retry 3 $base/$tar; curl -fsSL --retry 3 $base/SHASUMS256.txt | grep " $tar\$" | sha256sum -c -; \
    tar xJf $tar -C /usr/local --strip-components=1 --exclude='*.md' --exclude=LICENSE; rm $tar; \
    node --version; npm --version
ENV NODE_USE_ENV_PROXY=1
# Go from go.dev (Debian's lags the toolchain gate/ needs), checksum from go.dev/dl/?mode=json.
# GOPATH and the build cache default to ~/go and ~/.cache, on the home volume.
ARG GO_VERSION
RUN set -e; arch=$(dpkg --print-architecture); case $arch in amd64|arm64) ;; *) echo "unsupported arch: $arch" >&2; exit 1;; esac; \
    v=$GO_VERSION; tar=go$v.linux-$arch.tar.gz; cd /tmp; \
    sum=$(curl -fsSL --retry 3 'https://go.dev/dl/?mode=json&include=all' \
      | jq -r --arg f "$tar" 'first(.[].files[] | select(.filename == $f) | .sha256) // empty'); \
    [ -n "$sum" ] || { echo "no checksum for $tar on go.dev" >&2; exit 1; }; \
    curl -fsSLO --retry 3 https://go.dev/dl/$tar; echo "$sum  $tar" | sha256sum -c -; \
    tar xzf $tar -C /usr/local; rm $tar; /usr/local/go/bin/go version
ENV PATH=/usr/local/go/bin:$PATH
# GitHub CLI (official release; Debian's lags). Its token is a placeholder the proxy
# replaces with the real one (see GH_TOKEN in compose.yaml).
ARG GH_VERSION=2.105.0
RUN set -e; arch=$(dpkg --print-architecture); case $arch in amd64|arm64) ;; *) echo "unsupported arch: $arch" >&2; exit 1;; esac; \
    v=$GH_VERSION; d=gh_${v}_linux_$arch; tar=$d.tar.gz; \
    base=https://github.com/cli/cli/releases/download/v$v; cd /tmp; \
    curl -fsSLO --retry 3 $base/$tar; curl -fsSL --retry 3 $base/gh_${v}_checksums.txt | grep " $tar\$" | sha256sum -c -; \
    tar xzf $tar; install -m 755 $d/bin/gh /usr/local/bin/gh; \
    cp -r $d/share/man/man1 /usr/local/share/man/ 2>/dev/null || true; rm -rf $d $tar; \
    gh --version | head -1
# Workflow and Dockerfile linters, and mikefarah's yq (Debian's yq is the Python jq wrapper).
# actionlint runs shellcheck on `run:` blocks; zizmor audits workflows for security problems.
ARG ACTIONLINT_VERSION=1.7.12
RUN set -e; arch=$(dpkg --print-architecture); case $arch in amd64|arm64) ;; *) echo "unsupported arch: $arch" >&2; exit 1;; esac; \
    v=$ACTIONLINT_VERSION; tar=actionlint_${v}_linux_$arch.tar.gz; \
    base=https://github.com/rhysd/actionlint/releases/download/v$v; cd /tmp; \
    curl -fsSLO --retry 3 $base/$tar; curl -fsSL --retry 3 $base/actionlint_${v}_checksums.txt | grep " $tar\$" | sha256sum -c -; \
    tar xzf $tar actionlint; install -m 755 actionlint /usr/local/bin/actionlint; rm actionlint $tar; \
    actionlint --version | head -1
# zizmor publishes no checksum file; the sha256 per arch is pinned from the GitHub release asset
# digests (claude/versions updates them with the version).
ARG ZIZMOR_VERSION=1.33.1
ARG ZIZMOR_SHA256_AMD64=3e6a301c7a820a2501915f5a9de8c0486da82bdec7965f068477538a98743d43
ARG ZIZMOR_SHA256_ARM64=aa487c792a7cbbe86e4f8dccd3b66de33b3b51813c090aaa0842d7ea08a3fc35
RUN set -e; arch=$(dpkg --print-architecture); case $arch in amd64) a=x86_64; sum=$ZIZMOR_SHA256_AMD64;; arm64) a=aarch64; sum=$ZIZMOR_SHA256_ARM64;; *) echo "unsupported arch: $arch" >&2; exit 1;; esac; \
    v=$ZIZMOR_VERSION; tar=zizmor-$a-unknown-linux-gnu.tar.gz; cd /tmp; \
    curl -fsSLO --retry 3 https://github.com/zizmorcore/zizmor/releases/download/v$v/$tar; echo "$sum  $tar" | sha256sum -c -; \
    mkdir zizmor; tar xzf $tar -C zizmor; install -m 755 "$(find zizmor -type f -name zizmor)" /usr/local/bin/zizmor; rm -rf zizmor $tar; \
    zizmor --version
ARG HADOLINT_VERSION=2.15.1
RUN set -e; arch=$(dpkg --print-architecture); case $arch in amd64) a=x86_64;; arm64) a=arm64;; *) echo "unsupported arch: $arch" >&2; exit 1;; esac; \
    v=$HADOLINT_VERSION; f=hadolint-linux-$a; base=https://github.com/hadolint/hadolint/releases/download/v$v; cd /tmp; \
    curl -fsSLO --retry 3 $base/$f; curl -fsSL --retry 3 $base/checksums.sha256 | grep " \*\?$f\$" | sed 's/ \*/  /' | sha256sum -c -; \
    install -m 755 $f /usr/local/bin/hadolint; rm $f; hadolint --version
# yq's checksums file lists every hash; checksums_hashes_order says which column is SHA-256.
ARG YQ_VERSION=4.54.3
RUN set -e; arch=$(dpkg --print-architecture); case $arch in amd64|arm64) ;; *) echo "unsupported arch: $arch" >&2; exit 1;; esac; \
    v=$YQ_VERSION; f=yq_linux_$arch; base=https://github.com/mikefarah/yq/releases/download/v$v; cd /tmp; \
    col=$(curl -fsSL --retry 3 $base/checksums_hashes_order | grep -nx 'SHA-256' | cut -d: -f1); \
    [ -n "$col" ] || { echo "no SHA-256 column in yq checksums" >&2; exit 1; }; \
    sum=$(curl -fsSL --retry 3 $base/checksums | awk -v f=$f -v c=$((col + 1)) '$1 == f { print $c }'); \
    [ -n "$sum" ] || { echo "no checksum for $f" >&2; exit 1; }; \
    curl -fsSLO --retry 3 $base/$f; echo "$sum  $f" | sha256sum -c -; \
    install -m 755 $f /usr/local/bin/yq; rm $f; yq --version
# LeakTK and trzsz, built in the gotools stage above.
COPY --from=gotools /out/leaktk /out/trz /out/tsz /out/trzsz /usr/local/bin/
COPY --from=gotools /out/leaktk.bash-completion /usr/share/bash-completion/completions/leaktk
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
# Aikido safe-chain: malware/age checks for npm, pip, uv, etc. Installer pinned by checksum
# (no checksum file is published; claude/versions takes it from the GitHub release asset digest).
ARG SAFE_CHAIN_VERSION=1.5.29
ARG SAFE_CHAIN_SHA256=e9bfa05430bca0efcf26e5a0f06d09b9da8cc21de2e0ffab03f512dde649ebbe
RUN set -e; v=$SAFE_CHAIN_VERSION; cd /tmp; \
    curl -fsSL --retry 3 https://github.com/AikidoSec/safe-chain/releases/download/$v/install-safe-chain.sh -o isc.sh; \
    echo "$SAFE_CHAIN_SHA256  isc.sh" | sha256sum -c -; \
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
