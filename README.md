# Claude Code container

A browser terminal (ttyd, behind a passkey login) that opens a bash shell as your chosen user inside
a container with Claude Code installed. All of the container's outbound HTTP(S) goes through a
mitmproxy sidecar that you can later use to block hosts or inject credentials.

```
network "claude"
  tsbridge ──▶ gate:8080 (passkey login)
                 │ /tty/ttyd.sock (shared volume, no port)
                 ▼
  claude (ttyd → tmux → bash, user $CLAUDE_USER)
     │ HTTPS_PROXY
     ▼
  proxy:8080 (mitmproxy) ──▶ internet
```

## Deploy

The stack runs with `podman compose` on container_server. The images are built with `podman build`
on the host, not by Compose: Compose builds go through BuildKit, which Podman's Docker API doesn't
support (`failed to dial gRPC: unable to upgrade to h2c, received 404`).

1. Copy this directory to container_server and build the images there, as the user that will run
   `podman compose`:

   ```sh
   podman build --pull -t localhost/claude-code:latest claude/
   podman build --pull -t localhost/claude-gate:latest gate/
   ```

2. Create the env files from the `.example` files (see [Env files](#how-it-behaves)):

   ```sh
   cp .env.example .env
   for f in claude gate signer; do cp $f.env.example $f.env; done
   cp egress/egress.example.toml egress/egress.toml
   ```

   Set `GATE_ORIGIN` in `.env` to the URL you'll open the terminal at, e.g.
   `https://claude.<your-tailnet>.ts.net`, and `CLAUDE_USER` to the login name you want (default
   `claude`; see [The user](#the-user)). The egress policy in `egress/egress.toml` starts out
   injecting `GITHUB_TOKEN` for GitHub (see [The proxy](#the-proxy)). Optionally set `GIT_USER_NAME`/`GIT_USER_EMAIL` in `claude.env`. For the first deploy, put a setup code in `gate.env`: `GATE_SETUP_CODE=<output of openssl rand -hex 16>`.
   Then start the stack with `podman compose up -d`.
3. tsbridge publishes the gate on your tailnet at `GATE_ORIGIN`. Open
   `/auth/register` there, enter the setup code and create a passkey (see [Passkeys](#passkeys)).
   Then run `claude` and log in with your subscription via `/login`.

"Redeploy" below means running `podman compose up -d` again in this directory; Compose recreates
whatever changed. To rebuild (new OS packages, ttyd/leaktk versions, gate changes), repeat step 1, then
redeploy.

## How it behaves

- **Access**: sign in with a passkey; see [Passkeys](#passkeys).
- **Env files**: `.env` is the Compose project environment, used for `${…}` substitution in
  `compose.yaml` and loaded into the **proxy** (e.g. `GITHUB_TOKEN`). `claude.env` is loaded only into
  the **claude** container, `signer.env` only into the signer and `gate.env` only into the gate.
  The egress policy is `egress/egress.toml` (see [The proxy](#the-proxy)). Start each from its
  `.example` file. Edit the env files, then redeploy; the proxy picks up changes to `egress.toml` by
  itself. All of these are gitignored, so `compose.yaml` stays the same everywhere.
- **Look**: ttyd's font, size and Catppuccin-style theme are set in the `entrypoint` in `compose.yaml`.
  The tmux settings, including the status bar and true color, are in the `tmux_conf`
  config. Changing either needs only a redeploy, not a rebuild. `LANG=C.UTF-8` is required: without it
  tmux replaces Claude Code's Unicode characters with `_`.
- **Copy/paste**: drag to select, and ttyd copies to your clipboard (✂ flashes). Paste with
  Ctrl+Shift+V (plain Ctrl+V sends a literal ^V; in Claude Code it pastes images). tmux mouse mode is off,
  so to scroll back use `Ctrl-b [`, then PgUp or the arrows, and `q` to exit.
- **Persistence**: `/home/$CLAUDE_USER` is the `claude-home` volume. It holds Claude Code itself (`~/.local`), its
  login and settings, your shell history, and `~/work`. Closing the tab leaves the tmux session running;
  reopening the page reattaches.
- **Updates**: Claude Code is a native install owned by the user, so it auto-updates (or run `claude update`).
  Updates live in the volume. Rebuilding the image only refreshes the OS packages, because the home is
  filled from the image's template only on first use.
- **Adding tools**: the user has no sudo, and anything outside its home is lost when the container is
  recreated. For system packages, add them to `claude/Dockerfile`, rebuild and redeploy. Per-user tools
  persist in the home volume: `pipx`/`uv tool install`, binaries in `~/.local/bin`, and `npm install -g`
  (`NPM_CONFIG_PREFIX` points it at `~/.local`).
- **Tooling**: git, Node.js 24 LTS (from nodejs.org, with `NODE_USE_ENV_PROXY=1` so `fetch`/`https` in Node
  scripts use the proxy), Python/pip/venv/pipx, ripgrep, jq, vim, plus:
  - **GitHub CLI** (`gh`): its `GH_TOKEN` is a placeholder that the proxy swaps for the real
    `GITHUB_TOKEN`, so `gh` works without the token ever entering the container.
  - **[Aikido safe-chain](https://github.com/AikidoSec/safe-chain)** (1.5.25): installed in CI mode, so its
    PATH shims wrap npm, npx, yarn, pnpm, bun, pip, uv, poetry, pipx and others in every shell, including
    the non-interactive shells Claude Code runs commands in. It blocks known malware and, by default,
    package versions younger than 48 hours. Check it with `npm safe-chain-verify` or `pip safe-chain-verify`.
  - **[LeakTK](https://github.com/leaktk/leaktk)** (0.3.10): a secret scanner, e.g.
    `leaktk scan --kind GitRepo ~/work/<repo>`.
  - **[trzsz](https://github.com/trzsz/trzsz-go)** (1.2.0): browser file transfer, see below.
  - **Podman/Buildah** (Debian's), for building images only: `podman build` and `buildah` work, but
    `podman run` doesn't, because a fresh `/proc` can't be mounted in this container. The user has
    no capabilities, so builds map only its own uid: every file in an image is owned by root. `RUN`
    steps use chroot isolation on the container's network, so they go out through the proxy. Use
    fully qualified image names (`docker.io/library/debian`), and allow the registries in the
    egress policy if you restrict it. Images are stored in `~/.local/share/containers`.

## Getting files out

There are two ways to get files out, both behind the passkey login:

- **`/files/`** (also linked from `/auth/manage`) is a read-only browser over `~/work`. Click a file to
  view it, use ↓ (or add `?download`) to save it, or use **Download as zip** (`?zip`) to get a whole
  directory. Zips leave out `.git/`, `node_modules/` and symlinks. The gate mounts the home volume
  read-only and serves only `~/work` from it (`GATE_FILES`), opened as an `os.Root`: `..` and symlinks
  that point outside `~/work` fail, so `~/.claude` (Claude's login) can't be reached. (A volume
  `subpath` would keep the rest of the home out of the gate entirely, but podman ignores it.) Files
  you open are CSP-sandboxed: HTML among them can't run scripts or reach the terminal's websocket. A side effect is that images and stylesheets an HTML page loads
  from `/files/` don't load. Download the directory to view such pages properly.
- **trzsz** works inside the terminal, in desktop Chromium browsers (Chrome, Edge; Brave with
  `brave://flags/#file-system-access-api`). Firefox and Safari lack the File System Access API it saves
  with, so use `/files/` there. Run `tsz <file>…` to download through the browser (`tsz -d <dir>`
  for a directory), and `trz` to upload into the current directory. It works inside tmux. Run it in
  your own shell, such as a second tmux window (`Ctrl-b c`), not through Claude Code's `!` or its Bash
  tool, which have no terminal for the transfer.

## Passkeys

The `gate` container (built from `gate/`) is the only way into the terminal. It does passkey
(WebAuthn) sign-in and then proxies the page and its websocket to ttyd. ttyd doesn't listen on any port.
It listens on a UNIX socket in the `tty-sock` in-memory volume, which only the claude and gate containers
mount. It trusts the `X-Auth-User` header that the gate sets, so nothing else on the `claude` network
can reach ttyd or forge that header. Gate and claude share the signer's SELinux category for the same
reason the signer does.

- **First passkey**: with `GATE_SETUP_CODE` set in `gate.env` (at least 16 characters), open
  `/auth/register`, enter the code, give the passkey a name and create it. Your browser or phone stores
  it. Registering signs you in. Then clear `GATE_SETUP_CODE` and redeploy; the gate's log reminds you
  while it is set.
- **Managing passkeys**: open `/auth/manage` while signed in. It lists each passkey's name, when it was
  added and when it was last used, and marks the one this browser signed in with. From there you can:
  - **Add a passkey** for another device, which needs no setup code while you're signed in. A synced
    passkey (iCloud Keychain, Google Password Manager, 1Password) already covers all your devices.
  - **Rename** a passkey.
  - **Remove** a passkey. Every browser that signed in with it is signed out at once, so removing a lost
    device's passkey locks that device out. The last passkey can't be removed; add another first.
  - **Sign out all other browsers**, which keeps this one signed in.
- **Sessions** last `GATE_SESSION_DAYS` (default 30). `/auth/logout` signs this browser out.
- **Lost every passkey**: set `GATE_SETUP_CODE` again, redeploy, register a new one, then remove the old
  ones at `/auth/manage`.
- **Hostname**: passkeys are tied to the hostname of `GATE_ORIGIN` (set in `.env`). If that changes,
  register again.
- Passkeys, their names and the session key are in the `gate-data` volume (`owner.json`, `session.key`).
  The gate has no internet access. Its log records registrations, removals and failed sign-ins.

## The user

The image has no user baked in. The claude container starts as root only to run `init-user`
(`claude/init-user`):

1. It creates `CLAUDE_USER` (from `.env`, default `claude`) with uid 1000 and home `/home/$CLAUDE_USER`.
   The `claude-home` volume is mounted there.
2. On first use, when the volume is empty, it copies in the home template built into the image at
   `/opt/home-skel`: Claude Code, safe-chain, the shell dotfiles and `~/work`. Later starts leave the
   home alone.
3. It sets the git identity from `GIT_USER_NAME`/`GIT_USER_EMAIL` in `claude.env` on every start
   when they're set, so editing them and redeploying updates `~/.gitconfig`. When they're empty,
   `git config --global` is yours to manage.
4. It drops to the user for good (`setpriv`, with no capabilities and no-new-privs) before anything
   else runs. ttyd, the shell and Claude never run as root.

The uid is always 1000, whatever the name, because the signer's agent, the socket volumes and the gate
depend on it. The name can't be `root`, an existing system account like `daemon`, or anything other
than lowercase letters, digits, `_` and `-`.

Pick `CLAUDE_USER` before the first deploy. A new name mounts the volume at a new path, and some
files written there record the old one (e.g. Claude Code's launcher in `~/.local/bin` after an
update). To change the name, start from a fresh `claude-home` volume. An existing volume from before
this setting works as is with `CLAUDE_USER=rmonk`.

## Commit signing

The `signer` container holds Claude's SSH signing key in `ssh-agent` and shares only the agent socket
(the `signer-sock` in-memory volume). Claude can sign commits and tags but can't read or copy the key.
The signer has no network. On startup the claude container asks the agent for its public key and, if
there is one, turns on `commit.gpgsign`/`tag.gpgsign` with `gpg.format=ssh`.

To set it up:

1. Generate a key for Claude only: `ssh-keygen -t ed25519 -N '' -C claude-signing -f claude-signing`.
2. Put `SIGNING_KEY_B64=<output of base64 -w0 claude-signing>` in `signer.env`, then delete
   the local private key file.
3. Add `claude-signing.pub` on GitHub as a **signing key** (not an authentication key).
4. Give Claude its own identity with `GIT_USER_NAME` (e.g. `Claude (container_server)`) and
   `GIT_USER_EMAIL` (an address on your account) in `claude.env`, so "Verified" commits are clearly
   Claude's.
5. Redeploy. The signer is recreated and the claude container restarts with it.

Signer and claude share an SELinux category (`s0:c742,c743`), and the socket volume is labelled to
match, because container_server runs SELinux and otherwise the containers couldn't share the socket. Leave
`SIGNING_KEY_B64` empty to turn signing off.

## The proxy

The proxy enforces the egress policy in `egress/egress.toml` (start from
`egress/egress.example.toml`). The `egress/` folder is mounted read-only into the proxy, which checks the
file every two seconds and reloads it on any change, with no redeploy. Its log (`podman compose logs
proxy`) shows the policy it loaded, every host the container connects to, and each request it refused:

```toml
[allow]
hosts = []                      # only these hosts (and subdomains); empty: all not blocked

[block]
hosts = ["example.com"]         # refused, subdomains included; wins over [allow]

[inject."api.github.com"]       # headers on every HTTPS request to exactly this host
Authorization = "Bearer ${GITHUB_TOKEN}"

[inject."github.com"]
Authorization = { basic = "x-access-token:${GITHUB_TOKEN}" }   # HTTP Basic auth
```

- **Decryption**: only `[inject]` hosts are decrypted, so headers can be added. All other traffic
  passes through untouched. Headers are added only over HTTPS, never to plain-HTTP requests.
- **Secrets**: `${VAR}` is read from the project `.env`, which only the **proxy** loads, so secrets stay out
  of `egress.toml` and the agent never sees them. While any variable a host uses is empty, that host is
  skipped (logged), so requests never carry a bare `Bearer `.
- **Allow lists**: once `[allow]` lists anything, every other host is refused, including those Claude Code
  needs. Include `anthropic.com`, `claude.ai` and `claude.com`, plus whatever registries and services you
  use. Watch the proxy log for refusals.
- **Mistakes**: if an edit is invalid (bad TOML, an unknown section, a misspelt key), the proxy logs why
  and keeps the previous policy. If the file is invalid when the proxy starts, it blocks everything until
  the file is fixed. Without the file, it allows everything and injects nothing.
- **The code** that enforces the policy is `EGRESS_ADDON` in `compose.yaml`; changing that needs a redeploy.

The claude container trusts mitmproxy's CA for decrypted hosts. It mounts only the CA certificate (the
`mitmproxy-ca-cert` volume, which the proxy fills on startup); the private key stays in the proxy's
`mitmproxy-ca` volume. Claude Code and Node use
`NODE_EXTRA_CA_CERTS`. curl, git, Python, Go and uv use `/tmp/ca-bundle.pem` (system CAs plus mitmproxy's),
which the entrypoint builds at startup, through `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO` and
`REQUESTS_CA_BUNDLE`.

Egress is enforced. The `claude` network is `internal: true`, so the claude container has no route out;
only `proxy` also sits on `claude_egress`, which does. Anything that honors `HTTPS_PROXY` works (curl,
git over HTTPS, Node, Python/pip, npm/safe-chain, gh, Go tools, Claude Code). Anything that doesn't, such
as plain `ssh`, `git://` or raw sockets, fails, and external hostnames don't resolve inside the container.
tsbridge joins `claude` to reach the gate on port 8080.

Changing the `claude` network's settings means Compose must recreate it, which fails while another
project's container (tsbridge) is attached, leaving the project half-stopped. Detach tsbridge first,
bring the project down and up, then reattach tsbridge.
