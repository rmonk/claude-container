# Claude Code container

A browser terminal (ttyd, behind a passkey login) that opens a bash shell as `rmonk` inside a
container with Claude Code installed. All of the container's outbound HTTP(S) goes through a
mitmproxy sidecar that you can later use to block hosts or inject credentials.

```
network "claude"
  tsbridge ──▶ gate:8080 (passkey login)
                 │ /tty/ttyd.sock (shared volume, no port)
                 ▼
  claude (ttyd → tmux → bash, user rmonk)
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
   ```

   Set `GATE_ORIGIN` in `.env` to the URL you'll open the terminal at, e.g.
   `https://claude.<your-tailnet>.ts.net`. For the first deploy, put a setup code in `gate.env`: `GATE_SETUP_CODE=<output of openssl rand -hex 16>`.
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
  the **claude** container, `signer.env` only into the signer and `gate.env` only into the gate. Start
  each from its `.example` file. Edit them, then redeploy.
- **Look**: ttyd's font, size and Catppuccin-style theme are set in the `entrypoint` in `compose.yaml`.
  The tmux settings, including the status bar and true color, are in the `tmux_conf`
  config. Changing either needs only a redeploy, not a rebuild. `LANG=C.UTF-8` is required: without it
  tmux replaces Claude Code's Unicode characters with `_`.
- **Copy/paste**: drag to select, and ttyd copies to your clipboard (✂ flashes). Paste with
  Ctrl+Shift+V (plain Ctrl+V sends a literal ^V; in Claude Code it pastes images). tmux mouse mode is off,
  so to scroll back use `Ctrl-b [`, then PgUp or the arrows, and `q` to exit.
- **Persistence**: `/home/rmonk` is the `claude-home` volume. It holds Claude Code itself (`~/.local`), its
  login and settings, your shell history, and `~/work`. Closing the tab leaves the tmux session running;
  reopening the page reattaches.
- **Updates**: Claude Code is a native install owned by `rmonk`, so it auto-updates (or run `claude update`).
  Updates live in the volume. Rebuilding the image only refreshes the OS packages, because Docker seeds the
  volume from the image only when the volume is first created.
- **Adding tools**: `rmonk` has no sudo, and anything outside `/home/rmonk` is lost when the container is
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
4. Give Claude its own identity, e.g. `git config --global user.name "Claude (container_server)"` and an email
   address on your account, so "Verified" commits are clearly Claude's.
5. Redeploy. The signer is recreated and the claude container restarts with it.

Signer and claude share an SELinux category (`s0:c742,c743`), and the socket volume is labelled to
match, because container_server runs SELinux and otherwise the containers couldn't share the socket. Leave
`SIGNING_KEY_B64` empty to turn signing off.

## The proxy

Out of the box it passes everything through without decrypting it. Its logs (`podman compose logs proxy`)
list every host the container connects to. Change it by editing the
`EGRESS_POLICY` value in the proxy service's environment in `compose.yaml` and redeploying. The proxy
is recreated automatically, and its log starts with the hosts it decrypts and blocks:

```python
BLOCK = ["example.com"]                       # refused at CONNECT, subdomains included
INJECT = {                                    # decrypted, headers added; everything else stays passthrough
    "api.github.com": {"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}"},
}
```

Secrets used in `INJECT` belong in the project `.env`, which only the **proxy** loads, so the agent
never sees them. GitHub is set up this way: when `GITHUB_TOKEN` is set, requests to `api.github.com`,
`uploads.github.com` and `raw.githubusercontent.com` get `Authorization: Bearer <token>`, and
`github.com` (git over HTTPS) gets Basic auth as `x-access-token:<token>`.

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
