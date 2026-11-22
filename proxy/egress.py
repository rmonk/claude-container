"""Applies the egress policy in /etc/egress/egress.toml and reloads it when it changes.

The policy itself (allow, block, inject) is data in that file; this is only the code that
enforces it. See egress/egress.example.toml. mitmdump loads this file as a script (see
entrypoint.sh); test_egress.py tests it, and runs during the image build.
"""
import asyncio
import base64
import json
import logging
import os
import re
import ssl
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request

from mitmproxy import ctx, http

PATH = os.environ.get("EGRESS_CONFIG", "/etc/egress/egress.toml")
POLL_SECONDS = 2
VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
try:
    import certifi  # a mitmproxy dependency
    TLS = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    TLS = ssl.create_default_context()


class OAuth2Token:
    """An OAuth2 client-credentials token that the proxy fetches itself and renews before it
    expires, so the client secret and the token stay out of the claude container."""

    _shared = {}  # by settings, so reloading an unchanged policy keeps a still-valid token

    @classmethod
    def get(cls, token_url, client_id, client_secret, scope):
        key = (token_url, client_id, client_secret, scope)
        if key not in cls._shared:
            cls._shared[key] = cls(*key)
        return cls._shared[key]

    def __init__(self, token_url, client_id, client_secret, scope):
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.token = None
        self.fetched = 0.0
        self.renew_at = 0.0
        self.lock = asyncio.Lock()  # one fetch at a time; other requests wait for it

    def is_token_request(self, url):
        return url.split("?")[0].rstrip("/") == self.token_url.split("?")[0].rstrip("/")

    async def header(self):
        async with self.lock:
            if not self.token or time.monotonic() >= self.renew_at:
                token, lifetime = await asyncio.to_thread(self._fetch)
                self.token, self.fetched = token, time.monotonic()
                # Renew a little early (up to a minute) so a request never carries a token
                # that expires on the way.
                self.renew_at = self.fetched + max(lifetime - min(60, lifetime / 10), 1)
                logging.info(f"egress policy: got an OAuth2 token from {self.token_url}, valid {lifetime:.0f}s")
            return "Bearer " + self.token

    def _fetch(self):
        form = {"grant_type": "client_credentials", "client_id": self.client_id, "client_secret": self.client_secret}
        if self.scope:
            form["scope"] = self.scope
        req = urllib.request.Request(
            self.token_url,
            data=urllib.parse.urlencode(form).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15, context=TLS) as r:
                body = json.load(r)
        except urllib.error.HTTPError as e:
            with e:
                detail = e.read(300).decode(errors="replace").strip()
            raise RuntimeError(f"{self.token_url} answered {e.code}: {detail}") from None
        except (OSError, ValueError) as e:
            raise RuntimeError(f"{self.token_url}: {e}") from None
        token = body.get("access_token") if isinstance(body, dict) else None
        if not isinstance(token, str) or not token:
            error = body.get("error") if isinstance(body, dict) else None
            raise RuntimeError(f"{self.token_url} returned no access_token (error: {error})")
        lifetime = body.get("expires_in")
        if isinstance(lifetime, str) and lifetime.isdigit():
            lifetime = int(lifetime)
        if not isinstance(lifetime, (int, float)) or isinstance(lifetime, bool) or lifetime <= 0:
            lifetime = 300  # no usable lifetime given: renew every five minutes
        return token, float(lifetime)

    def refused(self, sent, status):
        """Drops the token after the server refused a request that carried it (header `sent`),
        so the next request fetches a new one. A 403 can also mean a missing scope, so it only
        drops a token at least a minute old, rather than fetching one per request."""
        if self.token and sent == "Bearer " + self.token and (status == 401 or time.monotonic() - self.fetched >= 60):
            logging.info(f"egress policy: server answered {status}; renewing the token from {self.token_url}")
            self.token = None


class Policy:
    def __init__(self, allow=(), block=(), inject=None, deny_all=False):
        self.allow = list(allow)
        self.block = list(block)
        self.inject = inject or {}
        self.deny_all = deny_all


def _hosts(data, section):
    table = data.get(section, {})
    if not isinstance(table, dict) or set(table) - {"hosts"}:
        raise ValueError(f"[{section}] takes only `hosts = [...]`")
    hosts = table.get("hosts", [])
    if not isinstance(hosts, list) or not all(isinstance(h, str) and h.strip() for h in hosts):
        raise ValueError(f"[{section}] hosts must be a list of host names")
    for h in hosts:
        if "/" in h or ":" in h:
            raise ValueError(f"[{section}] {h!r}: give a host name, without scheme, port or path")
    return [h.strip().lower().rstrip(".") for h in hosts]


def _render(value, missing):
    """Fills ${VAR} from the environment, noting variables that are unset or empty."""
    def sub(m):
        v = os.environ.get(m.group(1), "")
        if not v:
            missing.add(m.group(1))
        return v
    return VAR.sub(sub, value)


def _oauth2(where, conf, missing):
    """{ token_url, client_id, client_secret, scope? }: a Bearer token from the client-credentials grant."""
    required = {"token_url", "client_id", "client_secret"}
    if (
        not isinstance(conf, dict)
        or not required <= set(conf)
        or set(conf) - required - {"scope"}
        or not all(isinstance(v, str) for v in conf.values())
    ):
        raise ValueError(f"{where}: oauth2 takes token_url, client_id, client_secret and optionally scope, all strings")
    if not conf["token_url"].startswith("https://"):
        raise ValueError(f"{where}: oauth2 token_url must start with https://")
    own_missing = set()
    s = {k: _render(v, own_missing) for k, v in conf.items()}
    missing |= own_missing
    if own_missing:
        return None  # the host is skipped
    return OAuth2Token.get(s["token_url"], s["client_id"], s["client_secret"], s.get("scope", ""))


def _inject(data):
    table = data.get("inject", {})
    if not isinstance(table, dict):
        raise ValueError("[inject] must be tables of headers, e.g. [inject.\"api.example.com\"]")
    out = {}
    for host, headers in table.items():
        if not isinstance(headers, dict) or not headers:
            raise ValueError(f"[inject.{host!r}] must set at least one header")
        missing, rendered = set(), {}
        for name, value in headers.items():
            if isinstance(value, dict) and set(value) == {"basic"} and isinstance(value["basic"], str):
                creds = _render(value["basic"], missing)
                rendered[name] = "Basic " + base64.b64encode(creds.encode()).decode()
            elif isinstance(value, dict) and set(value) == {"oauth2"}:
                rendered[name] = _oauth2(f"[inject.{host!r}] {name}", value["oauth2"], missing)
            elif isinstance(value, str):
                rendered[name] = _render(value, missing)
            else:
                raise ValueError(
                    f"[inject.{host!r}] {name}: use a string, {{ basic = \"user:password\" }} "
                    f"or {{ oauth2 = {{ token_url = ..., client_id = ..., client_secret = ... }} }}"
                )
        if missing:
            logging.info(f"egress policy: not injecting for {host}: {', '.join(sorted(missing))} empty")
            continue
        out[host.lower().rstrip(".")] = rendered
    return out


def parse(text):
    data = tomllib.loads(text)
    unknown = set(data) - {"allow", "block", "inject"}
    if unknown:
        raise ValueError(f"unknown section(s): {', '.join(sorted(unknown))}")
    return Policy(_hosts(data, "allow"), _hosts(data, "block"), _inject(data))


def _matches(host, names):
    host = host.lower().rstrip(".")
    return any(host == n or host.endswith("." + n) for n in names)


class Egress:
    def __init__(self):
        self.policy = None
        self.signature = None
        self.task = None

    def running(self):
        self.read_policy()
        self.task = asyncio.get_running_loop().create_task(self.watch())

    async def watch(self):
        while True:
            await asyncio.sleep(POLL_SECONDS)
            if self._signature() != self.signature:
                self.read_policy()

    def _signature(self):
        try:
            st = os.stat(PATH)
            return (st.st_ino, st.st_mtime_ns, st.st_size)
        except FileNotFoundError:
            return None

    def read_policy(self):
        self.signature = self._signature()
        try:
            with open(PATH, "rb") as f:
                policy = parse(f.read().decode())
        except FileNotFoundError:
            policy = Policy()
            logging.warning(f"egress policy: no {PATH}; allowing everything, injecting nothing")
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, ValueError) as e:
            if self.policy is None:
                # A warning, not an error: mitmproxy exits on errors logged during startup,
                # and staying up (blocking) lets a fix be picked up without a restart.
                logging.warning(f"egress policy: {PATH} is invalid, blocking everything until it's fixed: {e}")
                policy = Policy(deny_all=True)
            else:
                logging.error(f"egress policy: {PATH} is invalid, keeping the previous policy: {e}")
                return
        self.policy = policy
        # Decrypt only the hosts that get headers; everything else passes through untouched.
        if policy.inject:
            ctx.options.update(ignore_hosts=[], allow_hosts=[rf"^{re.escape(h)}(:\d+)?$" for h in policy.inject])
        else:
            ctx.options.update(allow_hosts=[], ignore_hosts=[".*"])
        if not policy.deny_all:
            logging.info(
                f"egress policy: allowing {policy.allow or 'all hosts'}; blocking {policy.block or 'nothing'}; "
                f"injecting for {sorted(policy.inject) or 'nothing'}"
            )

    def refusal(self, host):
        p = self.policy
        if p is None or p.deny_all:
            return "egress policy is invalid"
        if _matches(host, p.block):
            return "blocked"
        if p.allow and not _matches(host, p.allow):
            return "not in the allow list"
        return None

    def http_connect(self, flow: http.HTTPFlow):
        self._check(flow, flow.request.host)

    async def request(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        if self._check(flow, host):
            return
        # Only over HTTPS: a plain-HTTP request would carry the secret in the clear.
        if flow.request.scheme != "https":
            return
        for name, value in self.policy.inject.get(host.lower(), {}).items():
            if isinstance(value, OAuth2Token):
                if value.is_token_request(flow.request.pretty_url):
                    continue  # the token request itself (e.g. claude getting its own token)
                try:
                    value = await value.header()
                except RuntimeError as e:
                    logging.error(f"egress policy: no OAuth2 token for {host}: {e}")
                    flow.response = http.Response.make(
                        502, f"could not get an OAuth2 token for {host} (egress policy): {e}\n".encode()
                    )
                    return
            flow.request.headers[name] = value

    def response(self, flow: http.HTTPFlow):
        if self.policy is None or flow.response.status_code not in (401, 403):
            return
        for name, value in self.policy.inject.get(flow.request.pretty_host.lower(), {}).items():
            if isinstance(value, OAuth2Token):
                value.refused(flow.request.headers.get(name, ""), flow.response.status_code)

    def _check(self, flow, host):
        if reason := self.refusal(host):
            logging.warning(f"BLOCK {host}:{flow.request.port} ({reason})")
            flow.response = http.Response.make(403, f"{reason} (egress policy)\n".encode())
            return True
        return False


addons = [Egress()]
