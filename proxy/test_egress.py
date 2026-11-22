"""Tests for egress.py. They run during the image build (see Dockerfile), and locally with
`python3 -m unittest -v test_egress` in this folder wherever mitmproxy is importable, e.g.

    podman run --rm -v ./proxy:/t:ro,z -w /t --entrypoint python3 \
      docker.io/mitmproxy/mitmproxy:12.3.1 -m unittest -v test_egress
"""
import asyncio
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from mitmproxy.test import taddons, tflow

import egress


def policy(text, **env):
    with mock.patch.dict(os.environ, env):
        return egress.parse(text)


OAUTH2 = """
[inject."panel.test"]
Authorization = { oauth2 = { token_url = "https://panel.test/oauth2/token", client_id = "${ID}", client_secret = "${SECRET}" } }
"""


class ParseTest(unittest.TestCase):
    def setUp(self):
        egress.OAuth2Token._shared.clear()

    def test_empty(self):
        p = policy("")
        self.assertEqual((p.allow, p.block, p.inject), ([], [], {}))

    def test_hosts_are_normalised(self):
        p = policy('[allow]\nhosts = ["Example.COM."]\n[block]\nhosts = ["bad.test"]')
        self.assertEqual(p.allow, ["example.com"])
        self.assertEqual(p.block, ["bad.test"])

    def test_rejects_mistakes(self):
        for text in [
            "[nope]\n",
            '[allow]\nhost = ["a.test"]',
            '[allow]\nhosts = ["https://a.test"]',
            '[allow]\nhosts = "a.test"',
            '[inject."a.test"]\n',
            '[inject."a.test"]\nX = 1',
            '[inject."a.test"]\nX = { bearer = "x" }',
        ]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                policy(text)

    def test_string_and_basic(self):
        p = policy('[inject."a.test"]\nX-Key = "k-${K}"\nAuthorization = { basic = "u:${K}" }', K="s3cret")
        self.assertEqual(p.inject["a.test"], {"X-Key": "k-s3cret", "Authorization": "Basic dTpzM2NyZXQ="})

    def test_empty_variable_skips_host(self):
        p = policy('[inject."a.test"]\nX-Key = "${K}"\n[inject."b.test"]\nX-Key = "fixed"', K="")
        self.assertEqual(list(p.inject), ["b.test"])

    def test_oauth2(self):
        p = policy(OAUTH2, ID="cid", SECRET="sec")
        tok = p.inject["panel.test"]["Authorization"]
        self.assertIsInstance(tok, egress.OAuth2Token)
        self.assertEqual((tok.token_url, tok.client_id, tok.client_secret, tok.scope),
                         ("https://panel.test/oauth2/token", "cid", "sec", ""))

    def test_oauth2_as_a_table(self):
        p = policy(
            '[inject."panel.test".Authorization.oauth2]\n'
            'token_url = "https://panel.test/oauth2/token"\nclient_id = "cid"\nclient_secret = "sec"\nscope = "a b"'
        )
        self.assertEqual(p.inject["panel.test"]["Authorization"].scope, "a b")

    def test_oauth2_reload_keeps_token(self):
        a = policy(OAUTH2, ID="cid", SECRET="sec").inject["panel.test"]["Authorization"]
        b = policy(OAUTH2, ID="cid", SECRET="sec").inject["panel.test"]["Authorization"]
        c = policy(OAUTH2, ID="cid", SECRET="other").inject["panel.test"]["Authorization"]
        self.assertIs(a, b)
        self.assertIsNot(a, c)

    def test_oauth2_empty_variable_skips_host(self):
        self.assertEqual(policy(OAUTH2, ID="cid", SECRET="").inject, {})

    def test_oauth2_rejects_mistakes(self):
        for conf in [
            'token_url = "https://p.test/t", client_id = "c"',
            'token_url = "https://p.test/t", client_id = "c", client_secret = "s", scopes = "x"',
            'token_url = "http://p.test/t", client_id = "c", client_secret = "s"',
            'token_url = "https://p.test/t", client_id = "c", client_secret = 1',
        ]:
            with self.subTest(conf=conf), self.assertRaises(ValueError):
                policy(f'[inject."p.test"]\nAuthorization = {{ oauth2 = {{ {conf} }} }}')


class Stub:
    """A local token endpoint (plain HTTP; OAuth2Token takes any URL, parse() insists on https)."""

    def __init__(self, reply):
        self.reply = reply  # (status, body) for each request, or a callable
        self.forms = []
        stub = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                stub.forms.append(dict(urllib.parse.parse_qsl(self.rfile.read(n).decode())))
                status, body = stub.reply() if callable(stub.reply) else stub.reply
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_port}/oauth2/token"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class OAuth2TokenTest(unittest.IsolatedAsyncioTestCase):
    def stub(self, reply):
        s = Stub(reply)
        self.addCleanup(s.close)
        return s

    async def test_fetches_once_and_caches(self):
        s = self.stub((200, {"access_token": "t1", "expires_in": 3600}))
        tok = egress.OAuth2Token(s.url, "cid", "sec", "server.view")
        self.assertEqual(await tok.header(), "Bearer t1")
        self.assertEqual(await tok.header(), "Bearer t1")
        self.assertEqual(s.forms, [{"grant_type": "client_credentials", "client_id": "cid",
                                    "client_secret": "sec", "scope": "server.view"}])

    async def test_no_scope_field_without_scope(self):
        s = self.stub((200, {"access_token": "t1", "expires_in": 60}))
        await egress.OAuth2Token(s.url, "cid", "sec", "").header()
        self.assertNotIn("scope", s.forms[0])

    async def test_renews_before_expiry(self):
        n = iter(range(1, 100))
        s = self.stub(lambda: (200, {"access_token": f"t{next(n)}", "expires_in": 3600}))
        tok = egress.OAuth2Token(s.url, "cid", "sec", "")
        await tok.header()
        self.assertAlmostEqual(tok.renew_at - tok.fetched, 3540, delta=1)  # a minute early
        tok.renew_at = time.monotonic() - 1
        self.assertEqual(await tok.header(), "Bearer t2")

    async def test_lifetime_defaults(self):
        for expires_in, want in [(None, 300), ("120", 120), (0, 300), (True, 300), ("soon", 300)]:
            body = {"access_token": "t"} | ({} if expires_in is None else {"expires_in": expires_in})
            s = self.stub((200, body))
            with self.subTest(expires_in=expires_in):
                self.assertEqual(egress.OAuth2Token(s.url, "c", "s", "")._fetch(), ("t", want))

    async def test_errors(self):
        for reply, words in [
            ((401, {"error": "invalid_client"}), "answered 401"),
            ((200, {"error": "nope"}), "no access_token"),
            ((200, b"not json"), "oauth2/token"),
        ]:
            s = self.stub(reply)
            with self.subTest(reply=reply), self.assertRaisesRegex(RuntimeError, words):
                await egress.OAuth2Token(s.url, "c", "s", "").header()

    async def test_concurrent_requests_share_one_fetch(self):
        def slow():
            time.sleep(0.2)
            return 200, {"access_token": "t1", "expires_in": 3600}
        s = self.stub(slow)
        tok = egress.OAuth2Token(s.url, "c", "s", "")
        got = await asyncio.gather(*(tok.header() for _ in range(8)))
        self.assertEqual(set(got), {"Bearer t1"})
        self.assertEqual(len(s.forms), 1)

    async def test_refused(self):
        tok = egress.OAuth2Token("http://unused", "c", "s", "")
        tok.token, tok.fetched = "t1", time.monotonic()
        tok.refused("Bearer other", 401)
        self.assertEqual(tok.token, "t1")  # a different (older) token was refused
        tok.refused("Bearer t1", 403)
        self.assertEqual(tok.token, "t1")  # a 403 on a fresh token may be a scope problem
        tok.fetched -= 61
        tok.refused("Bearer t1", 403)
        self.assertIsNone(tok.token)
        tok.token, tok.fetched = "t2", time.monotonic()
        tok.refused("Bearer t2", 401)
        self.assertIsNone(tok.token)


class AddonTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        egress.OAuth2Token._shared.clear()

    def load(self, text, **env):
        """Runs the addon with `text` as its policy file, returning (addon, context)."""
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        path = os.path.join(d.name, "egress.toml")
        with open(path, "w") as f:
            f.write(text)
        patches = [mock.patch.object(egress, "PATH", path), mock.patch.dict(os.environ, env)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        addon = egress.Egress()
        tctx = taddons.context(addon)
        tctx.__enter__()
        self.addCleanup(tctx.__exit__, None, None, None)
        # The test context leaves its Master's log handler on the root logger, bound to this
        # test's event loop; later tests' log calls would then fail on the closed loop.
        self.addCleanup(tctx.master._legacy_log_events.uninstall)
        addon.read_policy()
        return addon, tctx

    def flow(self, host, path="/", scheme="https"):
        f = tflow.tflow()
        f.request.scheme, f.request.host, f.request.port, f.request.path = scheme, host, 443, path
        f.request.headers.pop("Host", None)
        return f

    async def test_allow_and_block(self):
        addon, _ = self.load('[allow]\nhosts = ["ok.test"]\n[block]\nhosts = ["bad.ok.test"]')
        for host, refused in [("ok.test", False), ("api.ok.test", False), ("bad.ok.test", True), ("other.test", True)]:
            f = self.flow(host)
            addon.http_connect(f)
            with self.subTest(host=host):
                self.assertEqual(f.response is not None and f.response.status_code == 403, refused)

    async def test_invalid_at_start_blocks_everything(self):
        addon, _ = self.load("[allow\n")
        f = self.flow("any.test")
        await addon.request(f)
        self.assertEqual(f.response.status_code, 403)

    async def test_decrypts_only_inject_hosts(self):
        _, tctx = self.load('[inject."a.test"]\nX = "1"')
        self.assertEqual(tctx.options.allow_hosts, [r"^a\.test(:\d+)?$"])
        _, tctx = self.load("")
        self.assertEqual(tctx.options.ignore_hosts, [".*"])

    async def test_injects_over_https_only(self):
        addon, _ = self.load('[inject."a.test"]\nX-Key = "${K}"', K="s3cret")
        f = self.flow("a.test")
        await addon.request(f)
        self.assertEqual(f.request.headers["X-Key"], "s3cret")
        f = self.flow("a.test", scheme="http")
        await addon.request(f)
        self.assertNotIn("X-Key", f.request.headers)

    async def test_oauth2_flow(self):
        addon, _ = self.load(OAUTH2, ID="cid", SECRET="sec")
        tok = addon.policy.inject["panel.test"]["Authorization"]
        with mock.patch.object(tok, "_fetch", return_value=("t1", 3600.0)) as fetch:
            f = self.flow("panel.test", "/api/servers")
            await addon.request(f)
            self.assertEqual(f.request.headers["Authorization"], "Bearer t1")
            # The token request itself goes out as the client sent it.
            f = self.flow("panel.test", "/oauth2/token")
            await addon.request(f)
            self.assertNotIn("Authorization", f.request.headers)
            self.assertEqual(fetch.call_count, 1)
            # A 401 drops the token; the next request fetches another.
            f = self.flow("panel.test", "/api/servers")
            await addon.request(f)
            f.response = tflow.tresp(status_code=401)
            addon.response(f)
            fetch.return_value = ("t2", 3600.0)
            f = self.flow("panel.test", "/api/servers")
            await addon.request(f)
            self.assertEqual(f.request.headers["Authorization"], "Bearer t2")

    async def test_oauth2_failure_is_a_502(self):
        addon, _ = self.load(OAUTH2, ID="cid", SECRET="sec")
        tok = addon.policy.inject["panel.test"]["Authorization"]
        with mock.patch.object(tok, "_fetch", side_effect=RuntimeError("answered 401: invalid_client")):
            f = self.flow("panel.test", "/api/servers")
            await addon.request(f)
        self.assertEqual(f.response.status_code, 502)
        self.assertIn(b"invalid_client", f.response.content)
        self.assertNotIn("Authorization", f.request.headers)


if __name__ == "__main__":
    unittest.main()
