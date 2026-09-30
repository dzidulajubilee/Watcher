# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Watcher IDS — regression tests (stdlib only, no pip dependencies).

Boots the real Handler / databases on temporary files and exercises the HTTP
API end-to-end.  Nothing touches /var/lib/watcher or any real data.

Run from the repository root:
    python3 -m unittest discover -s tests -v
"""

import http.client
import json
import logging
import os
import pathlib
import socket
import sys
import tempfile
import threading
import time
import unittest

BACKEND = pathlib.Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND))
logging.disable(logging.CRITICAL)

import handlers                                   # noqa: E402
from auth         import AuthManager              # noqa: E402
from config_db    import ConfigDB                 # noqa: E402
from database     import AlertDB                  # noqa: E402
from database_dns import DnsDB                    # noqa: E402
from handlers     import Handler                  # noqa: E402
from registry     import Registry                 # noqa: E402
from server       import ThreadedHTTPServer       # noqa: E402
from suppression  import SuppressionDB            # noqa: E402
from threat_intel import ThreatIntelDB            # noqa: E402
from users        import UserManager              # noqa: E402
from webhooks     import WebhookDB                # noqa: E402

try:                                              # absent in the noai build
    from explain import ExplainDB, ExplainEngine  # noqa: E402
    HAVE_AI = True
except ImportError:                               # pragma: no cover
    HAVE_AI = False


def eve_alert_line(i, flow_id=None, ts=None, sig=None):
    return json.dumps({
        "timestamp": ts or f"2026-09-30T10:00:{i % 60:02d}.{i:06d}+0000",
        "flow_id": flow_id if flow_id is not None else 1000 + i,
        "event_type": "alert", "src_ip": "10.0.0.5", "dest_ip": "8.8.8.8",
        "proto": "TCP",
        "alert": {"signature_id": sig or 2000 + i, "signature": "test",
                  "category": "c", "severity": 2},
    })


class WatcherTestCase(unittest.TestCase):
    """Fresh databases + a live HTTP server per test."""

    ADMIN_PW = "Admin-Pass-123"

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="watcher-test-")
        self.db     = AlertDB(f"{self.tmp}/events.db")
        self.dns_db = DnsDB(f"{self.tmp}/dns.db")
        self.cfg    = ConfigDB(f"{self.tmp}/config.db")
        self.auth   = AuthManager(conn_fn=self.cfg._conn)
        self.um     = UserManager(conn_fn=self.cfg._conn)
        self.um.create("admin", self.ADMIN_PW, role="admin")
        self.registry = Registry()
        self.wdb   = WebhookDB(conn_fn=self.cfg._conn)
        self.ti_db = ThreatIntelDB(conn_fn=self.cfg._conn)
        self.sup   = SuppressionDB(conn_fn=self.cfg._conn)
        Handler.db, Handler.auth, Handler.registry = self.db, self.auth, self.registry
        Handler.wdb, Handler.ti_db, Handler.sup_db = self.wdb, self.ti_db, self.sup
        Handler.um, Handler.dns_db = self.um, self.dns_db
        Handler.eve_path = pathlib.Path(f"{self.tmp}/eve.json")
        Handler._stats_cache = None
        Handler._login_attempts = {}
        if HAVE_AI:
            self.explain = ExplainEngine(ExplainDB(conn_fn=self.cfg._conn))
            Handler.explain_engine = self.explain
        self.srv = ThreadedHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    # ── helpers ──────────────────────────────────────────────────────────────
    def req(self, method, path, body=None, token=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Content-Type": "application/json", **(headers or {})}
        if token:
            h["Cookie"] = f"suri_session={token}"
        c.request(method, path,
                  json.dumps(body) if body is not None else None, h)
        r = c.getresponse()
        raw = r.read()
        try:
            data = json.loads(raw)
        except Exception:
            data = raw
        return r.status, data, r

    def login(self, username, password, headers=None):
        status, data, r = self.req("POST", "/login",
                                   {"username": username, "password": password},
                                   headers=headers)
        cookie = r.getheader("Set-Cookie") or ""
        token = (cookie.split("suri_session=")[1].split(";")[0]
                 if "suri_session=" in cookie else None)
        return status, token, cookie

    def admin_token(self):
        return self.login("admin", self.ADMIN_PW)[1]

    def make_user(self, name, role):
        self.um.create(name, f"{name}-pass-123", role=role)
        return self.login(name, f"{name}-pass-123")[1]


# ══════════════════════════════════════════════════════════════════════════════
# Batch 1 — bug fixes
# ══════════════════════════════════════════════════════════════════════════════

class TestSseDroppedClient(WatcherTestCase):
    def test_registry_drops_client_whose_queue_overflows(self):
        reg = Registry()
        cid, _q = reg.add()                       # nobody drains this queue
        for i in range(700):                      # > MAX_QUEUE (500)
            reg.broadcast("alert", {"n": i})
        self.assertFalse(reg.is_registered(cid))

    def test_dropped_client_stream_is_closed_so_browser_reconnects(self):
        handlers.PING_EVERY = 1
        try:
            tok = self.admin_token()
            s = socket.create_connection(("127.0.0.1", self.port))
            s.settimeout(0.5)
            s.sendall(f"GET /events HTTP/1.1\r\nHost: x\r\n"
                      f"Cookie: suri_session={tok}\r\n\r\n".encode())
            deadline = time.time() + 3
            while self.registry.count() == 0 and time.time() < deadline:
                time.sleep(0.05)
            self.assertEqual(self.registry.count(), 1)
            # Simulate the registry dropping this client (as broadcast() does
            # when its queue overflows during a burst).
            with self.registry._lock:
                self.registry._clients.clear()
            closed, deadline = False, time.time() + 6
            while time.time() < deadline:
                try:
                    if s.recv(65536) == b"":
                        closed = True
                        break
                except socket.timeout:
                    pass
            s.close()
            self.assertTrue(closed, "dropped SSE client was left as a zombie stream")
        finally:
            handlers.PING_EVERY = 10

    def test_healthy_client_keeps_receiving(self):
        tok = self.admin_token()
        s = socket.create_connection(("127.0.0.1", self.port))
        s.settimeout(2)
        s.sendall(f"GET /events HTTP/1.1\r\nHost: x\r\n"
                  f"Cookie: suri_session={tok}\r\n\r\n".encode())
        time.sleep(0.3)
        self.registry.broadcast("alert", {"marker": "HELLO"})
        buf, deadline = b"", time.time() + 3
        while b"HELLO" not in buf and time.time() < deadline:
            buf += s.recv(65536)
        s.close()
        self.assertIn(b"HELLO", buf)


class TestInputValidation(WatcherTestCase):
    def test_bad_sig_id_returns_400_not_dropped_connection(self):
        tok = self.admin_token()
        cases = [
            ("POST", "/suppression",   {"name": "n", "sig_id": "abc"}),
            ("POST", "/suppression",   {"name": "n", "sig_id": 1, "expires_at": "soon"}),
            ("POST", "/threat-intel",  {"sig_id": "abc", "explanation": "e"}),
            ("GET",  "/threat-intel/lookup?sig_id=abc", None),
        ]
        for method, path, body in cases:
            status, data, _ = self.req(method, path, body, tok)
            self.assertEqual(status, 400, f"{method} {path}")

    def test_suppression_update_rejects_bad_sig_id_instead_of_widening_rule(self):
        tok = self.admin_token()
        _, rule, _ = self.req("POST", "/suppression", {"name": "n", "sig_id": 42}, tok)
        status, _, _ = self.req("PUT", f"/suppression/{rule['id']}", {"sig_id": "x"}, tok)
        self.assertEqual(status, 400)
        self.assertEqual(self.sup.get_by_id(rule["id"])["sig_id"], 42)

    def test_valid_inputs_still_work(self):
        tok = self.admin_token()
        s, _, _ = self.req("POST", "/suppression", {"name": "n", "sig_id": "42"}, tok)
        self.assertEqual(s, 201)
        s, _, _ = self.req("POST", "/threat-intel", {"sig_id": 7, "explanation": "e"}, tok)
        self.assertEqual(s, 201)
        s, d, _ = self.req("GET", "/threat-intel/lookup?sig_id=7", token=tok)
        self.assertEqual((s, d.get("sig_id")), (200, 7))


class TestThreatIntelImportAudit(WatcherTestCase):
    def test_import_records_real_username(self):
        tok = self.admin_token()
        s, _, _ = self.req("POST", "/threat-intel/import",
                           [{"sig_id": 123, "explanation": "e"}], tok)
        self.assertEqual(s, 200)
        self.assertEqual(self.ti_db.get_all()[0]["created_by"], "admin")


class TestUserUpdateOrdering(WatcherTestCase):
    def test_rejected_update_does_not_change_password(self):
        tok = self.admin_token()
        admin = self.um.get_by_username("admin")
        s, _, _ = self.req("PUT", f"/users/{admin['id']}",
                           {"password": "changed-pw-999", "role": "viewer"}, tok)
        self.assertEqual(s, 400)   # cannot demote last admin
        self.assertIsNotNone(self.um.authenticate("admin", self.ADMIN_PW))

    def test_last_admin_cannot_be_disabled_with_zero(self):
        tok = self.admin_token()
        admin = self.um.get_by_username("admin")
        s, _, _ = self.req("PUT", f"/users/{admin['id']}", {"enabled": 0}, tok)
        self.assertEqual(s, 400)


# ══════════════════════════════════════════════════════════════════════════════
# Batch 2 — security hardening
# ══════════════════════════════════════════════════════════════════════════════

class TestFallbackPassword(WatcherTestCase):
    def test_legacy_auto_generated_hash_no_longer_logs_in(self):
        # Simulate an upgraded install: a hash exists but was never set
        # explicitly by an operator (the old auto-generate-and-log path).
        from password_utils import hash_password
        c = self.cfg._conn()
        c.execute("INSERT OR REPLACE INTO auth (key, value) VALUES ('pw_hash', ?)",
                  (hash_password("leaked-from-journal"),))
        c.commit()
        status, _, _ = self.login("admin", "leaked-from-journal")
        self.assertEqual(status, 401)

    def test_explicit_fallback_works_and_can_be_cleared(self):
        self.auth.set_password("break-glass-pw")
        self.assertEqual(self.login("admin", "break-glass-pw")[0], 200)
        self.auth.clear_password()
        self.assertEqual(self.login("admin", "break-glass-pw")[0], 401)

    def test_normal_user_login_unaffected(self):
        self.assertEqual(self.login("admin", self.ADMIN_PW)[0], 200)


class TestSessionRevocation(WatcherTestCase):
    def _bob(self):
        tok = self.make_user("bob", "admin")
        return tok, self.um.get_by_username("bob")["id"]

    def test_demoted_user_loses_session(self):
        admin, (btok, bid) = self.admin_token(), self._bob()
        self.assertEqual(self.req("GET", "/users", token=btok)[0], 200)
        self.req("PUT", f"/users/{bid}", {"role": "viewer"}, admin)
        self.assertEqual(self.req("GET", "/me", token=btok)[0], 401)

    def test_disabled_user_loses_session(self):
        admin, (btok, bid) = self.admin_token(), self._bob()
        self.req("PUT", f"/users/{bid}", {"enabled": False}, admin)
        self.assertEqual(self.req("GET", "/me", token=btok)[0], 401)

    def test_deleted_user_loses_session(self):
        admin, (btok, bid) = self.admin_token(), self._bob()
        self.req("DELETE", f"/users/{bid}", token=admin)
        self.assertEqual(self.req("GET", "/me", token=btok)[0], 401)

    def test_unrelated_edit_keeps_session(self):
        admin, (btok, bid) = self.admin_token(), self._bob()
        self.req("PUT", f"/users/{bid}", {"role": "admin"}, admin)  # no change
        self.assertEqual(self.req("GET", "/me", token=btok)[0], 200)


class TestWebhookListAuthorization(WatcherTestCase):
    def test_only_admin_can_list_webhooks(self):
        self.wdb.create("s", "slack", "https://hooks.slack.com/services/SECRET", ["high"])
        for role in ("viewer", "analyst"):
            tok = self.make_user(f"u_{role}", role)
            self.assertEqual(self.req("GET", "/webhooks", token=tok)[0], 403, role)
        s, d, _ = self.req("GET", "/webhooks", token=self.admin_token())
        self.assertEqual((s, len(d)), (200, 1))


class TestSsrf(unittest.TestCase):
    def test_blocked_destinations(self):
        from webhooks import validate_webhook_url
        for url in ("http://127.0.0.1/", "http://0.0.0.0:8765/",
                    "http://[::ffff:127.0.0.1]/", "http://100.64.0.1/",
                    "http://[fe80::1]/", "http://10.1.2.3/", "http://[::1]/",
                    "http://169.254.169.254/", "ftp://example.com/"):
            self.assertIsNotNone(validate_webhook_url(url), url)

    def test_public_ip_allowed_and_allow_local_still_works(self):
        from webhooks import validate_webhook_url
        self.assertIsNone(validate_webhook_url("https://8.8.8.8/hook"))
        self.assertIsNone(validate_webhook_url("http://192.168.1.10/n8n", allow_local=True))

    def test_redirect_to_internal_address_is_not_followed(self):
        import http.server
        import webhooks
        hits = []

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def do_POST(self):
                if self.path == "/start":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/internal")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                else:
                    hits.append(self.path)
                    self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()
            do_GET = do_POST

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        port = srv.server_address[1]
        real = webhooks.validate_webhook_url
        # Treat the first hop as a public host; the redirect target is checked
        # with the real validator.
        webhooks.validate_webhook_url = (
            lambda u, allow_local=False: None if u.endswith("/start") else real(u, allow_local))
        try:
            err = webhooks.deliver(f"http://127.0.0.1:{port}/start", {"a": 1})
        finally:
            webhooks.validate_webhook_url = real
            srv.shutdown()
        self.assertEqual(hits, [])
        self.assertIn("Blocked redirect", err or "")


@unittest.skipUnless(HAVE_AI, "AI build only")
class TestExplainForceAuthorization(WatcherTestCase):
    def test_viewer_cannot_force_regenerate(self):
        tok = self.make_user("vic", "viewer")
        s, _, _ = self.req("POST", "/alerts/explain", {"sig_id": 1, "force": True}, tok)
        self.assertIn(s, (403,))

    def test_analyst_reaches_provider_path(self):
        tok = self.make_user("ana", "analyst")
        s, d, _ = self.req("POST", "/alerts/explain", {"sig_id": 1, "force": True}, tok)
        self.assertEqual((s, d.get("error")), (503, "no_key"))   # no key in tests


# ══════════════════════════════════════════════════════════════════════════════
# Batch 3 — data integrity
# ══════════════════════════════════════════════════════════════════════════════

class TestReplayIdempotent(WatcherTestCase):
    def _write_eve(self, n):
        with open(Handler.eve_path, "w") as f:
            f.write("\n".join(eve_alert_line(i) for i in range(n)) + "\n")

    def _alert_rows(self):
        return self.db._conn().execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    def test_replaying_twice_does_not_duplicate(self):
        import tail
        self._write_eve(100)
        r1 = tail.replay_eve(str(Handler.eve_path), self.db, self.registry)
        r2 = tail.replay_eve(str(Handler.eve_path), self.db, self.registry)
        self.assertEqual(self._alert_rows(), 100)
        self.assertEqual((r1["inserted"], r2["inserted"]), (100, 0))
        self.assertEqual((r2["duplicates"], r2["skipped"]), (100, 100))

    def test_replay_skips_alerts_already_stored_by_live_tail(self):
        import tail
        self._write_eve(20)
        for line in open(Handler.eve_path):            # live path, random IDs
            _, parsed = tail.parse_eve_line(line)
            self.db.insert(parsed)
        r = tail.replay_eve(str(Handler.eve_path), self.db, self.registry)
        self.assertEqual((self._alert_rows(), r["inserted"]), (20, 0))

    def test_distinct_alerts_on_same_flow_are_all_kept(self):
        import tail
        lines = [eve_alert_line(0, flow_id=7, ts="2026-09-30T10:00:00.000001+0000", sig=1),
                 eve_alert_line(1, flow_id=7, ts="2026-09-30T10:00:00.000001+0000", sig=2),
                 eve_alert_line(2, flow_id=7, ts="2026-09-30T10:00:00.000002+0000", sig=1)]
        Handler.eve_path.write_text("\n".join(lines) + "\n")
        r = tail.replay_eve(str(Handler.eve_path), self.db, self.registry)
        self.assertEqual((r["inserted"], self._alert_rows()), (3, 3))

    def test_live_ids_still_carry_entropy_suffix(self):     # Standing Rule 6
        import tail
        _, a = tail.parse_eve_line(eve_alert_line(1))
        _, b = tail.parse_eve_line(eve_alert_line(1))
        self.assertNotEqual(a["id"], b["id"])
        self.assertEqual(len(a["id"].rsplit("-", 1)[1]), 8)


class TestAckHistoryOrphans(WatcherTestCase):
    def test_purge_removes_only_orphaned_history(self):
        import tail
        for i in (1, 2):
            _, a = tail.parse_eve_line(eve_alert_line(i))
            self.db.insert(a)
        ids = [r[0] for r in self.db._conn().execute("SELECT id FROM alerts")]
        for i in ids:
            self.db.acknowledge(i, "acknowledged", "n", "admin")
        c = self.db._conn()
        c.execute("DELETE FROM alerts WHERE id = ?", (ids[0],)); c.commit()
        self.db.purge_old()
        left = [r[0] for r in c.execute("SELECT alert_id FROM ack_history")]
        self.assertEqual(left, [ids[1]])


@unittest.skipUnless(HAVE_AI, "AI build only")
class TestExplainPromptAndProvider(WatcherTestCase):
    def test_prompt_contains_no_ip_addresses(self):
        prompt = ExplainEngine._build_prompt({
            "sig_id": 1, "sig_msg": "ET TEST", "category": "c", "severity": "high",
            "src_ip": "10.20.30.40", "dest_ip": "172.16.5.6", "proto": "tcp"})
        self.assertNotIn("10.20.30.40", prompt)
        self.assertNotIn("172.16.5.6", prompt)
        self.assertIn("ET TEST", prompt)

    def test_ai_provider_env_used_when_ui_not_set_and_ui_wins(self):
        old = os.environ.get("AI_PROVIDER")
        try:
            os.environ["AI_PROVIDER"] = "openai"
            self.assertEqual(self.explain.active_provider(), "openai")
            self.explain.set_config(provider="anthropic")
            self.assertEqual(self.explain.active_provider(), "anthropic")
            os.environ["AI_PROVIDER"] = "bogus"
            self.explain._db.delete_setting("ai_provider")
            self.assertEqual(self.explain.active_provider(), "deepseek")
        finally:
            if old is None: os.environ.pop("AI_PROVIDER", None)
            else: os.environ["AI_PROVIDER"] = old


# ══════════════════════════════════════════════════════════════════════════════
# HTTPS / reverse-proxy support
# ══════════════════════════════════════════════════════════════════════════════

class _FakeHandler(Handler):
    def __init__(self, peer, headers):          # no socket needed
        self.client_address = (peer, 50000)
        self.headers = headers


class TestProxyAwareness(WatcherTestCase):
    def test_forwarded_headers_trusted_only_from_loopback(self):
        hdr = {"X-Real-IP": "203.0.113.7", "X-Forwarded-Proto": "https"}
        local = _FakeHandler("127.0.0.1", hdr)
        remote = _FakeHandler("192.0.2.9", hdr)
        self.assertEqual(local.address_string(), "203.0.113.7")
        self.assertEqual(local._cookie_secure_attr(), "; Secure")
        self.assertEqual(remote.address_string(), "192.0.2.9")   # spoof ignored
        self.assertEqual(remote._cookie_secure_attr(), "")
        self.assertEqual(_FakeHandler("127.0.0.1", {"X-Real-IP": "not-an-ip"})
                         .address_string(), "127.0.0.1")

    def test_rate_limit_is_per_real_client_behind_proxy(self):
        attacker = {"X-Real-IP": "203.0.113.66"}
        for _ in range(10):
            self.login("admin", "wrong", headers=attacker)
        self.assertEqual(self.login("admin", "wrong", headers=attacker)[0], 429)
        other = {"X-Real-IP": "203.0.113.77"}
        self.assertEqual(self.login("admin", self.ADMIN_PW, headers=other)[0], 200)

    def test_secure_cookie_over_https_only(self):
        _, _, cookie = self.login("admin", self.ADMIN_PW,
                                  headers={"X-Forwarded-Proto": "https"})
        self.assertIn("Secure", cookie)
        _, _, cookie = self.login("admin", self.ADMIN_PW)
        self.assertNotIn("Secure", cookie)

    def test_watcher_host_env_sets_default_bind(self):
        import server
        old = os.environ.get("WATCHER_HOST")
        try:
            os.environ["WATCHER_HOST"] = "127.0.0.1"
            self.assertEqual(server.build_arg_parser().parse_args([]).host, "127.0.0.1")
            self.assertEqual(server.build_arg_parser()
                             .parse_args(["--host", "0.0.0.0"]).host, "0.0.0.0")
            os.environ.pop("WATCHER_HOST")
            self.assertEqual(server.build_arg_parser().parse_args([]).host, "0.0.0.0")
        finally:
            if old is not None: os.environ["WATCHER_HOST"] = old


if __name__ == "__main__":
    unittest.main()
