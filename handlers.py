"""
Watcher IDS Dashboard — HTTP Request Handler
Handles all HTTP routes: login, logout, dashboard, SSE, REST API.
"""

import json
import logging
import re
import time
from http.cookies import SimpleCookie
from http.server   import BaseHTTPRequestHandler
from pathlib       import Path
from queue         import Empty
from urllib.parse  import urlparse, parse_qs

from config import FRONTEND_DIR, PING_EVERY, RETAIN_DAYS, SESSION_TTL

log = logging.getLogger("watcher.http")


class Handler(BaseHTTPRequestHandler):
    """
    Single handler class wired to the ThreadedHTTPServer.
    Dependencies (db, auth, registry) are injected as class attributes
    by server.py before the server starts.

    Routes
    ------
    GET  /              → serve frontend/index.html
    GET  /login         → serve frontend/login.html
    POST /login         → verify password, set session cookie
    GET  /logout        → revoke session, redirect to /login
    GET  /events        → SSE stream (requires auth)
    GET  /alerts        → JSON alert history (requires auth)
    GET  /flows         → JSON flow events (requires auth)
    GET  /dns           → JSON DNS events (requires auth)
    GET  /http          → JSON HTTP events (requires auth)
    DELETE /alerts      → wipe database (requires auth)
    DELETE /flows       → wipe flows table (requires auth)
    DELETE /dns         → wipe dns_events table (requires auth)
    GET  /charts        → JSON chart data (requires auth)
    GET  /health        → JSON status (requires auth)
    GET  /webhooks      → list all webhooks (requires auth)
    POST /webhooks      → create webhook (requires auth)
    PUT  /webhooks/<id> → update webhook (requires auth)
    DELETE /webhooks/<id> → delete webhook (requires auth)
    POST /webhooks/<id>/test → fire a test alert (requires auth)
    GET  /frontend/*    → static files: JS, CSS (requires auth)
    """

    # Injected by server.py
    db       = None
    auth     = None
    registry = None
    wdb      = None   # WebhookDB instance
    um       = None   # UserManager instance

    # Suppress Python's default "Server: BaseHTTP/x Python/x" header
    # which triggers Suricata SID 2034635.
    server_version = ""
    sys_version    = ""

    # ── Logging ───────────────────────────────────────────────────────────────

    def log_message(self, fmt, *args):
        first = str(args[0]) if args else ""
        # Suppress per-request noise for long-lived SSE connections
        if "/events" not in first:
            log.info("%s %s", self.address_string(), fmt % args)

    # ── Session helpers ───────────────────────────────────────────────────────

    def _token(self) -> str:
        """Extract session token from the Cookie header."""
        raw = self.headers.get("Cookie", "")
        if not raw:
            return ""
        try:
            c = SimpleCookie(raw)
            m = c.get("suri_session")
            return m.value if m else ""
        except Exception:
            return ""

    def _session(self) -> dict | None:
        """Return the session dict {token, username, role} or None."""
        return self.auth.get_session(self._token())

    def _authed(self) -> bool:
        return self._session() is not None

    def _role(self) -> str:
        """Return the role of the current session, or '' if unauthenticated."""
        s = self._session()
        return s["role"] if s else ""

    def _require_role(self, *roles: str) -> bool:
        """
        Return True if authenticated AND role is in `roles`.
        Sends 403 Forbidden (not 401) so the frontend can distinguish
        'not logged in' from 'logged in but not allowed'.
        """
        if not self._authed():
            self._json({"error": "Unauthorized"}, 401)
            return False
        if roles and self._role() not in roles:
            self._json({"error": "Forbidden", "role": self._role()}, 403)
            return False
        return True

    # Files under /frontend/ that must be publicly accessible
    _PUBLIC_FRONTEND = {"/frontend/login.js"}

    def _require_auth(self) -> bool:
        """Require any valid session — role not checked here."""
        if self._authed():
            return True
        p = urlparse(self.path).path
        api_paths = ("/alerts", "/flows", "/dns", "/http", "/events",
                     "/health", "/charts", "/webhooks", "/users", "/me")
        if p.startswith("/frontend/") and p not in self._PUBLIC_FRONTEND:
            self._json({"error": "Unauthorized"}, 401)
        elif any(p.startswith(x) for x in api_paths):
            self._json({"error": "Unauthorized"}, 401)
        else:
            self._redirect("/login")
        return False

    # ── Low-level response helpers ────────────────────────────────────────────

    def _redirect(self, location: str):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path: Path, content_type: str, no_cache: bool = True):
        if not path.exists():
            self.send_error(404, f"{path.name} not found")
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if no_cache:
            self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _qs_int(self, qs: dict, key: str, default: int,
                lo: int = 1, hi: int = 20000) -> int:
        try:
            return max(lo, min(int(qs.get(key, [default])[0]), hi))
        except (ValueError, TypeError):
            return default

    # ── Routing ───────────────────────────────────────────────────────────────

    def do_GET(self):
        p  = urlparse(self.path)
        qs = parse_qs(p.query)

        if p.path == "/login":
            self._file(FRONTEND_DIR / "login.html", "text/html; charset=utf-8")
            return
        if p.path == "/frontend/login.js":
            self._file(FRONTEND_DIR / "login.js", "application/javascript")
            return
        if p.path == "/logout":
            self._logout()
            return

        if not self._require_auth():
            return

        # Authenticated routes
        if p.path in ("/", "/index.html"):
            self._file(FRONTEND_DIR / "index.html", "text/html; charset=utf-8")
        elif p.path == "/events":
            self._serve_sse()
        elif p.path == "/alerts":
            self._serve_alerts(qs)
        elif p.path == "/flows":
            self._serve_table("flows", qs)
        elif p.path == "/dns":
            self._serve_table("dns", qs)
        elif p.path == "/http":
            self._serve_table("http", qs)
        elif p.path == "/charts":
            self._serve_charts(qs)
        elif re.match(r"^/alerts/[^/]+/ack/history$", p.path):
            alert_id = p.path.split("/")[2]
            self._json(self.db.fetch_ack_history(alert_id))
        elif p.path == "/webhooks":
            self._json(self.wdb.get_all())
        elif p.path == "/me":
            s = self._session()
            self._json({"username": s["username"], "role": s["role"]})
        elif p.path == "/users":
            if not self._require_role("admin"): return
            self._json(self.um.get_all())
        elif p.path == "/health":
            self._json({
                "status":  "ok",
                "clients": self.registry.count(),
                "db":      self.db.stats(),
                "time":    int(time.time()),
            })
        elif p.path.startswith("/frontend/"):
            self._serve_static(p.path)
        else:
            self.send_error(404)

    def do_POST(self):
        p = urlparse(self.path)
        if p.path == "/login":
            self._do_login()
            return
        if not self._require_auth():
            return
        if p.path == "/users":
            self._user_create()
        elif p.path == "/alerts/bulk-ack":
            self._bulk_ack_alerts()
        elif re.match(r"^/alerts/[^/]+/ack$", p.path):
            alert_id = p.path.split("/")[2]
            self._ack_alert(alert_id)
        elif p.path == "/webhooks":
            self._webhook_create()
        elif p.path.startswith("/webhooks/") and p.path.endswith("/test"):
            try:
                wid = int(p.path.split("/")[2])
                self._webhook_test(wid)
            except (ValueError, IndexError):
                self.send_error(400)
        else:
            self.send_error(404)

    def do_PUT(self):
        if not self._require_auth():
            return
        p = urlparse(self.path)
        if p.path.startswith("/users/"):
            try:
                uid = int(p.path.split("/")[2])
                self._user_update(uid)
            except (ValueError, IndexError):
                self.send_error(400)
        elif p.path.startswith("/webhooks/"):
            try:
                wid = int(p.path.split("/")[2])
                self._webhook_update(wid)
            except (ValueError, IndexError):
                self.send_error(400)
        else:
            self.send_error(404)

    def do_DELETE(self):
        if not self._require_auth():
            return
        p = urlparse(self.path)
        if p.path == "/alerts":
            if not self._require_role("admin"): return
            self._json({"deleted": self.db.clear_all()})
        elif p.path == "/flows":
            if not self._require_role("admin"): return
            self._json({"deleted": self.db.clear_flows()})
        elif p.path == "/dns":
            if not self._require_role("admin"): return
            self._json({"deleted": self.db.clear_dns()})
        elif p.path.startswith("/users/"):
            try:
                uid = int(p.path.split("/")[2])
                self._user_delete(uid)
            except (ValueError, IndexError):
                self.send_error(400)
        elif p.path.startswith("/webhooks/"):
            try:
                wid = int(p.path.split("/")[2])
                self.wdb.delete(wid)
                self._json({"deleted": wid})
            except (ValueError, IndexError):
                self.send_error(400)
        else:
            self.send_error(404)

    # ── Static files ──────────────────────────────────────────────────────────

    _MIME = {
        ".html": "text/html; charset=utf-8",
        ".js":   "application/javascript",
        ".jsx":  "application/javascript",
        ".css":  "text/css",
        ".ico":  "image/x-icon",
    }

    def _serve_static(self, url_path: str):
        """Serve files from the frontend/ directory."""
        # Strip leading /frontend/ and resolve safely inside FRONTEND_DIR
        rel = url_path.lstrip("/").removeprefix("frontend/")
        target = (FRONTEND_DIR / rel).resolve()

        # Security: prevent directory traversal
        try:
            target.relative_to(FRONTEND_DIR.resolve())
        except ValueError:
            self.send_error(403)
            return

        suffix  = target.suffix.lower()
        ctype   = self._MIME.get(suffix, "application/octet-stream")
        no_cache = suffix in (".html", ".jsx")
        self._file(target, ctype, no_cache=no_cache)

    # ── Login / logout ────────────────────────────────────────────────────────

    def _do_login(self):
        try:
            n    = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n))
            username = body.get("username", "").strip()
            pw       = body.get("password", "")
        except Exception:
            self._json({"error": "Bad request"}, 400)
            return

        # ── Primary: RBAC user login ──────────────────────────────────────────
        user = self.um.authenticate(username, pw) if username else None

        # ── Fallback: single-password (logs in as admin with username 'admin') ─
        if user is None and not username and self.auth.check_password(pw):
            user = {"username": "admin", "role": "admin"}

        # ── Also accept: username='admin', single-password ───────────────────
        if user is None and username.lower() == "admin" and self.auth.check_password(pw):
            user = {"username": "admin", "role": "admin"}

        if user:
            token = self.auth.create_session(
                username=user["username"], role=user["role"]
            )
            log.info("Login OK  user=%s role=%s from %s",
                     user["username"], user["role"], self.address_string())
            resp = json.dumps({"ok": True, "role": user["role"],
                               "username": user["username"]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header(
                "Set-Cookie",
                f"suri_session={token}; Path=/; HttpOnly; "
                f"SameSite=Strict; Max-Age={SESSION_TTL}",
            )
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
        else:
            log.warning("Failed login  user=%r from %s",
                        username or "(no username)", self.address_string())
            time.sleep(1)
            self._json({"error": "Invalid username or password"}, 401)

    def _logout(self):
        self.auth.revoke_session(self._token())
        self.send_response(302)
        self.send_header("Location", "/login")
        self.send_header(
            "Set-Cookie",
            "suri_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
        )
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ── Data endpoints ────────────────────────────────────────────────────────

    def _serve_table(self, table: str, qs: dict):
        """Serve flows/dns/http event history as JSON."""
        days  = self._qs_int(qs, "days",  RETAIN_DAYS, 1, RETAIN_DAYS)
        limit = self._qs_int(qs, "limit", 5000,         1, 20000)
        fetch = {
            "flows": self.db.fetch_flows,
            "dns":   self.db.fetch_dns,
            "http":  self.db.fetch_http,
        }.get(table)
        if fetch is None:
            self.send_error(404); return
        body = json.dumps(fetch(days=days, limit=limit)).encode()
        self.send_response(200)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control",  "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _serve_alerts(self, qs: dict):
        days  = self._qs_int(qs, "days",  RETAIN_DAYS, 1, RETAIN_DAYS)
        limit = self._qs_int(qs, "limit", 5000,         1, 20000)
        body  = json.dumps(self.db.fetch_recent(days=days, limit=limit)).encode()
        self.send_response(200)
        self.send_header("Content-Type",  "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _webhook_create(self):
        try:
            n    = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n))
        except Exception:
            self._json({"error": "Bad request"}, 400); return

        name       = str(body.get("name", "")).strip()
        wtype      = str(body.get("type", "generic")).strip()
        url        = str(body.get("url", "")).strip()
        severities = body.get("severities", ["critical", "high", "medium", "low", "info"])
        enabled    = bool(body.get("enabled", True))

        if not name or not url:
            self._json({"error": "name and url are required"}, 400); return
        if wtype not in ("slack", "discord", "generic"):
            self._json({"error": "type must be slack, discord, or generic"}, 400); return

        wh = self.wdb.create(name, wtype, url, severities, enabled)
        self._json(wh, 201)

    def _webhook_update(self, wid: int):
        if not self.wdb.get(wid):
            self._json({"error": "Not found"}, 404); return
        try:
            n    = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n))
        except Exception:
            self._json({"error": "Bad request"}, 400); return
        wh = self.wdb.update(wid, **body)
        self._json(wh)

    def _webhook_test(self, wid: int):
        wh = self.wdb.get(wid)
        if not wh:
            self._json({"error": "Not found"}, 404); return

        from webhooks import build_payload, deliver
        test_alert = {
            "id":       "test-0",
            "ts":       "2026-01-01T00:00:00+0000",
            "src_ip":   "10.0.0.1",
            "src_port": 12345,
            "dst_ip":   "8.8.8.8",
            "dst_port": 443,
            "proto":    "TCP",
            "iface":    "eth0",
            "flow_id":  0,
            "sig_id":   9999999,
            "sig_msg":  "Watcher Test Alert — webhook is working",
            "category": "Test",
            "severity": "medium",
            "action":   "allowed",
        }
        payload = build_payload(wh["type"], test_alert)
        error   = deliver(wh["url"], payload)
        if error:
            self._json({"ok": False, "error": error})
        else:
            self._json({"ok": True})

    def _serve_charts(self, qs: dict):
        """Return all chart data in a single JSON response."""
        days = self._qs_int(qs, "days", 1, 1, 90)
        trend_window = self._qs_int(qs, "trend", 24, 24, 2160)  # hours: 24h–90d (2160h)
        data = {
            "top_talkers":  self.db.chart_top_talkers(limit=10, days=days),
            "trend":        (self.db.chart_alert_trend(hours=trend_window)
                             if trend_window <= 24
                             else self.db.chart_alert_trend_days(days=trend_window // 24)),
            "by_category":  self.db.chart_by_category(days=days),
            "by_severity":  self.db.chart_by_severity(days=days),
            "window_hours": trend_window,
            "window_days":  days,
        }
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control",  "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _user_create(self):
        if not self._require_role("admin"): return
        try:
            n    = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n))
        except Exception:
            self._json({"error": "Bad request"}, 400); return
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", "")).strip()
        role     = str(body.get("role", "analyst")).strip()
        if not username or not password:
            self._json({"error": "username and password are required"}, 400); return
        if role not in ("admin", "analyst", "viewer"):
            self._json({"error": "role must be admin, analyst, or viewer"}, 400); return
        user = self.um.create(username, password, role)
        if user is None:
            self._json({"error": f"Username '{username}' already exists"}, 409); return
        self._json(user, 201)

    def _user_update(self, uid: int):
        if not self._require_role("admin"): return
        user = self.um.get_by_id(uid)
        if not user:
            self._json({"error": "Not found"}, 404); return
        try:
            n    = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n))
        except Exception:
            self._json({"error": "Bad request"}, 400); return
        # Password change is a separate field
        if "password" in body:
            pw = str(body.pop("password", "")).strip()
            if pw:
                self.um.set_password(uid, pw)
        # Guard: can't demote the last admin
        if body.get("role") and body["role"] != "admin":
            if user["role"] == "admin" and self.um.count_admins() <= 1:
                self._json({"error": "Cannot demote the last admin"}, 400); return
        if body.get("enabled") is not None:
            if not body["enabled"] and user["role"] == "admin":
                if self.um.count_admins() <= 1:
                    self._json({"error": "Cannot disable the last admin"}, 400); return
        updated = self.um.update(uid, **{k: v for k, v in body.items()
                                          if k in ("role", "enabled", "username")})
        self._json(updated)

    def _user_delete(self, uid: int):
        if not self._require_role("admin"): return
        user = self.um.get_by_id(uid)
        if not user:
            self._json({"error": "Not found"}, 404); return
        if user["role"] == "admin" and self.um.count_admins() <= 1:
            self._json({"error": "Cannot delete the last admin"}, 400); return
        # Don't let admin delete their own account
        s = self._session()
        if s and s["username"].lower() == user["username"].lower():
            self._json({"error": "Cannot delete your own account"}, 400); return
        self.um.delete(uid)
        self._json({"deleted": uid})

    def _bulk_ack_alerts(self):
        """POST /alerts/bulk-ack — acknowledge multiple alerts at once."""
        if self._role() == "viewer":
            self._json({"error": "Forbidden"}, 403); return
        try:
            n    = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n)) if n else {}
        except Exception:
            self._json({"error": "Bad request"}, 400); return
        ids    = body.get("ids", [])
        status = str(body.get("status", "")).strip()
        note   = str(body.get("note",   "")).strip()
        if not ids or not isinstance(ids, list):
            self._json({"error": "ids must be a non-empty list"}, 400); return
        s        = self._session()
        username = s["username"] if s else ""
        updated  = self.db.bulk_acknowledge(ids, status, note, username)
        self._json({"ok": True, "updated": updated})

    def _ack_alert(self, alert_id: str):
        """POST /alerts/<id>/ack — set status and optional note."""
        # Viewer cannot acknowledge
        if self._role() == "viewer":
            self._json({"error": "Forbidden"}, 403); return
        try:
            n    = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n)) if n else {}
        except Exception:
            self._json({"error": "Bad request"}, 400); return
        status = str(body.get("status", "")).strip()
        note   = str(body.get("note",   "")).strip()
        s      = self._session()
        username = s["username"] if s else ""
        ok = self.db.acknowledge(alert_id, status, note, username)
        if ok:
            self._json({"ok": True, "id": alert_id,
                        "status": status, "note": note, "by": username})
        else:
            self._json({"error": "Alert not found or invalid status"}, 404)

    def _serve_sse(self):
        """Long-lived SSE response — blocks until client disconnects."""
        self.send_response(200)
        self.send_header("Content-Type",      "text/event-stream")
        self.send_header("Cache-Control",     "no-cache")
        self.send_header("Connection",        "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        cid, q = self.registry.add()

        # Immediate ping so the browser confirms the connection is alive
        try:
            self.wfile.write(
                f"event: ping\ndata: {int(time.time())}\n\n".encode()
            )
            self.wfile.flush()
        except Exception:
            self.registry.remove(cid)
            return

        # Drain queue, sending alerts and keep-alive pings
        while True:
            try:
                msg = q.get(timeout=PING_EVERY)
            except Empty:
                msg = f"event: ping\ndata: {int(time.time())}\n\n"
            try:
                self.wfile.write(msg.encode())
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                break

        self.registry.remove(cid)
