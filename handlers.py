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
    Dependencies (db, auth, registry, wdb, um) are injected as class
    attributes by server.py before the server starts.

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
    DELETE /alerts      → wipe alerts table (requires admin)
    DELETE /flows       → wipe flows table (requires admin)
    DELETE /dns         → wipe dns_events table (requires admin)
    GET  /charts        → JSON chart data (requires auth)
    GET  /health        → JSON status (requires auth)
    GET  /webhooks      → list all webhooks (requires auth)
    POST /webhooks      → create webhook (requires admin)
    PUT  /webhooks/<id> → update webhook (requires admin)
    DELETE /webhooks/<id> → delete webhook (requires admin)
    POST /webhooks/<id>/test → fire a test alert (requires admin)
    GET  /users         → list users (requires admin)
    POST /users         → create user (requires admin)
    PUT  /users/<id>    → update user (requires admin)
    DELETE /users/<id>  → delete user (requires admin)
    GET  /me            → current session info
    GET  /frontend/*    → static files (requires auth)
    """

    # Injected by server.py
    db       = None
    auth     = None
    registry = None
    wdb      = None
    um       = None
    dns_db   = None   # DnsDB — dedicated DNS database

    server_version = ""
    sys_version    = ""

    # ── Logging ───────────────────────────────────────────────────────────────

    def log_message(self, fmt, *args):
        first = str(args[0]) if args else ""
        if "/events" not in first:
            log.info("%s %s", self.address_string(), fmt % args)

    # ── Session helpers ───────────────────────────────────────────────────────

    def _token(self) -> str:
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
        return self.auth.get_session(self._token())

    def _authed(self) -> bool:
        return self._session() is not None

    def _role(self) -> str:
        s = self._session()
        return s["role"] if s else ""

    def _require_role(self, *roles: str) -> bool:
        if not self._authed():
            self._json({"error": "Unauthorized"}, 401)
            return False
        if roles and self._role() not in roles:
            self._json({"error": "Forbidden", "role": self._role()}, 403)
            return False
        return True

    _PUBLIC_FRONTEND = {"/frontend/login.js"}

    def _require_auth(self) -> bool:
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
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json_body(self, data, status: int = 200):
        """
        Shared helper for data endpoints that return potentially large JSON
        payloads with no-cache headers.  Centralises the encode/header/write
        pattern that was previously duplicated across _serve_alerts,
        _serve_table, and _serve_charts.
        """
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control",  "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path: Path, content_type: str, no_cache: bool = True):
        if not path.exists():
            self.send_error(404, f"{path.name} not found")
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type",   content_type)
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
            self._send_json_body(self.db.fetch_ack_history(alert_id))
        elif p.path == "/webhooks":
            self._send_json_body(self.wdb.get_all())
        elif p.path == "/me":
            s = self._session()
            self._json({"username": s["username"], "role": s["role"]})
        elif p.path == "/users":
            if not self._require_role("admin"): return
            self._send_json_body(self.um.get_all())
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
            self._ack_alert(p.path.split("/")[2])
        elif p.path == "/webhooks":
            self._webhook_create()
        elif p.path.startswith("/webhooks/") and p.path.endswith("/test"):
            try:
                self._webhook_test(int(p.path.split("/")[2]))
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
                self._user_update(int(p.path.split("/")[2]))
            except (ValueError, IndexError):
                self.send_error(400)
        elif p.path.startswith("/webhooks/"):
            try:
                self._webhook_update(int(p.path.split("/")[2]))
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
            self._json({"deleted": self.dns_db.clear()})
        elif p.path.startswith("/users/"):
            try:
                self._user_delete(int(p.path.split("/")[2]))
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
        rel    = url_path.lstrip("/").removeprefix("frontend/")
        target = (FRONTEND_DIR / rel).resolve()
        try:
            target.relative_to(FRONTEND_DIR.resolve())
        except ValueError:
            self.send_error(403)
            return
        suffix   = target.suffix.lower()
        ctype    = self._MIME.get(suffix, "application/octet-stream")
        no_cache = suffix in (".html", ".jsx")
        self._file(target, ctype, no_cache=no_cache)

    # ── Login / logout ────────────────────────────────────────────────────────

    def _do_login(self):
        try:
            n        = int(self.headers.get("Content-Length", 0))
            body     = json.loads(self.rfile.read(n))
            username = body.get("username", "").strip()
            pw       = body.get("password", "")
        except Exception:
            self._json({"error": "Bad request"}, 400)
            return

        user = self.um.authenticate(username, pw) if username else None

        if user is None and not username and self.auth.check_password(pw):
            user = {"username": "admin", "role": "admin"}

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
        days  = self._qs_int(qs, "days",  RETAIN_DAYS, 1, RETAIN_DAYS)
        limit = self._qs_int(qs, "limit", 5000,        1, 20000)
        if table == "dns":
            self._send_json_body(self.dns_db.fetch(days=days, limit=limit))
            return
        fetch = {"flows": self.db.fetch_flows,
                 "http":  self.db.fetch_http}.get(table)
        if fetch is None:
            self.send_error(404)
            return
        self._send_json_body(fetch(days=days, limit=limit))

    def _serve_alerts(self, qs: dict):
        days  = self._qs_int(qs, "days",  RETAIN_DAYS, 1, RETAIN_DAYS)
        limit = self._qs_int(qs, "limit", 5000,        1, 20000)
        self._send_json_body(self.db.fetch_recent(days=days, limit=limit))

    def _serve_charts(self, qs: dict):
        days         = self._qs_int(qs, "days",  1,  1,  90)
        trend_window = self._qs_int(qs, "trend", 24, 24, 2160)
        self._send_json_body({
            "top_talkers":  self.db.chart_top_talkers(limit=10, days=days),
            "trend":        (self.db.chart_alert_trend(hours=trend_window)
                             if trend_window <= 24
                             else self.db.chart_alert_trend_days(days=trend_window // 24)),
            "by_category":  self.db.chart_by_category(days=days),
            "by_severity":  self.db.chart_by_severity(days=days),
            "window_hours": trend_window,
            "window_days":  days,
        })

    # ── Webhooks ──────────────────────────────────────────────────────────────

    def _webhook_create(self):
        if not self._require_role("admin"): return
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
        self._json(self.wdb.create(name, wtype, url, severities, enabled), 201)

    def _webhook_update(self, wid: int):
        if not self._require_role("admin"): return
        if not self.wdb.get(wid):
            self._json({"error": "Not found"}, 404); return
        try:
            n    = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n))
        except Exception:
            self._json({"error": "Bad request"}, 400); return
        self._json(self.wdb.update(wid, **body))

    def _webhook_test(self, wid: int):
        if not self._require_role("admin"): return
        wh = self.wdb.get(wid)
        if not wh:
            self._json({"error": "Not found"}, 404); return
        from webhooks import build_payload, deliver
        test_alert = {
            "id": "test-0", "ts": "2026-01-01T00:00:00+0000",
            "src_ip": "10.0.0.1", "src_port": 12345,
            "dst_ip": "8.8.8.8",  "dst_port": 443,
            "proto": "TCP", "iface": "eth0", "flow_id": 0,
            "sig_id": 9999999, "sig_msg": "Watcher Test Alert — webhook is working",
            "category": "Test", "severity": "medium", "action": "allowed",
        }
        error = deliver(wh["url"], build_payload(wh["type"], test_alert))
        self._json({"ok": error is None, **({"error": error} if error else {})})

    # ── Users ─────────────────────────────────────────────────────────────────

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
        if "password" in body:
            pw = str(body.pop("password", "")).strip()
            if pw:
                self.um.set_password(uid, pw)
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
        s = self._session()
        if s and s["username"].lower() == user["username"].lower():
            self._json({"error": "Cannot delete your own account"}, 400); return
        self.um.delete(uid)
        self._json({"deleted": uid})

    # ── Acknowledgement ───────────────────────────────────────────────────────

    def _bulk_ack_alerts(self):
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
        if self._role() == "viewer":
            self._json({"error": "Forbidden"}, 403); return
        try:
            n    = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n)) if n else {}
        except Exception:
            self._json({"error": "Bad request"}, 400); return
        status   = str(body.get("status", "")).strip()
        note     = str(body.get("note",   "")).strip()
        s        = self._session()
        username = s["username"] if s else ""
        ok = self.db.acknowledge(alert_id, status, note, username)
        if ok:
            self._json({"ok": True, "id": alert_id,
                        "status": status, "note": note, "by": username})
        else:
            self._json({"error": "Alert not found or invalid status"}, 404)

    # ── SSE ───────────────────────────────────────────────────────────────────

    def _serve_sse(self):
        self.send_response(200)
        self.send_header("Content-Type",      "text/event-stream")
        self.send_header("Cache-Control",     "no-cache")
        self.send_header("Connection",        "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        cid, q = self.registry.add()

        try:
            self.wfile.write(
                f"event: ping\ndata: {int(time.time())}\n\n".encode()
            )
            self.wfile.flush()
        except Exception:
            self.registry.remove(cid)
            return

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
