"""
Watcher IDS Dashboard — HTTP Request Handler
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
    db       = None
    auth     = None
    registry = None
    wdb      = None
    um       = None
    dns_db   = None
    ti_db    = None
    sup_db   = None
    explain_engine = None
    # Stats cache: (data, expires_at) — avoids 7 DB queries on every /health poll
    _stats_cache: "tuple | None" = None
    _stats_lock = __import__("threading").Lock()
    eve_path = None   # pathlib.Path to eve.json — set by server.py
    # Replay state: None | "running" | { result dict }
    _replay_state: "dict | str | None" = None
    _replay_lock = __import__("threading").Lock()
    # Login rate limit: {ip: [timestamp, ...]} — max 10 attempts per 5 min window
    _login_attempts: dict = {}
    _login_lock = __import__("threading").Lock()

    server_version = ""
    sys_version    = ""

    def log_message(self, fmt, *args):
        first = str(args[0]) if args else ""
        if "/events" not in first:
            log.info("%s %s", self.address_string(), fmt % args)

    # ── Session ───────────────────────────────────────────────────────────────

    def _token(self):
        raw = self.headers.get("Cookie", "")
        if not raw:
            return ""
        try:
            c = SimpleCookie(raw)
            m = c.get("suri_session")
            return m.value if m else ""
        except Exception:
            return ""

    def _session(self):
        return self.auth.get_session(self._token())

    def _authed(self):
        return self._session() is not None

    def _role(self):
        s = self._session()
        return s["role"] if s else ""

    def _require_role(self, *roles):
        if not self._authed():
            self._json({"error": "Unauthorized"}, 401)
            return False
        if roles and self._role() not in roles:
            self._json({"error": "Forbidden"}, 403)
            return False
        return True

    _PUBLIC = {"/frontend/login.js"}

    def _require_auth(self):
        if self._authed():
            return True
        p = urlparse(self.path).path
        api = ("/alerts", "/flows", "/dns", "/http", "/events",
               "/health", "/charts", "/webhooks", "/users", "/me",
               "/threat-intel", "/suppression", "/settings")
        if p.startswith("/frontend/") and p not in self._PUBLIC:
            self._json({"error": "Unauthorized"}, 401)
        elif any(p.startswith(x) for x in api):
            self._json({"error": "Unauthorized"}, 401)
        else:
            self._redirect("/login")
        return False

    # ── Response helpers ──────────────────────────────────────────────────────

    def _redirect(self, loc):
        self.send_response(302)
        self.send_header("Location", loc)
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ── Engine status ─────────────────────────────────────────────────────────
    _ENGINE_IDLE_SECS = 30   # seconds since last write before status → idle

    @classmethod
    def _engine_status(cls) -> dict:
        """
        Determine Suricata engine status by inspecting eve.json mtime.

        Returns:
          { "status": "running" | "idle" | "stopped",
            "mtime":  <epoch float | null> }

        running : eve.json modified within last 30 s  → engine is processing traffic
        idle    : eve.json exists but older than 30 s → engine up, no recent traffic
        stopped : eve.json missing / unreadable        → engine down or not configured
        """
        if cls.eve_path is None:
            return {"status": "stopped", "mtime": None}
        try:
            mtime  = cls.eve_path.stat().st_mtime
            age    = time.time() - mtime
            status = "running" if age <= cls._ENGINE_IDLE_SECS else "idle"
            return {"status": status, "mtime": mtime}
        except OSError:
            return {"status": "stopped", "mtime": None}

    def _security_headers(self):
        """Emit security headers on every response."""
        self.send_header("X-Content-Type-Options",  "nosniff")
        self.send_header("X-Frame-Options",         "DENY")
        self.send_header("Referrer-Policy",         "no-referrer")
        self.send_header("Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "font-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'")

    def _json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control",  "no-cache")
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path, content_type, no_cache=True, cache_control=""):
        if not path.exists():
            self.send_error(404, f"{path.name} not found")
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type",   content_type)
        self.send_header("Content-Length", str(len(data)))
        if cache_control:
            self.send_header("Cache-Control", cache_control)
        elif no_cache:
            self.send_header("Cache-Control", "no-cache")
        self._security_headers()
        self.end_headers()
        self.wfile.write(data)

    _MAX_BODY = 1_048_576  # 1 MB hard cap — prevents memory exhaustion

    def _read_json(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            if n > self._MAX_BODY:
                self._json({"error": "Request body too large"}, 413)
                return None
            return json.loads(self.rfile.read(n)) if n else {}
        except Exception:
            self._json({"error": "Bad request"}, 400)
            return None

    def _qs_int(self, qs, key, default, lo=1, hi=20000):
        try:
            return max(lo, min(int(qs.get(key, [default])[0]), hi))
        except (ValueError, TypeError):
            return default

    # ── Routing ───────────────────────────────────────────────────────────────

    def do_GET(self):
        p  = urlparse(self.path)
        qs = parse_qs(p.query)
        path = p.path

        if path == "/login":
            self._file(FRONTEND_DIR / "login.html", "text/html; charset=utf-8"); return
        if path == "/frontend/login.js":
            self._file(FRONTEND_DIR / "login.js", "application/javascript"); return
        if path == "/logout":
            self._logout(); return

        if not self._require_auth():
            return

        if path in ("/", "/index.html"):
            self._file(FRONTEND_DIR / "index.html", "text/html; charset=utf-8")
        elif path == "/events":
            self._serve_sse()
        elif path == "/alerts":
            self._serve_alerts(qs)
        elif path == "/flows":
            self._serve_table("flows", qs)
        elif path == "/dns":
            self._serve_table("dns", qs)
        elif path == "/http":
            self._serve_table("http", qs)
        elif path == "/charts":
            self._serve_charts(qs)
        elif re.match(r"^/alerts/[^/]+/ack/history$", path):
            self._json(self.db.fetch_ack_history(path.split("/")[2]))
        elif re.match(r"^/alerts/[^/]+/raw$", path):
            raw = self.db.fetch_raw(path.split("/")[2])
            if raw is None:
                self.send_error(404)
            else:
                self._json(raw)
        elif path == "/webhooks":
            self._json(self.wdb.get_all())
        elif path == "/settings/explain":
            if not self._require_auth(): return
            self._json(self.explain_engine.get_config())
        elif path == "/me":
            s = self._session()
            self._json({"username": s["username"], "role": s["role"]})
        elif path == "/users":
            if not self._require_role("admin"): return
            self._json(self.um.get_all())
        elif path == "/health":
            now = time.time()
            with Handler._stats_lock:
                if Handler._stats_cache is None or Handler._stats_cache[1] < now:
                    Handler._stats_cache = (self.db.stats(), now + 5)
                cached = Handler._stats_cache[0]
            self._json({"status": "ok",
                        "clients": self.registry.count(),
                        "db":      cached,
                        "engine":  self._engine_status(),
                        "time":    int(now)})
        elif path == "/threat-intel":
            self._json(self.ti_db.get_all())
        elif path == "/threat-intel/lookup":
            sid = qs.get("sig_id", [None])[0]
            cat = qs.get("category", [None])[0]
            self._json(self.ti_db.lookup(
                sig_id=int(sid) if sid else None, category=cat) or {})
        elif path == "/threat-intel/gaps":
            top = self.db.top_sids(limit=200)
            self._json(self.ti_db.coverage_gaps(top, limit=20))
        elif path == "/threat-intel/stats":
            self._json(self.ti_db.stats())
        elif path == "/threat-intel/export":
            if not self._require_auth(): return
            data     = self.ti_db.export_all()
            body     = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type",        "application/json; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="watcher-threat-intel.json"')
            self.send_header("Content-Length",      str(len(body)))
            self._security_headers()
            self.end_headers()
            self.wfile.write(body)
        elif path == "/suppression":
            self._json(self.sup_db.get_all())
        elif path == "/admin/replay":
            if not self._require_role("admin"): return
            with Handler._replay_lock:
                state = Handler._replay_state
            self._json({"status": state if isinstance(state, str) else "idle",
                        "result": state if isinstance(state, dict) else None})
        elif path.startswith("/frontend/"):
            self._serve_static(path)
        else:
            self.send_error(404)

    def do_POST(self):
        p    = urlparse(self.path)
        path = p.path

        if path == "/login":
            self._do_login(); return
        if not self._require_auth():
            return

        if path == "/users":
            self._user_create()
        elif path == "/alerts/bulk-ack":
            self._bulk_ack()
        elif path == "/alerts/delete-selected":
            self._delete_selected()
        elif re.match(r"^/alerts/[^/]+/ack$", path):
            self._ack_alert(path.split("/")[2])
        elif path == "/webhooks":
            self._webhook_create()
        elif re.match(r"^/webhooks/\d+/test$", path):
            self._webhook_test(int(path.split("/")[2]))
        elif path == "/alerts/explain":
            self._explain_get_or_create()
        elif path == "/threat-intel":
            self._ti_create()
        elif path == "/threat-intel/import":
            self._ti_import()
        elif path == "/suppression":
            self._sup_create()
        elif path == "/admin/replay":
            self._admin_replay()
        else:
            self.send_error(404)

    def do_PUT(self):
        if not self._require_auth():
            return
        p    = urlparse(self.path)
        path = p.path

        if re.match(r"^/users/\d+$", path):
            self._user_update(int(path.split("/")[2]))
        elif re.match(r"^/webhooks/\d+$", path):
            self._webhook_update(int(path.split("/")[2]))
        elif path == "/settings/explain":
            self._explain_settings_update()
        elif re.match(r"^/threat-intel/\d+$", path):
            self._ti_update(int(path.split("/")[2]))
        elif re.match(r"^/suppression/\d+$", path):
            self._sup_update(int(path.split("/")[2]))
        else:
            self.send_error(404)

    def do_DELETE(self):
        if not self._require_auth():
            return
        p    = urlparse(self.path)
        path = p.path

        if path == "/alerts":
            if not self._require_role("admin"): return
            self._json({"deleted": self.db.clear_all()})
        elif path == "/flows":
            if not self._require_role("admin"): return
            self._json({"deleted": self.db.clear_flows()})
        elif path == "/dns":
            if not self._require_role("admin"): return
            self._json({"deleted": self.dns_db.clear()})
        elif re.match(r"^/users/\d+$", path):
            self._user_delete(int(path.split("/")[2]))
        elif re.match(r"^/webhooks/\d+$", path):
            if not self._require_role("admin"): return
            wid = int(path.split("/")[2])
            self.wdb.delete(wid)
            self._json({"deleted": wid})
        elif re.match(r"^/threat-intel/\d+$", path):
            self._ti_delete(int(path.split("/")[2]))
        elif re.match(r"^/suppression/\d+$", path):
            self._sup_delete(int(path.split("/")[2]))
        elif path == "/admin/flush":
            self._admin_flush()
        else:
            self.send_error(404)

    # ── Static files ──────────────────────────────────────────────────────────

    _MIME = {
        ".html": "text/html; charset=utf-8",
        ".js":   "application/javascript",
        ".css":  "text/css",
        ".ico":  "image/x-icon",
        ".svg":  "image/svg+xml",
        ".woff2":"font/woff2",
        ".woff": "font/woff",
    }

    def _serve_static(self, url_path):
        rel    = url_path.lstrip("/").removeprefix("frontend/")
        target = (FRONTEND_DIR / rel).resolve()
        try:
            target.relative_to(FRONTEND_DIR.resolve())
        except ValueError:
            self.send_error(403); return
        suffix = target.suffix.lower()
        ctype  = self._MIME.get(suffix, "application/octet-stream")
        if url_path.startswith("/frontend/assets/"):
            self._file(target, ctype,
                       cache_control="public, max-age=31536000, immutable")
        else:
            self._file(target, ctype, no_cache=suffix == ".html")

    # ── Login / logout ────────────────────────────────────────────────────────

    _RATE_WINDOW  = 300   # 5-minute window
    _RATE_MAX     = 10    # max attempts per window per IP

    def _check_rate_limit(self) -> bool:
        """Return True (blocked) if this IP has too many recent login failures."""
        ip  = self.address_string()
        now = time.time()
        cutoff = now - self._RATE_WINDOW
        with self._login_lock:
            attempts = [t for t in self._login_attempts.get(ip, []) if t > cutoff]
            self._login_attempts[ip] = attempts
            return len(attempts) >= self._RATE_MAX

    def _record_failure(self):
        ip = self.address_string()
        with self._login_lock:
            self._login_attempts.setdefault(ip, []).append(time.time())

    def _clear_failures(self):
        ip = self.address_string()
        with self._login_lock:
            self._login_attempts.pop(ip, None)

    def _do_login(self):
        if self._check_rate_limit():
            log.warning("Login rate-limited for %s", self.address_string())
            time.sleep(2)
            self._json({"error": "Too many login attempts. Try again later."}, 429)
            return
        try:
            n    = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n))
            username = body.get("username", "").strip()
            pw       = body.get("password", "")
        except Exception:
            self._json({"error": "Bad request"}, 400); return

        user = self.um.authenticate(username, pw) if username else None

        if user is None and username.lower() == "admin" and self.auth.check_password(pw):
            user = {"username": "admin", "role": "admin"}

        if user:
            self._clear_failures()
            token = self.auth.create_session(username=user["username"], role=user["role"])
            log.info("Login OK  user=%s role=%s from %s",
                     user["username"], user["role"], self.address_string())
            resp = json.dumps({"ok": True, "role": user["role"],
                               "username": user["username"]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie",
                f"suri_session={token}; Path=/; HttpOnly; "
                f"SameSite=Strict; Max-Age={SESSION_TTL}")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
        else:
            self._record_failure()
            log.warning("Failed login user=%r from %s",
                        username or "(none)", self.address_string())
            time.sleep(1)
            self._json({"error": "Invalid username or password"}, 401)

    def _logout(self):
        self.auth.revoke_session(self._token())
        self.send_response(302)
        self.send_header("Location", "/login")
        self.send_header("Set-Cookie",
            "suri_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ── Data ──────────────────────────────────────────────────────────────────

    def _serve_alerts(self, qs):
        days   = self._qs_int(qs, "days",   RETAIN_DAYS, 1, RETAIN_DAYS)
        limit  = self._qs_int(qs, "limit",  300,  1, 5000)
        offset = self._qs_int(qs, "offset", 0,    0, 10_000_000)
        q      = (qs.get("q", [""])[0] or "").strip()

        # Full-database search: bypass pagination cache, query all fields
        if q:
            self._json(self.db.search_alerts(
                q, days=days, limit=limit, offset=offset))
            return

        # Pass cached total from stats (avoids COUNT(*) on every paginated request)
        cached_total = None
        if Handler._stats_cache:
            cached_total = Handler._stats_cache[0].get("alerts", {}).get("window")
        self._json(self.db.fetch_recent(days=days, limit=limit, offset=offset,
                                        _precomputed_total=cached_total))

    def _serve_table(self, table, qs):
        days   = self._qs_int(qs, "days",   RETAIN_DAYS, 1, RETAIN_DAYS)
        limit  = self._qs_int(qs, "limit",  300, 1, 5000)
        offset = self._qs_int(qs, "offset", 0,   0, 10_000_000)
        if table == "dns":
            self._json(self.dns_db.fetch(days=days, limit=limit, offset=offset))
            return
        fn = {"flows": self.db.fetch_flows, "http": self.db.fetch_http}.get(table)
        if fn is None:
            self.send_error(404); return
        self._json(fn(days=days, limit=limit))

    def _serve_charts(self, qs):
        days  = self._qs_int(qs, "days",  1,  1, 90)
        trend = self._qs_int(qs, "trend", 24, 24, 2160)
        self._json({
            "top_talkers": self.db.chart_top_talkers(limit=10, days=days),
            "trend": (self.db.chart_alert_trend(hours=trend)
                      if trend <= 24
                      else self.db.chart_alert_trend_days(days=trend // 24)),
            "by_category": self.db.chart_by_category(days=days),
            "by_severity": self.db.chart_by_severity(days=days),
        })

    # ── Ack ───────────────────────────────────────────────────────────────────

    def _ack_alert(self, alert_id):
        if self._role() == "viewer":
            self._json({"error": "Forbidden"}, 403); return
        body = self._read_json()
        if body is None: return
        s        = self._session()
        username = s["username"] if s else ""
        ok = self.db.acknowledge(
            alert_id, body.get("status", ""), body.get("note", ""), username)
        if ok:
            self._json({"ok": True})
        else:
            self._json({"error": "Alert not found or invalid status"}, 404)

    def _bulk_ack(self):
        if self._role() == "viewer":
            self._json({"error": "Forbidden"}, 403); return
        body = self._read_json()
        if body is None: return
        ids    = body.get("ids", [])
        status = str(body.get("status", "")).strip()
        note   = str(body.get("note",   "")).strip()
        if not ids or not isinstance(ids, list):
            self._json({"error": "ids must be a non-empty list"}, 400); return
        s       = self._session()
        updated = self.db.bulk_acknowledge(ids, status, note, s["username"] if s else "")
        self._json({"ok": True, "updated": updated})

    def _delete_selected(self):
        if not self._require_role("admin"): return
        body = self._read_json()
        if body is None: return
        ids = body.get("ids", [])
        if not ids or not isinstance(ids, list):
            self._json({"error": "ids must be a non-empty list"}, 400); return
        self._json({"ok": True, "deleted": self.db.delete_by_ids(ids)})

    # ── Webhooks ──────────────────────────────────────────────────────────────

    def _webhook_create(self):
        if not self._require_role("admin"): return
        body = self._read_json()
        if body is None: return
        name            = str(body.get("name",  "")).strip()
        wtype           = str(body.get("type",  "generic")).strip()
        url             = str(body.get("url",   "")).strip()
        allow_local_ips = bool(body.get("allow_local_ips", False))
        if not name or not url:
            self._json({"error": "name and url are required"}, 400); return
        if wtype not in ("slack", "discord", "generic"):
            self._json({"error": "type must be slack, discord, or generic"}, 400); return
        from webhooks import validate_webhook_url
        err = validate_webhook_url(url, allow_local=allow_local_ips)
        if err:
            self._json({"error": err}, 400); return
        self._json(self.wdb.create(
            name, wtype, url,
            body.get("severities", ["critical","high","medium","low","info"]),
            bool(body.get("enabled", True)),
            allow_local_ips), 201)

    def _webhook_update(self, wid):
        if not self._require_role("admin"): return
        existing = self.wdb.get(wid)
        if not existing:
            self._json({"error": "Not found"}, 404); return
        body = self._read_json()
        if body is None: return
        if "url" in body:
            from webhooks import validate_webhook_url
            allow_local = bool(body.get("allow_local_ips",
                               existing.get("allow_local_ips", False)))
            err = validate_webhook_url(str(body["url"]).strip(), allow_local=allow_local)
            if err:
                self._json({"error": err}, 400); return
        self._json(self.wdb.update(wid, **body))

    def _webhook_test(self, wid):
        if not self._require_role("admin"): return
        wh = self.wdb.get(wid)
        if not wh:
            self._json({"error": "Not found"}, 404); return
        from webhooks import validate_webhook_url
        allow_local = wh.get("allow_local_ips", False)
        err = validate_webhook_url(wh["url"], allow_local=allow_local)
        if err:
            self._json({"error": f"Blocked: {err}"}, 400); return
        from webhooks import build_payload, deliver
        test_alert = {
            "id": "test-0", "ts": "2026-01-01T00:00:00+0000",
            "src_ip": "10.0.0.1", "src_port": 12345,
            "dst_ip": "8.8.8.8",  "dst_port": 443,
            "proto": "TCP", "iface": "eth0", "flow_id": 0,
            "sig_id": 9999999, "sig_msg": "Watcher Test Alert",
            "category": "Test", "severity": "medium", "action": "allowed",
        }
        # BUG FIX: pass allow_local so the delivery respects the
        # "Allow Local / Private IPs" setting during test calls.
        err = deliver(wh["url"], build_payload(wh["type"], test_alert),
                      allow_local=allow_local)
        self._json({"ok": err is None, **({} if not err else {"error": err})})

    # ── Users ─────────────────────────────────────────────────────────────────

    def _user_create(self):
        if not self._require_role("admin"): return
        body = self._read_json()
        if body is None: return
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", "")).strip()
        role     = str(body.get("role", "analyst")).strip()
        if not username or not password:
            self._json({"error": "username and password are required"}, 400); return
        if role not in ("admin", "analyst", "viewer"):
            self._json({"error": "Invalid role"}, 400); return
        user = self.um.create(username, password, role)
        if user is None:
            self._json({"error": f"Username '{username}' already exists"}, 409); return
        self._json(user, 201)

    def _user_update(self, uid):
        if not self._require_role("admin"): return
        user = self.um.get_by_id(uid)
        if not user:
            self._json({"error": "Not found"}, 404); return
        body = self._read_json()
        if body is None: return
        pw = str(body.pop("password", "")).strip()
        if pw:
            self.um.set_password(uid, pw)
            # Invalidate all active sessions for this user so re-login is forced
            self.auth.revoke_sessions_for_user(user.get("username", ""))
        if body.get("role") and body["role"] not in ("admin", "analyst", "viewer"):
            self._json({"error": "Invalid role"}, 400); return
        if user["role"] == "admin" and self.um.count_admins() <= 1:
            if body.get("role") and body["role"] != "admin":
                self._json({"error": "Cannot demote the last admin"}, 400); return
            if body.get("enabled") is False:
                self._json({"error": "Cannot disable the last admin"}, 400); return
        updated = self.um.update(uid, **{k: v for k, v in body.items()
                                          if k in ("role", "enabled", "username")})
        self._json(updated)

    def _user_delete(self, uid):
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

    # ── Threat Intel ──────────────────────────────────────────────────────────

    def _ti_create(self):
        if not self._require_role("admin", "analyst"): return
        body = self._read_json()
        if body is None: return
        explanation = str(body.get("explanation", "")).strip()
        if not explanation:
            self._json({"error": "explanation is required"}, 400); return
        sig_id   = body.get("sig_id")
        category = str(body.get("category", "")).strip() or None
        if not sig_id and not category:
            self._json({"error": "Either sig_id or category is required"}, 400); return
        s = self._session()
        self._json(self.ti_db.create(
            sig_id      = sig_id,
            sig_msg     = str(body.get("sig_msg", "")).strip() or None,
            category    = category,
            explanation = explanation,
            tags        = body.get("tags", []),
            refs        = body.get("refs", []),
            created_by  = s["username"] if s else "",
        ), 201)

    def _ti_update(self, tid):
        if not self._require_role("admin", "analyst"): return
        if not self.ti_db.get_by_id(tid):
            self._json({"error": "Not found"}, 404); return
        body = self._read_json()
        if body is None: return
        self._json(self.ti_db.update(tid, **body))

    def _ti_delete(self, tid):
        if not self._require_role("admin"): return
        if not self.ti_db.get_by_id(tid):
            self._json({"error": "Not found"}, 404); return
        self.ti_db.delete(tid)
        self._json({"deleted": tid})

    # ── Suppression ───────────────────────────────────────────────────────────

    def _sup_create(self):
        if not self._require_role("admin"): return
        body = self._read_json()
        if body is None: return
        name     = str(body.get("name", "")).strip()
        sig_id   = body.get("sig_id")
        src_ip   = str(body.get("src_ip",   "")).strip() or None
        category = str(body.get("category", "")).strip() or None
        if not name:
            self._json({"error": "name is required"}, 400); return
        if not sig_id and not src_ip and not category:
            self._json({"error": "At least one of sig_id, src_ip, or category is required"}, 400)
            return
        s = self._session()
        self._json(self.sup_db.create(
            name       = name,
            sig_id     = sig_id,
            src_ip     = src_ip,
            category   = category,
            reason     = str(body.get("reason", "")).strip() or None,
            expires_at = body.get("expires_at"),
            created_by = s["username"] if s else "",
        ), 201)

    def _sup_update(self, rule_id):
        if not self._require_role("admin"): return
        if not self.sup_db.get_by_id(rule_id):
            self._json({"error": "Not found"}, 404); return
        body = self._read_json()
        if body is None: return
        self._json(self.sup_db.update(rule_id, **body))

    def _sup_delete(self, rule_id):
        if not self._require_role("admin"): return
        if not self.sup_db.get_by_id(rule_id):
            self._json({"error": "Not found"}, 404); return
        self.sup_db.delete(rule_id)
        self._json({"deleted": rule_id})

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
                f"event: ping\ndata: {int(time.time())}\n\n".encode())
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

    # ── AI Explain ────────────────────────────────────────────────────────────

    def _explain_get_or_create(self):
        """POST /alerts/explain — return cached or freshly generated explanation."""
        if not self._require_auth(): return
        body = self._read_json()
        if body is None: return

        sig_id = body.get("sig_id")
        if not sig_id:
            self._json({"error": "sig_id is required"}, 400); return

        try:
            sig_id = int(sig_id)
        except (ValueError, TypeError):
            self._json({"error": "sig_id must be an integer"}, 400); return

        if not self.explain_engine.has_key():
            from explain import PROVIDERS as _AI_P
            active = self.explain_engine.active_provider()
            label  = _AI_P.get(active, {}).get("label", active)
            env_k  = _AI_P.get(active, {}).get("env_key", "API_KEY")
            self._json({"error": "no_key",
                        "message": f"No {label} API key configured. "
                                   f"Add {env_k} to watcher.conf "
                                    "or set it in Settings → AI Explain."}, 503)
            return

        force = bool(body.get("force", False))
        alert = {
            "sig_id":   sig_id,
            "sig_msg":  body.get("sig_msg", ""),
            "src_ip":   body.get("src_ip", ""),
            "dest_ip":  body.get("dest_ip", ""),
            "proto":    body.get("proto", ""),
            "category": body.get("category", ""),
            "severity": body.get("severity", ""),
        }

        try:
            result = self.explain_engine.explain(alert, force=force)
            self._json(result)
        except ValueError as e:
            self._json({"error": str(e)}, 400)
        except RuntimeError as e:
            self._json({"error": str(e)}, 502)
        except Exception as e:
            log.exception("Unexpected error in explain")
            self._json({"error": "Internal error"}, 500)

    def _explain_settings_update(self):
        """PUT /settings/explain — update enabled, provider, or api_key."""
        if not self._require_role("admin"): return
        body = self._read_json()
        if body is None: return

        enabled         = body.get("enabled")           # bool or None
        provider        = body.get("provider")          # str or None
        api_key         = body.get("api_key")           # str or None
        target_provider = body.get("target_provider")  # str or None

        self._json(self.explain_engine.set_config(
            enabled         = enabled,
            provider        = provider if provider else None,
            api_key         = api_key,
            target_provider = target_provider,
        ))

    # ── Data Control ──────────────────────────────────────────────────────────

    def _admin_replay(self):
        """
        POST /admin/replay
        Starts a background replay of eve.json from the beginning.
        Only one replay can run at a time.
        Returns immediately; poll GET /admin/replay for status.
        """
        if not self._require_role("admin"): return

        with Handler._replay_lock:
            if Handler._replay_state == "running":
                self._json({"error": "Replay already in progress."}, 409)
                return
            Handler._replay_state = "running"

        eve_path      = self.eve_path
        db            = self.db
        dns_db        = self.dns_db
        registry      = self.registry
        wdb           = self.wdb
        sup_db        = self.sup_db
        stats_ref     = Handler

        def _run():
            from tail import replay_eve
            try:
                result = replay_eve(
                    str(eve_path), db, registry,
                    dns_db=dns_db, sup_db=sup_db,
                )
                # Invalidate stats cache so /health reflects new counts
                with Handler._stats_lock:
                    stats_ref._stats_cache = None
            except Exception as exc:
                result = {"error": str(exc)}
            with Handler._replay_lock:
                Handler._replay_state = result

        import threading as _t
        _t.Thread(target=_run, daemon=True, name="admin-replay").start()
        self._json({"status": "started"}, 202)

    def _admin_flush(self):
        """
        DELETE /admin/flush
        Wipes all alert, flow, dns, and http records from the database.
        Admin only. Invalidates the stats cache.
        """
        if not self._require_role("admin"): return
        counts      = self.db.flush_all()
        dns_deleted = self.dns_db.flush_all() if self.dns_db else 0
        counts["dns_events"] = dns_deleted
        # Invalidate stats cache
        with Handler._stats_lock:
            Handler._stats_cache = None
        log.info("Admin flush: %s", counts)
        self._json({"deleted": counts})

    # ── Threat Intel Import ───────────────────────────────────────────────────

    def _ti_import(self):
        """POST /threat-intel/import — bulk import from JSON array."""
        if not self._require_role("admin"): return
        body = self._read_json()
        if body is None: return

        entries = body if isinstance(body, list) else body.get("entries", [])
        if not isinstance(entries, list):
            self._json({"error": "Expected a JSON array of entries."}, 400)
            return
        if len(entries) > 5000:
            self._json({"error": "Maximum 5,000 entries per import."}, 400)
            return

        # Identify caller for audit trail
        token = self.headers.get("Cookie", "")
        try:
            tok = token.split("token=")[1].split(";")[0].strip()
            caller = (self.auth.validate(tok) or {}).get("username", "import")
        except Exception:
            caller = "import"

        result = self.ti_db.import_entries(entries, imported_by=caller)
        self._json(result, 200)
