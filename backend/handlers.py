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
               "/threat-intel", "/suppression")
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

    def _json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control",  "no-cache")
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
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
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
        elif path == "/webhooks":
            self._json(self.wdb.get_all())
        elif path == "/me":
            s = self._session()
            self._json({"username": s["username"], "role": s["role"]})
        elif path == "/users":
            if not self._require_role("admin"): return
            self._json(self.um.get_all())
        elif path == "/health":
            self._json({"status": "ok", "clients": self.registry.count(),
                        "db": self.db.stats(), "time": int(time.time())})
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
        elif path == "/suppression":
            self._json(self.sup_db.get_all())
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
        elif path == "/threat-intel":
            self._ti_create()
        elif path == "/suppression":
            self._sup_create()
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

    def _do_login(self):
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
        days  = self._qs_int(qs, "days",  RETAIN_DAYS, 1, RETAIN_DAYS)
        limit = self._qs_int(qs, "limit", 5000, 1, 20000)
        self._json(self.db.fetch_recent(days=days, limit=limit))

    def _serve_table(self, table, qs):
        days  = self._qs_int(qs, "days",  RETAIN_DAYS, 1, RETAIN_DAYS)
        limit = self._qs_int(qs, "limit", 5000, 1, 20000)
        if table == "dns":
            self._json(self.dns_db.fetch(days=days, limit=limit)); return
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
        name  = str(body.get("name",  "")).strip()
        wtype = str(body.get("type",  "generic")).strip()
        url   = str(body.get("url",   "")).strip()
        if not name or not url:
            self._json({"error": "name and url are required"}, 400); return
        if wtype not in ("slack", "discord", "generic"):
            self._json({"error": "type must be slack, discord, or generic"}, 400); return
        self._json(self.wdb.create(
            name, wtype, url,
            body.get("severities", ["critical","high","medium","low","info"]),
            bool(body.get("enabled", True))), 201)

    def _webhook_update(self, wid):
        if not self._require_role("admin"): return
        if not self.wdb.get(wid):
            self._json({"error": "Not found"}, 404); return
        body = self._read_json()
        if body is None: return
        self._json(self.wdb.update(wid, **body))

    def _webhook_test(self, wid):
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
            "sig_id": 9999999, "sig_msg": "Watcher Test Alert",
            "category": "Test", "severity": "medium", "action": "allowed",
        }
        err = deliver(wh["url"], build_payload(wh["type"], test_alert))
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
