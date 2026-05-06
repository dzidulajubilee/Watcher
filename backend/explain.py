"""
Watcher IDS Dashboard — AI Alert Explanations (DeepSeek)

ExplainDB     : caches AI-generated explanations in config.db
ExplainEngine : calls DeepSeek API, respects key priority

Key priority (first wins):
  1. DB override  — admin sets via Settings UI
  2. Env var      — DEEPSEEK_API_KEY in /etc/watcher/watcher.conf

Explanations are keyed by sig_id (Suricata signature ID).
Cached entries can be force-regenerated on demand.
"""

import json
import logging
import os
import time
import urllib.error
import urllib.request

log = logging.getLogger("watcher.explain")

DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
DEEPSEEK_MODEL   = "deepseek-chat"
MAX_TOKENS       = 220


# ── ExplainDB ─────────────────────────────────────────────────────────────────

class ExplainDB:
    """
    Manages two tables in config.db:

      ai_explanations  — cached DeepSeek responses keyed by sig_id
      settings         — generic key-value store (used for deepseek_api_key)
    """

    def __init__(self, conn_fn):
        self._conn = conn_fn
        self._setup()

    def _setup(self):
        c = self._conn()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS ai_explanations (
                sig_id            INTEGER PRIMARY KEY,
                sig_msg           TEXT,
                category          TEXT,
                explanation       TEXT    NOT NULL,
                model             TEXT    NOT NULL,
                generated_at      REAL    NOT NULL,
                prompt_tokens     INTEGER NOT NULL DEFAULT 0,
                completion_tokens INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        """)
        c.commit()

    # ── Settings (key-value) ──────────────────────────────────────────────────

    def get_setting(self, key: str, default=None):
        row = self._conn().execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        ).fetchone()
        return row[0] if row else default

    def set_setting(self, key: str, value: str):
        c = self._conn()
        c.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        c.commit()

    def delete_setting(self, key: str):
        c = self._conn()
        c.execute("DELETE FROM settings WHERE key = ?", (key,))
        c.commit()

    # ── Explanation cache ─────────────────────────────────────────────────────

    def get(self, sig_id: int) -> dict | None:
        row = self._conn().execute(
            "SELECT * FROM ai_explanations WHERE sig_id = ?", (sig_id,)
        ).fetchone()
        return dict(row) if row else None

    def upsert(self, sig_id: int, sig_msg: str | None, category: str | None,
               explanation: str, model: str,
               prompt_tokens: int = 0, completion_tokens: int = 0) -> dict:
        c   = self._conn()
        now = time.time()
        c.execute(
            """INSERT INTO ai_explanations
               (sig_id, sig_msg, category, explanation, model,
                generated_at, prompt_tokens, completion_tokens)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(sig_id) DO UPDATE SET
                 sig_msg           = excluded.sig_msg,
                 category          = excluded.category,
                 explanation       = excluded.explanation,
                 model             = excluded.model,
                 generated_at      = excluded.generated_at,
                 prompt_tokens     = excluded.prompt_tokens,
                 completion_tokens = excluded.completion_tokens""",
            (sig_id, sig_msg or None, category or None,
             explanation, model, now, prompt_tokens, completion_tokens),
        )
        c.commit()
        return self.get(sig_id)

    def delete(self, sig_id: int):
        c = self._conn()
        c.execute("DELETE FROM ai_explanations WHERE sig_id = ?", (sig_id,))
        c.commit()


# ── ExplainEngine ─────────────────────────────────────────────────────────────

class ExplainEngine:
    """Calls DeepSeek and caches results via ExplainDB."""

    def __init__(self, db: ExplainDB):
        self._db = db

    # ── Key management ────────────────────────────────────────────────────────

    def _api_key(self) -> str | None:
        """DB override wins; fall back to env var from watcher.conf."""
        return (
            self._db.get_setting("deepseek_api_key")
            or os.environ.get("DEEPSEEK_API_KEY")
            or None
        )

    def has_key(self) -> bool:
        return bool(self._api_key())

    def key_source(self) -> str:
        """Returns 'db', 'env', or 'none' — for the Settings UI."""
        if self._db.get_setting("deepseek_api_key"):
            return "db"
        if os.environ.get("DEEPSEEK_API_KEY"):
            return "env"
        return "none"

    def key_hint(self) -> str | None:
        """Returns a masked key hint like 'sk-...aB3c', or None."""
        key = self._api_key()
        if not key or len(key) < 8:
            return None
        return f"{key[:4]}...{key[-4:]}"

    def set_key(self, key: str | None):
        """Store or clear the DB override key."""
        if key and key.strip():
            self._db.set_setting("deepseek_api_key", key.strip())
        else:
            self._db.delete_setting("deepseek_api_key")

    # ── Prompt ────────────────────────────────────────────────────────────────

    @staticmethod
    def _build_prompt(alert: dict) -> str:
        """
        Builds a prompt that returns a 3-sentence executive summary:
          1. What triggered it.
          2. Why it matters / threat context.
          3. Recommended immediate action.
        Designed to be skimmable in under 10 seconds by a SOC analyst.
        """
        lines = [
            "You are a senior SOC analyst writing for a security operations team.",
            "Write a 3-sentence executive summary for the following Suricata IDS alert.",
            "",
            f"Alert : {alert.get('sig_msg', 'Unknown')}",
            f"SID   : {alert.get('sig_id', 'N/A')}",
        ]
        if alert.get("category"):
            lines.append(f"Category : {alert['category']}")
        if alert.get("severity"):
            lines.append(f"Severity : {alert['severity']}")
        if alert.get("src_ip"):
            lines.append(f"Source   : {alert['src_ip']}")
        if alert.get("dest_ip"):
            lines.append(f"Dest     : {alert['dest_ip']}")
        if alert.get("proto"):
            lines.append(f"Protocol : {alert['proto'].upper()}")

        lines += [
            "",
            "Rules:",
            "- Sentence 1: what specifically triggered this alert.",
            "- Sentence 2: the likely threat type and why it matters.",
            "- Sentence 3: the single most important action the analyst should take right now.",
            "- Output exactly 3 sentences, no headers, no bullets, no markdown.",
        ]
        return "\n".join(lines)

    # ── DeepSeek API call ─────────────────────────────────────────────────────

    def _call_deepseek(self, prompt: str) -> dict:
        api_key = self._api_key()
        if not api_key:
            raise ValueError("No DeepSeek API key configured")

        payload = json.dumps({
            "model":      DEEPSEEK_MODEL,
            "max_tokens": MAX_TOKENS,
            "messages":   [{"role": "user", "content": prompt}],
        }).encode()

        req = urllib.request.Request(
            DEEPSEEK_API_URL,
            data=payload,
            headers={
                "Content-Type":  "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            log.error("DeepSeek API error %s: %s", e.code, body)
            if e.code == 401:
                raise RuntimeError("Invalid DeepSeek API key.")
            if e.code == 429:
                raise RuntimeError("DeepSeek rate limit reached. Try again shortly.")
            raise RuntimeError(f"DeepSeek API returned {e.code}: {body[:200]}")
        except OSError as e:
            raise RuntimeError(f"Network error reaching DeepSeek: {e}")

        text  = data["choices"][0]["message"]["content"].strip()
        usage = data.get("usage", {})
        return {
            "explanation":       text,
            "model":             data.get("model", DEEPSEEK_MODEL),
            "prompt_tokens":     usage.get("prompt_tokens", 0),
            "completion_tokens": usage.get("completion_tokens", 0),
        }

    # ── Public interface ──────────────────────────────────────────────────────

    def explain(self, alert: dict, force: bool = False) -> dict:
        """
        Return an explanation for the alert, using the cache unless force=True.
        alert must contain at least: sig_id (int), sig_msg (str)
        Returns the db row dict with an extra `cached` bool.
        """
        sig_id = int(alert.get("sig_id") or 0)
        if not sig_id:
            raise ValueError("alert must have a valid sig_id")

        if not force:
            cached = self._db.get(sig_id)
            if cached:
                cached["cached"] = True
                return cached

        log.info("Calling DeepSeek for SID %d (%s)", sig_id,
                 alert.get("sig_msg", "")[:60])
        result = self._call_deepseek(self._build_prompt(alert))

        row = self._db.upsert(
            sig_id            = sig_id,
            sig_msg           = alert.get("sig_msg"),
            category          = alert.get("category"),
            explanation       = result["explanation"],
            model             = result["model"],
            prompt_tokens     = result["prompt_tokens"],
            completion_tokens = result["completion_tokens"],
        )
        row["cached"] = False
        return row
