"""
Watcher IDS Dashboard — AI Alert Explanations (multi-provider)

Supported providers:
  deepseek  — DeepSeek Chat  (deepseek-chat)
  openai    — OpenAI         (gpt-4o-mini)
  anthropic — Anthropic      (claude-haiku-4-5-20251001)

ExplainDB      : SQLite cache + settings in config.db
ExplainEngine  : dispatches to the active provider, caches results

Settings stored in the `settings` table (key → value):
  ai_enabled        "1" | "0"           (default "1")
  ai_provider       "deepseek" | "openai" | "anthropic"  (default "deepseek")
  deepseek_api_key  DB override (env fallback: DEEPSEEK_API_KEY)
  openai_api_key    DB override (env fallback: OPENAI_API_KEY)
  anthropic_api_key DB override (env fallback: ANTHROPIC_API_KEY)

Key priority per provider: DB override wins, then env var.
"""

import json
import logging
import os
import time
import urllib.error
import urllib.request

log = logging.getLogger("watcher.explain")

MAX_TOKENS = 220   # 3-sentence executive summary needs no more

# ── Provider registry ─────────────────────────────────────────────────────────
PROVIDERS = {
    "deepseek": {
        "label":   "DeepSeek",
        "model":   "deepseek-chat",
        "url":     "https://api.deepseek.com/v1/chat/completions",
        "format":  "openai",          # OpenAI-compatible
        "env_key": "DEEPSEEK_API_KEY",
        "db_key":  "deepseek_api_key",
    },
    "openai": {
        "label":   "OpenAI",
        "model":   "gpt-4o-mini",
        "url":     "https://api.openai.com/v1/chat/completions",
        "format":  "openai",
        "env_key": "OPENAI_API_KEY",
        "db_key":  "openai_api_key",
    },
    "anthropic": {
        "label":   "Anthropic (Claude)",
        "model":   "claude-haiku-4-5-20251001",
        "url":     "https://api.anthropic.com/v1/messages",
        "format":  "anthropic",       # different request/response shape
        "env_key": "ANTHROPIC_API_KEY",
        "db_key":  "anthropic_api_key",
    },
}

DEFAULT_PROVIDER = "deepseek"


# ── ExplainDB ─────────────────────────────────────────────────────────────────

class ExplainDB:
    """
    Two tables in config.db:
      ai_explanations  — cached AI responses keyed by sig_id
      settings         — key-value store (ai_enabled, ai_provider, *_api_key)
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
                provider          TEXT    NOT NULL DEFAULT 'deepseek',
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

    # ── Generic settings ──────────────────────────────────────────────────────

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

    def upsert(self, sig_id: int, sig_msg, category, explanation: str,
               model: str, provider: str,
               prompt_tokens: int = 0, completion_tokens: int = 0) -> dict:
        now = time.time()
        c   = self._conn()
        c.execute(
            """INSERT INTO ai_explanations
               (sig_id, sig_msg, category, explanation, model, provider,
                generated_at, prompt_tokens, completion_tokens)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(sig_id) DO UPDATE SET
                 sig_msg           = excluded.sig_msg,
                 category          = excluded.category,
                 explanation       = excluded.explanation,
                 model             = excluded.model,
                 provider          = excluded.provider,
                 generated_at      = excluded.generated_at,
                 prompt_tokens     = excluded.prompt_tokens,
                 completion_tokens = excluded.completion_tokens""",
            (sig_id, sig_msg or None, category or None,
             explanation, model, provider, now, prompt_tokens, completion_tokens),
        )
        c.commit()
        return self.get(sig_id)

    def delete(self, sig_id: int):
        c = self._conn()
        c.execute("DELETE FROM ai_explanations WHERE sig_id = ?", (sig_id,))
        c.commit()


# ── ExplainEngine ─────────────────────────────────────────────────────────────

class ExplainEngine:
    """Dispatches to the active provider and caches results via ExplainDB."""

    def __init__(self, db: ExplainDB):
        self._db = db

    # ── Config helpers ────────────────────────────────────────────────────────

    def is_enabled(self) -> bool:
        return self._db.get_setting("ai_enabled", "1") == "1"

    def active_provider(self) -> str:
        p = self._db.get_setting("ai_provider", DEFAULT_PROVIDER)
        return p if p in PROVIDERS else DEFAULT_PROVIDER

    def _api_key(self, provider: str) -> str | None:
        cfg = PROVIDERS[provider]
        return (
            self._db.get_setting(cfg["db_key"])
            or os.environ.get(cfg["env_key"])
            or None
        )

    def has_key(self) -> bool:
        return bool(self._api_key(self.active_provider()))

    def _key_source(self, provider: str) -> str:
        cfg = PROVIDERS[provider]
        if self._db.get_setting(cfg["db_key"]):
            return "db"
        if os.environ.get(cfg["env_key"]):
            return "env"
        return "none"

    def _key_hint(self, provider: str) -> str | None:
        key = self._api_key(provider)
        if not key or len(key) < 8:
            return None
        return f"{key[:4]}...{key[-4:]}"

    # ── Public config API (used by handlers) ──────────────────────────────────

    def get_config(self) -> dict:
        """Full config blob for GET /settings/explain."""
        prov = self.active_provider()
        providers_status = {}
        for pid, pcfg in PROVIDERS.items():
            providers_status[pid] = {
                "label":      pcfg["label"],
                "model":      pcfg["model"],
                "key_source": self._key_source(pid),
                "key_hint":   self._key_hint(pid),
            }
        return {
            "enabled":   self.is_enabled(),
            "provider":  prov,
            "providers": providers_status,
        }

    def set_config(self, enabled=None, provider=None,
                   api_key=None, target_provider=None) -> dict:
        """
        Partial update — only supplied fields are changed.
        target_provider: which provider's key to update (defaults to active).
        """
        if enabled is not None:
            self._db.set_setting("ai_enabled", "1" if enabled else "0")

        if provider is not None and provider in PROVIDERS:
            self._db.set_setting("ai_provider", provider)

        # Key update — targets either the specified provider or the active one
        kp = target_provider if (target_provider and target_provider in PROVIDERS) \
             else self.active_provider()
        if api_key is not None:
            cfg = PROVIDERS[kp]
            if api_key.strip():
                self._db.set_setting(cfg["db_key"], api_key.strip())
            else:
                self._db.delete_setting(cfg["db_key"])

        return self.get_config()

    # ── Prompt ────────────────────────────────────────────────────────────────

    @staticmethod
    def _build_prompt(alert: dict) -> str:
        """
        Returns a prompt that yields a 3-sentence executive summary:
          1. What triggered it.
          2. Why it matters / threat context.
          3. Recommended immediate action.
        """
        lines = [
            "You are a senior SOC analyst writing for a security operations team.",
            "Write a 3-sentence executive summary for the following Suricata IDS alert.",
            "",
            f"Alert    : {alert.get('sig_msg', 'Unknown')}",
            f"SID      : {alert.get('sig_id', 'N/A')}",
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

    # ── Provider API calls ────────────────────────────────────────────────────

    def _call_openai_compat(self, provider: str, prompt: str) -> dict:
        """Handles DeepSeek and OpenAI — both use the OpenAI chat completions format."""
        cfg     = PROVIDERS[provider]
        api_key = self._api_key(provider)
        if not api_key:
            raise ValueError(f"No API key configured for {cfg['label']}")

        payload = json.dumps({
            "model":      cfg["model"],
            "max_tokens": MAX_TOKENS,
            "messages":   [{"role": "user", "content": prompt}],
        }).encode()

        req = urllib.request.Request(
            cfg["url"],
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
            log.error("%s API error %s: %s", cfg["label"], e.code, body)
            if e.code == 401:
                raise RuntimeError(f"Invalid {cfg['label']} API key.")
            if e.code == 429:
                raise RuntimeError(f"{cfg['label']} rate limit reached. Try again shortly.")
            raise RuntimeError(f"{cfg['label']} API returned {e.code}: {body[:200]}")
        except OSError as e:
            raise RuntimeError(f"Network error reaching {cfg['label']}: {e}")

        text  = data["choices"][0]["message"]["content"].strip()
        usage = data.get("usage", {})
        return {
            "explanation":       text,
            "model":             data.get("model", cfg["model"]),
            "provider":          provider,
            "prompt_tokens":     usage.get("prompt_tokens", 0),
            "completion_tokens": usage.get("completion_tokens", 0),
        }

    def _call_anthropic(self, prompt: str) -> dict:
        """Anthropic Messages API — different request and response shape."""
        cfg     = PROVIDERS["anthropic"]
        api_key = self._api_key("anthropic")
        if not api_key:
            raise ValueError("No API key configured for Anthropic (Claude)")

        payload = json.dumps({
            "model":      cfg["model"],
            "max_tokens": MAX_TOKENS,
            "messages":   [{"role": "user", "content": prompt}],
        }).encode()

        req = urllib.request.Request(
            cfg["url"],
            data=payload,
            headers={
                "Content-Type":      "application/json",
                "x-api-key":         api_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            log.error("Anthropic API error %s: %s", e.code, body)
            if e.code == 401:
                raise RuntimeError("Invalid Anthropic API key.")
            if e.code == 429:
                raise RuntimeError("Anthropic rate limit reached. Try again shortly.")
            raise RuntimeError(f"Anthropic API returned {e.code}: {body[:200]}")
        except OSError as e:
            raise RuntimeError(f"Network error reaching Anthropic: {e}")

        # Anthropic response: {"content": [{"type": "text", "text": "..."}], "usage": {...}}
        text  = data["content"][0]["text"].strip()
        usage = data.get("usage", {})
        return {
            "explanation":       text,
            "model":             data.get("model", cfg["model"]),
            "provider":          "anthropic",
            "prompt_tokens":     usage.get("input_tokens", 0),
            "completion_tokens": usage.get("output_tokens", 0),
        }

    def _call_provider(self, provider: str, prompt: str) -> dict:
        fmt = PROVIDERS[provider]["format"]
        if fmt == "anthropic":
            return self._call_anthropic(prompt)
        return self._call_openai_compat(provider, prompt)

    # ── Public explain ────────────────────────────────────────────────────────

    def explain(self, alert: dict, force: bool = False) -> dict:
        """
        Return an explanation for the alert, using the cache unless force=True.
        Raises ValueError if AI is disabled or no key is configured.
        Returns the db row dict with extra `cached` (bool) and `provider` fields.
        """
        if not self.is_enabled():
            raise ValueError("AI explanations are disabled.")

        sig_id = int(alert.get("sig_id") or 0)
        if not sig_id:
            raise ValueError("alert must have a valid sig_id")

        if not force:
            cached = self._db.get(sig_id)
            if cached:
                cached["cached"] = True
                return cached

        provider = self.active_provider()
        if not self._api_key(provider):
            raise ValueError(
                f"no_key: No API key configured for {PROVIDERS[provider]['label']}."
            )

        log.info("Calling %s for SID %d (%s)",
                 PROVIDERS[provider]["label"], sig_id,
                 alert.get("sig_msg", "")[:60])

        result = self._call_provider(provider, self._build_prompt(alert))

        row = self._db.upsert(
            sig_id            = sig_id,
            sig_msg           = alert.get("sig_msg"),
            category          = alert.get("category"),
            explanation       = result["explanation"],
            model             = result["model"],
            provider          = result["provider"],
            prompt_tokens     = result["prompt_tokens"],
            completion_tokens = result["completion_tokens"],
        )
        row["cached"] = False
        return row
