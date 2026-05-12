#!/usr/bin/env python3
"""
strip-ai.py  —  Watcher IDS dual-build AI stripper
===================================================
Produces an AI-free copy of the source tree. build-deb.sh calls this
automatically — one source tree, three release artifacts per run.

What "no AI" means
------------------
  NO:  LLM calls, API keys, explain.py, ExplainEngine, /alerts/explain,
       /settings/explain, AiExplainPanel, AI Explanation tab in the dialog.
  YES: Explain button, ExplainDialog modal, Threat Intel tab, all of
       IntelDisplay / IntelEditor / NoIntel / ThreatIntelPanel.

Modifications per file
----------------------
  backend/explain.py              SKIPPED (no LLM engine)
  backend/handlers.py             3 routes + 2 method bodies removed
  backend/server.py               import + init + wiring lines removed
  backend/tail.py                 threading, signature, auto-explain removed
  frontend-src/src/App.jsx        aiEnabled state + fetch removed;
                                  Explain button + ExplainDialog KEPT
  frontend-src/src/Settings.jsx   PROVIDER_META, AiExplainPanel removed
  frontend-src/src/ThreatIntel.jsx AI tab content surgically removed from
                                  ExplainDialog; dialog + Threat Intel KEPT
  packaging/postinst              What's New rewritten for noai variant
  packaging/watcher.conf          AI provider section removed

Algorithm
---------
Python  : exact multi-line string matching.
JSX     : line-level helpers for simple removals; brace-depth state machine
          (end-of-line evaluation) only for whole-function excision.
"""

from __future__ import annotations
import argparse, os, re, shutil, sys
from pathlib import Path


# ── helpers ───────────────────────────────────────────────────────────────────

def _load(p): return Path(p).read_text(encoding="utf-8")
def _save(p, t):
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    Path(p).write_text(t, encoding="utf-8")


def remove_lines_containing(text, *needles):
    return "".join(l for l in text.splitlines(keepends=True)
                   if not any(n in l for n in needles))


def remove_exact_block(text, start, end, inclusive=True):
    lines = text.splitlines(keepends=True)
    si = next((i for i,l in enumerate(lines) if start in l), None)
    if si is None: raise ValueError(f"start not found: {start!r}")
    ei = next((i for i in range(si, len(lines)) if end in lines[i]), None)
    if ei is None: raise ValueError(f"end not found: {end!r}")
    if inclusive: del lines[si:ei+1]
    else:         del lines[si:ei]
    return "".join(lines)


def replace_exact_block(text, start, end, replacement):
    lines = text.splitlines(keepends=True)
    si = next((i for i,l in enumerate(lines) if start in l), None)
    if si is None: raise ValueError(f"start not found: {start!r}")
    ei = next((i for i in range(si, len(lines)) if end in lines[i]), None)
    if ei is None: raise ValueError(f"end not found: {end!r}")
    lines[si:ei+1] = [replacement] if replacement else []
    return "".join(lines)


def strip_jsx_block(text, trigger):
    """
    Remove the JSX function/const whose opening line contains `trigger`.
    Evaluates brace depth at END-OF-LINE so destructured params like
    `function Foo({ a, b }) {` don't cause a false block-close mid-line.
    """
    lines = text.splitlines(keepends=True)
    ti = next((i for i,l in enumerate(lines) if trigger in l), None)
    if ti is None: raise ValueError(f"trigger not found: {trigger!r}")
    start = ti
    if ti > 0 and re.match(r'\s*//', lines[ti-1]):
        start = ti - 1

    depth = 0; entered = False
    in_str = None; in_bc = False; end = None

    for i in range(ti, len(lines)):
        ln = lines[i]; j = 0; in_lc = False
        while j < len(ln):
            c = ln[j]; nc = ln[j+1] if j+1 < len(ln) else ''
            if in_str:
                if c == '\\': j += 2; continue
                if c == in_str: in_str = None
                j += 1; continue
            if in_bc:
                if c == '*' and nc == '/': in_bc = False; j += 2
                else: j += 1
                continue
            if in_lc: break
            if c == '/' and nc == '/': in_lc = True; break
            if c == '/' and nc == '*': in_bc = True; j += 2; continue
            if c in ('"', "'", '`'): in_str = c; j += 1; continue
            if c == '{': depth += 1
            elif c == '}': depth -= 1
            j += 1
        if depth > 0: entered = True
        if entered and depth <= 0: end = i; break

    if end is None: raise ValueError(f"closing brace not found for: {trigger!r}")
    del lines[start:end+1]
    return "".join(lines)


# ── per-file strip functions ──────────────────────────────────────────────────

def strip_handlers_py(text):
    text = remove_lines_containing(text, "    explain_engine = None")
    text = remove_exact_block(text,
        'elif path == "/settings/explain":',
        "self._json(self.explain_engine.get_config())")
    text = remove_exact_block(text,
        'elif path == "/alerts/explain":',
        "self._explain_get_or_create()")
    text = remove_exact_block(text,
        'elif path == "/settings/explain":',
        "self._explain_settings_update()")
    text = remove_exact_block(text,
        "# ── AI Explain ──", "# ── Data Control ──", inclusive=False)
    return text


def strip_server_py(text):
    # Replace two-line kwargs dict FIRST (before any line removals that would
    # break the exact match by eating the second line).
    text = text.replace(
        '        kwargs={"dns_db": dns_db, "sup_db": sup_db,\n'
        '                "explain_engine": explain_eng},',
        '        kwargs={"dns_db": dns_db, "sup_db": sup_db},')
    text = remove_lines_containing(text,
        "from explain       import ExplainDB, ExplainEngine",
        "explain_db  = ExplainDB(",
        "explain_eng = ExplainEngine(",
        "Handler.explain_engine = explain_eng",
        '"explain_engine": explain_eng')
    return text


def strip_tail_py(text):
    text = remove_lines_containing(text, "import threading")
    text = text.replace(
        "def tail_thread(path: str, db, registry, wdb=None, dns_db=None, sup_db=None,\n"
        "               explain_engine=None):",
        "def tail_thread(path: str, db, registry, wdb=None, dns_db=None, sup_db=None):")
    text = remove_lines_containing(text,
        "explain_engine: optional ExplainEngine",
        "_explained_sids: set = set()",
        "# Track which sig_ids we have already queued for auto-explain")
    text = remove_exact_block(text,
        "# ── Auto-explain (background, per unique SID) ──",
        "_explained_sids)")
    lines = text.splitlines(keepends=True)
    idx = next((i for i,l in enumerate(lines) if "def _auto_explain(" in l), None)
    if idx is not None:
        if idx > 0 and lines[idx-1].strip() == "": idx -= 1
        del lines[idx:]
    return "".join(lines)


def strip_app_jsx(text):
    # Remove aiEnabled state + comment ONLY — showExplain, Explain button,
    # ExplainDialog JSX are ALL kept.
    text = remove_lines_containing(text,
        "// AI enabled state",
        "const [aiEnabled,")
    text = remove_exact_block(text,
        "// Fetch AI enabled status once",
        ".catch(() => setAiEnabled(false));")
    # Remove only the aiEnabled prop line in the ExplainDialog call
    text = remove_lines_containing(text, "aiEnabled={aiEnabled}")
    return text


def strip_settings_jsx(text):
    text = strip_jsx_block(text, "const PROVIDER_META = {")
    text = strip_jsx_block(text, "function AiExplainPanel(")
    text = remove_lines_containing(text, "// ── AiExplainPanel ──")
    text = text.replace("{ id:'ai-explain', label:'AI Explain' }, ", "")
    text = remove_exact_block(text,
        "{tab === 'ai-explain' && (",
        "          <AiExplainPanel role={role}/>")
    # Remove orphaned closing ")}" after the suppression panel
    lines = text.splitlines(keepends=True)
    for i, ln in enumerate(lines):
        if "<SuppressionPanel" in ln:
            for j in range(i, min(i+6, len(lines))):
                if lines[j].strip() == ")}":
                    nxt = next((lines[k].strip()
                                for k in range(j+1, min(j+4, len(lines)))
                                if lines[k].strip()), "")
                    if "data-control" in nxt or "DataControlPanel" in nxt:
                        del lines[j]; break
            break
    return "".join(lines)


def strip_threatintel_jsx(text):
    """
    Surgically remove only the AI content INSIDE ExplainDialog.
    The dialog, its header, the Threat Intel tab, IntelDisplay, IntelEditor,
    NoIntel, and ThreatIntelPanel are ALL preserved intact.
    """
    # 1. PROVIDER_COLOR const + preceding comment line
    text = remove_lines_containing(text,
        "provider accent colours (mirrors Settings.jsx PROVIDER_META)",
        "const PROVIDER_COLOR = {")

    # 2. Simplify ExplainDialog prop signature (drop aiEnabled: aiEnabledProp)
    text = text.replace(
        "export function ExplainDialog({ alert, role, aiEnabled: aiEnabledProp, onClose })",
        "export function ExplainDialog({ alert, role, onClose })")

    # 3. Remove aiEnabled state line
    text = remove_lines_containing(text,
        "const [aiEnabled, setAiEnabled] = useState(null);")

    # 4. Remove AI explanation state block (comment + 3 state lines)
    text = remove_exact_block(text,
        "// AI explanation state",
        "const [aiError,   setAiError]")

    # 5. Replace aiEnabled/tab-init useEffect with simple intel-only version
    text = replace_exact_block(text,
        "// Use the aiEnabled prop passed from App",
        "}, [alert?.sig_id, aiEnabledProp]);",
        "  useEffect(() => { setTab('intel'); }, [alert?.sig_id]);\n")

    # 6. Remove AI fetch-on-open useEffect
    text = remove_exact_block(text,
        "// Fetch AI explanation on open (if enabled)",
        "}, [alert?.sig_id, aiEnabled]);")

    # 7. Remove fetchAi() function (brace-depth tracker)
    text = strip_jsx_block(text, "  function fetchAi(force)")

    # 8. Remove AI tab entry from tab nav array
    text = remove_lines_containing(text,
        "aiEnabled ? { id:'ai', label:'AI Explanation' } : null,")

    # 9. Remove AI Explanation tab panel — use the blank line + Threat Intel
    #    comment as the unique end anchor (avoids ambiguous closing "        )}")
    text = remove_exact_block(text,
        "{/* AI Explanation tab */}",
        "{/* Threat Intel tab */}",
        inclusive=False)   # keep the Threat Intel comment line

    return text


def strip_postinst(text, version):
    text = text.replace(
        f"Watcher IDS v{version} installed successfully",
        f"Watcher IDS v{version}-noai installed successfully")
    lines = text.splitlines(keepends=True)
    s = next((i for i,l in enumerate(lines) if "What's new" in l), None)
    if s is not None:
        e = next((i for i in range(s, len(lines)) if "Fully air-gapped" in lines[i]), s)
        lines[s:e+1] = [(
            f"    echo \"│  What's new in v{version}-noai:                               │\"\n"
            "    echo \"│    • AI-free build — LLM engine removed, Threat Intel kept  │\"\n"
            "    echo \"│    • Explain button retained — opens Threat Intel notes      │\"\n"
            "    echo \"│    • Fix: webhook Test now respects Allow Local IPs          │\"\n"
            "    echo \"│    • Fix: stale blocked-error cleared when local IPs on     │\"\n"
            "    echo \"│    • Fully air-gapped — zero external font/CDN deps         │\"\n"
        )]
    return "".join(lines)


def strip_watcher_conf(text):
    lines = text.splitlines(keepends=True)
    s = next((i for i,l in enumerate(lines) if "AI-powered alert explanations" in l), None)
    if s is not None:
        if s > 0 and lines[s-1].strip() == "": s -= 1
        del lines[s:]
    return "".join(lines)


# ── file routing ──────────────────────────────────────────────────────────────

SKIP_FILES = {"backend/explain.py", "strip-ai.py"}
SKIP_DIR_PREFIXES = ("frontend/", "packaging/build/")

STRIPPERS = {
    "backend/handlers.py":              strip_handlers_py,
    "backend/server.py":                strip_server_py,
    "backend/tail.py":                  strip_tail_py,
    "frontend-src/src/App.jsx":         strip_app_jsx,
    "frontend-src/src/Settings.jsx":    strip_settings_jsx,
    "frontend-src/src/ThreatIntel.jsx": strip_threatintel_jsx,
}

BANNED = (
    "ExplainEngine", "ExplainDB", "_auto_explain", "explain_engine",
    "AiExplainPanel", "PROVIDER_META", "settings/explain", "alerts/explain",
    "AI Explanation tab", "aiEnabledProp",
    "const [aiEnabled,", "const [aiData,", "const [aiLoading,",
    "const [aiError,", "function fetchAi(", "PROVIDER_COLOR",
)

REQUIRED = {
    "frontend-src/src/ThreatIntel.jsx": (
        "export function ExplainDialog(",
        "Threat Intel",
        "/threat-intel/lookup",
        "IntelDisplay",
        "IntelEditor",
    ),
    "frontend-src/src/App.jsx": (
        "showExplain",
        "ExplainDialog",
        "setShowExplain",
    ),
}


# ── tree copy ─────────────────────────────────────────────────────────────────

def copy_tree(src_root, dst_root, version, verbose=True):
    log = []
    for src_path in sorted(Path(src_root).rglob("*")):
        if src_path.is_dir(): continue
        rel     = src_path.relative_to(src_root)
        rel_str = rel.as_posix()
        if any(p in rel.parts for p in ("__pycache__", ".git", "node_modules", "build")): continue
        if src_path.suffix in (".pyc", ".pyo"): continue
        if any(rel_str.startswith(p) for p in SKIP_DIR_PREFIXES): continue

        dst_path = dst_root / rel
        if rel_str in SKIP_FILES:
            log.append(f"  SKIP   {rel_str}"); continue

        dst_path.parent.mkdir(parents=True, exist_ok=True)

        if rel_str in STRIPPERS:
            _save(dst_path, STRIPPERS[rel_str](_load(src_path)))
            log.append(f"  STRIP  {rel_str}")
        elif rel_str == "packaging/postinst":
            result = strip_postinst(_load(src_path), version)
            _save(dst_path, result)
            dst_path.chmod(src_path.stat().st_mode)
            log.append(f"  STRIP  {rel_str}  (What's New rewritten)")
        elif rel_str == "packaging/watcher.conf":
            _save(dst_path, strip_watcher_conf(_load(src_path)))
            log.append(f"  STRIP  {rel_str}  (AI section removed)")
        else:
            shutil.copy2(str(src_path), str(dst_path))
            log.append(f"  COPY   {rel_str}")
    return log


def verify(dst_root, quiet=False):
    all_ok = True
    for rel_str in list(STRIPPERS) + ["packaging/postinst", "packaging/watcher.conf"]:
        p = dst_root / rel_str
        if not p.exists(): continue
        text = _load(p)
        bad     = [t for t in BANNED   if t in text]
        missing = [t for t in REQUIRED.get(rel_str, ()) if t not in text]
        if bad or missing:
            for b in bad:     print(f"  FAIL  {rel_str}  banned: {b!r}")
            for m in missing: print(f"  FAIL  {rel_str}  missing: {m!r}")
            all_ok = False
        elif not quiet:
            print(f"  OK    {rel_str}")
    return all_ok


def self_test(src_root, version):
    import traceback
    ok = True
    print("Self-test:")
    test_map = {**STRIPPERS,
                "packaging/postinst":     lambda t: strip_postinst(t, version),
                "packaging/watcher.conf": strip_watcher_conf}
    for rel_str, fn in sorted(test_map.items()):
        path = src_root / rel_str
        if not path.exists(): print(f"  WARN  {rel_str} — not found"); continue
        try:
            result = fn(_load(path))
            assert result.strip()
            bad     = [t for t in BANNED   if t in result]
            missing = [t for t in REQUIRED.get(rel_str, ()) if t not in result]
            if bad or missing:
                for b in bad:     print(f"  FAIL  {rel_str}  banned: {b!r}")
                for m in missing: print(f"  FAIL  {rel_str}  missing: {m!r}")
                ok = False
            else:
                print(f"  OK    {rel_str}")
        except Exception:
            print(f"  FAIL  {rel_str}"); traceback.print_exc(); ok = False
    return ok


# ── CLI ───────────────────────────────────────────────────────────────────────

def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--version", default=None)
    ap.add_argument("--test", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)

    src_root = Path(args.src).resolve() if args.src else Path(__file__).parent.resolve()

    version = args.version
    if not version:
        for c in (src_root/"packaging"/"DEBIAN"/"control", src_root/"packaging"/"control"):
            if c.exists():
                for l in c.read_text().splitlines():
                    if l.startswith("Version:"):
                        version = l.split(":",1)[1].strip(); break
            if version: break
    version = version or "1.7.2"

    if args.test:
        return 0 if self_test(src_root, version) else 1

    dst_root = Path(args.out).resolve() if args.out \
               else src_root.parent / "watcher-ids-noai"

    print(f"strip-ai.py  v{version}")
    print(f"  src  →  {src_root}")
    print(f"  dst  →  {dst_root}\n")

    if dst_root.exists(): shutil.rmtree(dst_root)
    dst_root.mkdir(parents=True)

    log = copy_tree(src_root, dst_root, version)
    if not args.quiet:
        for l in log: print(l)

    print("\nVerifying …")
    ok = verify(dst_root, quiet=args.quiet)
    print()
    if ok:   print(f"✓  AI-free tree written to: {dst_root}")
    else:    print("✗  Verification failed — see FAIL lines above.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
