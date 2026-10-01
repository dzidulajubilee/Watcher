# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Watcher IDS Dashboard — fast Suricata timestamp parsing (hot path).

Suricata writes timestamps as  2026-09-30T12:34:56.123456+0000.
datetime.strptime() cost ~17 % of ingest CPU at high event rates; this module
parses that fixed layout with slicing and calendar.timegm instead.

Semantics are identical to the previous implementation, which
  1. truncated fractional seconds to milliseconds (".123456" -> ".123"),
  2. parsed with strptime("%Y-%m-%dT%H:%M:%S.%f%z"), and
  3. returned datetime.timestamp().
The result is computed from integer microseconds and divided once, exactly
as timedelta.total_seconds() does, so the float is bit-identical.
Anything that does not match the fast layout falls back to the original
strptime path unchanged (verified by tests/test_regressions.py).
"""

import calendar
import logging
import re
from datetime import datetime

log = logging.getLogger("watcher.timeparse")

_RE_USEC = re.compile(r"(\.\d{3})\d+")         # 123456 -> 123  (µs -> ms)
_RE_TZ   = re.compile(r"([+-]\d{2})(\d{2})$")   # +0000  -> +00:00
_DIGITS  = frozenset("0123456789")


def _slow_epoch(ts: str, warn: bool = True) -> float:
    """Original implementation — used for anything outside the fast layout."""
    normalised = _RE_USEC.sub(r"\1", ts)
    normalised = _RE_TZ.sub(r"\1:\2", normalised)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(normalised, fmt).timestamp()
        except ValueError:
            pass
    if warn:
        log.warning("_to_epoch: could not parse %r (normalised: %r)", ts, normalised)
    return 0.0


# Cache: "YYYY-MM-DDTHH" + zone -> epoch seconds at the start of that hour
# (already validated).  Suricata timestamps are near-monotonic, so almost every
# event hits the cache; bounded so malformed/random input cannot grow it.
_HOUR_CACHE: dict = {}
_HOUR_CACHE_MAX = 4096


def _hour_base(ts: str, n: int):
    key = ts[0:13] + ts[n - 5:]
    base = _HOUR_CACHE.get(key)
    if base is not None:
        return base
    tz = ts[n - 4:]
    try:
        year, month, day, hour = int(ts[0:4]), int(ts[5:7]), int(ts[8:10]), int(ts[11:13])
        tzh, tzm = int(tz[0:2]), int(tz[2:4])
    except ValueError:
        return None
    if not (ts[0:4].isdigit() and tz.isdigit() and ts[5:7].isdigit() and ts[8:10].isdigit()
            and ts[11:13].isdigit() and 1 <= month <= 12 and 1 <= day <= 31
            and hour <= 23 and tzm <= 59):
        return None
    if day > calendar.monthrange(year, month)[1]:
        return None
    off = tzh * 3600 + tzm * 60
    if ts[n - 5] == "+":
        off = -off
    base = calendar.timegm((year, month, day, hour, 0, 0, 0, 0, 0)) + off
    if len(_HOUR_CACHE) >= _HOUR_CACHE_MAX:
        _HOUR_CACHE.clear()
    _HOUR_CACHE[key] = base
    return base


def to_epoch(ts: str, warn: bool = True) -> float:
    """
    Parse a Suricata ISO-8601 timestamp to a Unix epoch float (0.0 on failure).
    warn=False keeps DnsDB's original behaviour of failing silently.
    """
    if not ts:
        return 0.0
    n = len(ts)
    # Fast layout: YYYY-MM-DDTHH:MM:SS[.f{1,}](+|-)HHMM
    if (n >= 24 and ts[4] == "-" and ts[7] == "-" and ts[10] == "T"
            and ts[13] == ":" and ts[16] == ":" and ts[n - 5] in "+-"):
        frac = ""
        if n - 5 > 19:
            if ts[19] != ".":
                return _slow_epoch(ts, warn)
            frac = ts[20:n - 5]
            if not frac or not set(frac) <= _DIGITS:
                return _slow_epoch(ts, warn)
        elif n - 5 != 19:
            return _slow_epoch(ts, warn)
        mm, ss = ts[14:16], ts[17:19]
        if not (mm.isdigit() and ss.isdigit() and mm.isascii() and ss.isascii()):
            return _slow_epoch(ts, warn)
        minute, sec = int(mm), int(ss)
        if minute > 59 or sec > 59:
            return _slow_epoch(ts, warn)
        base = _hour_base(ts, n)
        if base is None:
            return _slow_epoch(ts, warn)
        # milliseconds, exactly as the old truncation + %f did
        ms = int(frac[:3].ljust(3, "0")) if frac else 0
        secs = base + minute * 60 + sec
        return (secs * 1_000_000 + ms * 1000) / 1_000_000
    return _slow_epoch(ts, warn)
