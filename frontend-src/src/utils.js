// ── Constants ────────────────────────────────────────────────────────────────
export const MAX_ALERTS = 5000;
export const SSE_URL    = '/events';

export const SEV_COLORS = {
  critical: 'var(--red)',
  high:     'var(--orange)',
  medium:   'var(--yellow)',
  low:      'var(--green)',
  info:     'var(--accent)',
};

// ── Timestamp formatting ──────────────────────────────────────────────────────
// Cache today/yesterday boundaries so we don't create 4 Date objects per cell.
let _fmtCache = { todayStart: 0, yestStart: 0, ts: 0 };

function _refreshFmtCache() {
  const now = new Date();
  now.setHours(0, 0, 0, 0);
  _fmtCache = {
    todayStart: now.getTime(),
    yestStart:  now.getTime() - 86400000,
    ts:         Date.now(),
  };
}
_refreshFmtCache();

export function fmtTime(ts) {
  try {
    if (Date.now() - _fmtCache.ts > 60000) _refreshFmtCache();
    const d      = new Date(ts);
    const dStart = new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
    const timeStr = d.toLocaleTimeString('en-US', {
      hour: '2-digit', minute: '2-digit', hour12: true,
    });
    if (dStart === _fmtCache.todayStart) return timeStr;
    if (dStart === _fmtCache.yestStart)  return `Yesterday at ${timeStr}`;
    const dateStr = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    return `${dateStr} at ${timeStr}`;
  } catch { return '--:--'; }
}

export function fmtBytes(n) {
  if (!n || n === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(n) / Math.log(1024));
  return (n / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
}

export function fmtDur(s) {
  if (!s || s === 0) return '0s';
  if (s < 60)   return s.toFixed(1) + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm ' + Math.floor(s % 60) + 's';
  return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
}
