import { useState, useEffect } from 'react';
import { fmtTime, SEV_COLORS } from './utils.js';

// ── Acknowledgement statuses ──────────────────────────────────────────────────
export const ACK_STATUSES = [
  { value: 'new',            label: 'New',            color: 'var(--text3)',  bg: 'var(--bg3)' },
  { value: 'investigating',  label: 'Investigating',  color: 'var(--yellow)', bg: 'var(--yellow-d)' },
  { value: 'acknowledged',   label: 'Acknowledged',   color: 'var(--green)',  bg: 'var(--green-d)' },
  { value: 'false_positive', label: 'False Positive', color: 'var(--purple)', bg: 'rgba(159,122,234,.13)' },
];
export const ACK_MAP = Object.fromEntries(ACK_STATUSES.map(s => [s.value, s]));

// ── Clock ─────────────────────────────────────────────────────────────────────
export function Clock() {
  const [t, setT] = useState('');
  useEffect(() => {
    const tick = () => setT(new Date().toLocaleTimeString('en-GB', { hour12: false }));
    tick();
    const id = setInterval(tick, 500);
    return () => clearInterval(id);
  }, []);
  return <span className="clock">{t}</span>;
}

// ── Sparkline ─────────────────────────────────────────────────────────────────
export function Sparkline({ data }) {
  const max = Math.max(1, ...data);
  return (
    <div className="spark-wrap">
      <div className="spark-label">Alerts / 60s window</div>
      <div className="spark-row">
        {data.map((v, i) => (
          <div key={i} className="spark-bar"
               style={{ height: Math.max(2, Math.round((v / max) * 26)) }} />
        ))}
      </div>
    </div>
  );
}

// ── Timeline ──────────────────────────────────────────────────────────────────
export function Timeline({ alerts }) {
  return (
    <div className="tline">
      {alerts.slice(0, 8).map((a, i) => (
        <div key={a.id || i} className="tl-item">
          <div className="tl-dot" style={{ background: SEV_COLORS[a.severity] }} />
          <div className="tl-time">{fmtTime(a.ts)}</div>
          <div className="tl-msg">{a.sig_msg}</div>
        </div>
      ))}
    </div>
  );
}

// ── AckBadge ──────────────────────────────────────────────────────────────────
export function AckBadge({ status }) {
  const cfg = ACK_MAP[status] || ACK_MAP['new'];
  return (
    <span style={{
      display:'inline-flex', alignItems:'center', padding:'2px 8px',
      borderRadius:'var(--radius-sm)', fontSize:10, fontWeight:500,
      fontFamily:'var(--mono)', letterSpacing:'.05em', textTransform:'uppercase',
      color: cfg.color, background: cfg.bg,
    }}>{cfg.label}</span>
  );
}

// ── JSON Syntax Highlighter ───────────────────────────────────────────────────
export function HighlightedJSON({ data }) {
  const jsonString = JSON.stringify(data, null, 2);
  const tokens = [];
  let i = 0;
  const len = jsonString.length;

  while (i < len) {
    const char = jsonString[i];

    if (/\s/.test(char)) { tokens.push(char); i++; continue; }

    if ('{}[],:'.includes(char)) {
      tokens.push(<span key={i} className="json-punct">{char}</span>);
      i++; continue;
    }

    if (char === '"') {
      let j = i + 1, escaped = false;
      while (j < len) {
        if (jsonString[j] === '"' && !escaped) break;
        escaped = jsonString[j] === '\\' && !escaped;
        j++;
      }
      const token = jsonString.slice(i, j + 1);
      const isKey = jsonString[j + 1] === ':' ||
        (j + 1 < len && jsonString[j + 1] === ' ' && jsonString[j + 2] === ':');
      tokens.push(
        <span key={i} className={isKey ? 'json-key' : 'json-string'}>{token}</span>
      );
      i = j + 1; continue;
    }

    if (/[0-9\-]/.test(char)) {
      let j = i;
      while (j < len && /[0-9eE.\-+]/.test(jsonString[j])) j++;
      tokens.push(<span key={i} className="json-number">{jsonString.slice(i, j)}</span>);
      i = j; continue;
    }

    if (/[a-zA-Z]/.test(char)) {
      let j = i;
      while (j < len && /[a-zA-Z]/.test(jsonString[j])) j++;
      const token = jsonString.slice(i, j);
      const cls = token === 'true' || token === 'false' ? 'json-boolean' : 'json-null';
      tokens.push(<span key={i} className={cls}>{token}</span>);
      i = j; continue;
    }

    tokens.push(char); i++;
  }

  return <pre className="rawjson">{tokens}</pre>;
}
