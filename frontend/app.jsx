/**
 * Watcher IDS Dashboard — app.jsx
 * Full application: themes, all views, SSE, state management.
 * Loaded by index.html via <script type="text/babel" src="/frontend/app.jsx">
 *
 * Views: Alerts | Flow Events | DNS Queries | Charts | Settings (Users + Webhooks)
 */

// ─────────────────────────────────────────────────────────────────────────────
// Themes — THEMES array + ThemePicker component (inlined from themes.js)
// ─────────────────────────────────────────────────────────────────────────────
// ── Themes ──

const THEMES = [
  { id: 'night',     label: 'Night',          accent: '#4f9cf9', dot: '#0f1117' },
  { id: 'light',     label: 'Light',          accent: '#2563eb', dot: '#f0f2f5' },
  { id: 'midnight',  label: 'Midnight Blue',  accent: '#58a6ff', dot: '#161b27' },
  { id: 'solarized', label: 'Solarized Dark', accent: '#268bd2', dot: '#002b36' },
  { id: 'dracula',   label: 'Dracula',        accent: '#bd93f9', dot: '#21222c' },
  { id: 'nord',      label: 'Nord',           accent: '#88c0d0', dot: '#3b4252' },
];

/**
 * ThemePicker
 * Dropdown in the topbar that lets the user switch between themes.
 * The selected theme is persisted to localStorage so it survives refreshes.
 */
function ThemePicker({ theme, onChange }) {
  const [open, setOpen] = React.useState(false);
  const ref             = React.useRef(null);
  const current         = THEMES.find(t => t.id === theme) || THEMES[0];

  // Close dropdown when clicking outside
  React.useEffect(() => {
    function handleClick(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  return (
    <div style={{ position: 'relative' }} ref={ref}>
      <div
        className="theme-btn"
        onClick={() => setOpen(o => !o)}
      >
        <div className="theme-swatch" style={{ background: current.accent }} />
        <span>{current.label}</span>
        <svg width="10" height="10" viewBox="0 0 10 10"
             fill="none" stroke="currentColor" strokeWidth="1.5">
          <path d="M2 4l3 3 3-3"/>
        </svg>
      </div>

      {open && (
        <div className="theme-dropdown" onClick={e => e.stopPropagation()}>
          {THEMES.map(t => (
            <div
              key={t.id}
              className={`theme-option${theme === t.id ? ' active' : ''}`}
              onClick={() => { onChange(t.id); setOpen(false); }}
            >
              {/* Background swatch (dark/light preview) */}
              <div style={{
                width: 10, height: 10, borderRadius: '50%', flexShrink: 0,
                background: t.dot,
                border: `2px solid ${t.accent}`,
                boxShadow: `0 0 0 1px ${t.accent}55`,
              }}/>
              {/* Accent swatch */}
              <div style={{
                width: 10, height: 10, borderRadius: '50%', flexShrink: 0,
                background: t.accent,
              }}/>
              {t.label}
              {theme === t.id && (
                <svg style={{ marginLeft: 'auto' }} width="10" height="10"
                     viewBox="0 0 10 10" fill="none"
                     stroke="currentColor" strokeWidth="2">
                  <path d="M2 5l2.5 2.5L8 3"/>
                </svg>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main Application
// ─────────────────────────────────────────────────────────────────────────────
// ── Main App ──

const { useState, useEffect, useRef, useMemo, useCallback } = React;

// ── Constants ────────────────────────────────────────────────────────────────
const MAX_ALERTS = 5000;
const SSE_URL    = '/events';

const SEV_COLORS = {
  critical: 'var(--red)',
  high:     'var(--orange)',
  medium:   'var(--yellow)',
  low:      'var(--green)',
  info:     'var(--accent)',
};

// ── Helpers ───────────────────────────────────────────────────────────────────
// today/yesterday epoch boundaries are cached and refreshed once per minute
// so the 4-Date-object per-call overhead is gone from the hot render path.
let _fmtCache = { todayStart: 0, yestStart: 0, ts: 0 };
function _refreshFmtCache() {
  const now   = new Date();
  now.setHours(0, 0, 0, 0);
  _fmtCache = {
    todayStart: now.getTime(),
    yestStart:  now.getTime() - 86400000,
    ts:         Date.now(),
  };
}
_refreshFmtCache();

function fmtTime(ts) {
  try {
    if (Date.now() - _fmtCache.ts > 60000) _refreshFmtCache();
    const d = new Date(ts);
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

function fmtBytes(n) {
  if (!n || n === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(n) / Math.log(1024));
  return (n / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
}

function fmtDur(s) {
  if (!s || s === 0) return '0s';
  if (s < 60)  return s.toFixed(1) + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm ' + Math.floor(s % 60) + 's';
  return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
}

// ── Clock ─────────────────────────────────────────────────────────────────────
function Clock() {
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
function Sparkline({ data }) {
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
function Timeline({ alerts }) {
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

// ── Acknowledgement ──────────────────────────────────────────────────────────────
const ACK_STATUSES = [
  { value: 'new',            label: 'New',            color: 'var(--text3)',  bg: 'var(--bg3)' },
  { value: 'investigating',  label: 'Investigating',  color: 'var(--yellow)', bg: 'var(--yellow-d)' },
  { value: 'acknowledged',   label: 'Acknowledged',   color: 'var(--green)',  bg: 'var(--green-d)' },
  { value: 'false_positive', label: 'False Positive', color: 'var(--purple)', bg: 'rgba(159,122,234,.13)' },
];
const ACK_MAP = Object.fromEntries(ACK_STATUSES.map(s => [s.value, s]));

function AckBadge({ status }) {
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

// ── Safe JSON Syntax Highlighter ─────────────────────────────────────────────
function HighlightedJSON({ data }) {
  const jsonString = JSON.stringify(data, null, 2);

  // Tokenize the JSON string into React elements
  const tokens = [];
  let i = 0;
  const length = jsonString.length;

  while (i < length) {
    const char = jsonString[i];

    // Whitespace
    if (/\s/.test(char)) {
      tokens.push(char);
      i++;
      continue;
    }

    // Punctuation / structural characters
    if ('{}[],:'.includes(char)) {
      tokens.push(<span key={i} className="json-punct">{char}</span>);
      i++;
      continue;
    }

    // String literals (including property keys)
    if (char === '"') {
      let j = i + 1;
      let escaped = false;
      while (j < length) {
        if (jsonString[j] === '"' && !escaped) break;
        escaped = jsonString[j] === '\\' && !escaped;
        j++;
      }
      const token = jsonString.slice(i, j + 1);
      const isKey = jsonString[j + 1] === ':' || (j + 1 < length && jsonString[j + 1] === ' ' && jsonString[j + 2] === ':');
      tokens.push(
        <span key={i} className={isKey ? 'json-key' : 'json-string'}>
          {token}
        </span>
      );
      i = j + 1;
      continue;
    }

    // Numbers
    if (/[0-9\-]/.test(char)) {
      let j = i;
      while (j < length && /[0-9eE.\-+]/.test(jsonString[j])) j++;
      const token = jsonString.slice(i, j);
      tokens.push(<span key={i} className="json-number">{token}</span>);
      i = j;
      continue;
    }

    // Booleans / null
    if (/[a-zA-Z]/.test(char)) {
      let j = i;
      while (j < length && /[a-zA-Z]/.test(jsonString[j])) j++;
      const token = jsonString.slice(i, j);
      const cls = token === 'true' || token === 'false' ? 'json-boolean' : 'json-null';
      tokens.push(<span key={i} className={cls}>{token}</span>);
      i = j;
      continue;
    }

    // Fallback
    tokens.push(char);
    i++;
  }

  return <pre className="rawjson">{tokens}</pre>;
}

// ── Detail Panel ──────────────────────────────────────────────────────────────
function Detail({ alert, onAck, role }) {
  const [ackStatus,   setAckStatus]   = useState(alert?.ack_status || 'new');
  const [ackNote,     setAckNote]     = useState(alert?.ack_note   || '');
  const [saving,      setSaving]      = useState(false);
  const [saveMsg,     setSaveMsg]     = useState('');
  const [tab,         setTab]         = useState('details'); // 'details'|'history'|'raw'
  const [history,     setHistory]     = useState([]);
  const [histLoading, setHistLoading] = useState(false);

  // Reset local state whenever a different alert is selected
  useEffect(() => {
    setAckStatus(alert?.ack_status || 'new');
    setAckNote(alert?.ack_note     || '');
    setSaveMsg('');
    setTab('details');
    setHistory([]);
  }, [alert?.id]);

  // Fetch history when the history tab is opened
  useEffect(() => {
    if (tab !== 'history' || !alert) return;
    setHistLoading(true);
    fetch(`/alerts/${alert.id}/ack/history`)
      .then(r => r.json())
      .then(d => { setHistory(Array.isArray(d) ? d : []); setHistLoading(false); })
      .catch(() => setHistLoading(false));
  }, [tab, alert?.id]);

  async function submitAck() {
    if (!alert) return;
    setSaving(true); setSaveMsg('');
    try {
      const r = await fetch(`/alerts/${alert.id}/ack`, {
        method:  'POST',
        headers: {'Content-Type':'application/json'},
        body:    JSON.stringify({status: ackStatus, note: ackNote}),
      });
      const d = await r.json();
      if (r.ok) {
        setSaveMsg('✓ Saved');
        onAck && onAck(alert.id, ackStatus, ackNote);
        // Refresh history list silently if the tab is open
        if (tab === 'history') {
          fetch(`/alerts/${alert.id}/ack/history`)
            .then(r => r.json()).then(d => setHistory(Array.isArray(d) ? d : [])).catch(()=>{});
        }
      } else {
        setSaveMsg(`✗ ${d.error || 'Failed'}`);
      }
    } catch { setSaveMsg('✗ Network error'); }
    setSaving(false);
    setTimeout(() => setSaveMsg(''), 3000);
  }

  if (!alert) return (
    <div className="dscroll">
      <div className="empty" style={{ height: '100%' }}>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
          <rect x="3" y="3" width="18" height="18" rx="2" />
          <line x1="3" y1="9" x2="21" y2="9" />
          <line x1="9" y1="21" x2="9"  y2="9" />
        </svg>
        <div>Select an alert</div>
        <div style={{ fontSize: 10 }}>to view full details</div>
      </div>
    </div>
  );

  const F = ({ label, val, full, color }) => (
    <div className={`dfield${full ? ' dfull' : ''}`}>
      <div className="dfield-label">{label}</div>
      <div className="dfield-val" style={color ? { color } : {}}>{val ?? '—'}</div>
    </div>
  );

  const tabBtn = (id, label) => (
    <button onClick={() => setTab(id)} style={{
      padding: '2px 10px', borderRadius: 'var(--radius-sm)', border: 'none',
      background: tab === id ? 'var(--accent)' : 'transparent',
      color:      tab === id ? 'white' : 'var(--text3)',
      fontSize: 11, fontFamily: 'var(--mono)', cursor: 'pointer', transition: 'all .15s',
    }}>{label}</button>
  );

  return (
    <div style={{display:'flex', flexDirection:'column', flex:1, overflow:'hidden'}}>
      {/* Tab bar */}
      <div style={{
        display:'flex', alignItems:'center', padding:'8px 12px',
        borderBottom:'1px solid var(--border)', background:'var(--bg1)', flexShrink:0,
      }}>
        <div style={{display:'flex', gap:1, background:'var(--bg3)',
                     border:'1px solid var(--border)', borderRadius:'var(--radius-sm)', padding:2}}>
          {tabBtn('details', 'Details')}
          {tabBtn('history', 'History')}
          {tabBtn('raw',     'Raw JSON')}
        </div>
      </div>

      {/* ── Details tab ── */}
      {tab === 'details' && (
        <div className="dscroll">
          <div className="dsec">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
              <span className={`sbadge ${alert.severity}`}>{alert.severity}</span>
              <span style={{ fontSize: 13, fontWeight: 500, lineHeight: 1.3 }}>
                {alert.sig_msg}
              </span>
            </div>
          </div>

          <div className="dsec">
            <div className="dsec-title">Network</div>
            <div className="dgrid">
              <F label="Source IP"   val={alert.src_ip} />
              <F label="Source Port" val={alert.src_port} />
              <F label="Dest IP"     val={alert.dst_ip} />
              <F label="Dest Port"   val={alert.dst_port} />
              <F label="Protocol"    val={alert.proto} />
              <F label="Action"      val={alert.action}
                 color={alert.action === 'blocked' ? 'var(--red)' : 'var(--green)'} />
            </div>
          </div>

          <div className="dsec">
            <div className="dsec-title">Signature</div>
            <div className="dgrid">
              <F label="SID"       val={alert.sig_id} />
              <F label="Category"  val={alert.category} />
              <F label="Flow ID"   val={alert.flow_id}  full />
              <F label="Timestamp" val={alert.ts}        full />
            </div>
          </div>

          {role !== 'viewer' && (
            <div className="dsec">
              <div className="dsec-title">Status & Notes</div>
              <div style={{display:'flex',flexWrap:'wrap',gap:6,marginBottom:10}}>
                {ACK_STATUSES.map(s => (
                  <button key={s.value} onClick={() => setAckStatus(s.value)} style={{
                    padding:'3px 10px', borderRadius:'var(--radius-sm)', cursor:'pointer',
                    border:`1px solid ${ackStatus===s.value ? s.color : 'var(--border)'}`,
                    background: ackStatus===s.value ? s.bg : 'transparent',
                    color:      ackStatus===s.value ? s.color : 'var(--text3)',
                    fontSize:10, fontFamily:'var(--mono)', fontWeight:500,
                    letterSpacing:'.05em', textTransform:'uppercase', transition:'all .15s',
                  }}>{s.label}</button>
                ))}
              </div>
              <textarea
                value={ackNote}
                onChange={e => setAckNote(e.target.value)}
                placeholder="Add analyst note (optional)…"
                rows={3}
                style={{
                  width:'100%', padding:'7px 9px',
                  background:'var(--bg2)', border:'1px solid var(--border)',
                  borderRadius:'var(--radius-sm)', color:'var(--text1)',
                  fontSize:11, fontFamily:'var(--sans)', resize:'vertical',
                  outline:'none', lineHeight:1.5,
                }}
                onFocus={e => e.target.style.borderColor='var(--accent)'}
                onBlur={e  => e.target.style.borderColor='var(--border)'}
              />
              <div style={{display:'flex',alignItems:'center',gap:8,marginTop:8}}>
                <button onClick={submitAck} disabled={saving} style={{
                  padding:'4px 14px', borderRadius:'var(--radius-sm)',
                  border:'1px solid var(--accent)', background:'var(--accent-d)',
                  color:'var(--accent)', fontSize:11, fontFamily:'var(--sans)',
                  cursor: saving ? 'wait' : 'pointer', transition:'all .15s',
                }}>{saving ? 'Saving…' : 'Save'}</button>
                {saveMsg && (
                  <span style={{fontSize:11, fontFamily:'var(--mono)',
                    color: saveMsg.startsWith('✓') ? 'var(--green)' : 'var(--red)'}}>
                    {saveMsg}
                  </span>
                )}
                {alert.ack_by && (
                  <span style={{fontSize:10, fontFamily:'var(--mono)',
                                color:'var(--text3)', marginLeft:'auto'}}>
                    by {alert.ack_by}
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── History tab ── */}
      {tab === 'history' && (
        <div className="dscroll">
          <div className="dsec-title" style={{marginBottom:14}}>Acknowledgement History</div>
          {histLoading && (
            <div style={{color:'var(--text3)', fontSize:12, fontFamily:'var(--mono)',
                         textAlign:'center', padding:'30px 0'}}>Loading…</div>
          )}
          {!histLoading && history.length === 0 && (
            <div className="empty" style={{height:160}}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
                <circle cx="12" cy="12" r="10"/>
                <polyline points="12 6 12 12 16 14"/>
              </svg>
              <div>No history yet</div>
              <div style={{fontSize:10}}>Changes appear here after the first save</div>
            </div>
          )}
          {!histLoading && history.map((h, i) => {
            const cfg     = ACK_MAP[h.status] || ACK_MAP['new'];
            const date    = new Date(h.changed_at * 1000);
            const dateStr = date.toLocaleDateString(undefined, {month:'short', day:'numeric', year:'numeric'});
            const timeStr = date.toLocaleTimeString('en-GB', {hour12:false});
            return (
              <div key={i} style={{
                display:'flex', gap:10, paddingBottom:14, marginBottom:14,
                borderBottom: i < history.length - 1 ? '1px solid var(--border)' : 'none',
              }}>
                {/* Timeline dot + vertical line */}
                <div style={{display:'flex', flexDirection:'column', alignItems:'center', flexShrink:0}}>
                  <div style={{
                    width:10, height:10, borderRadius:'50%', marginTop:3, flexShrink:0,
                    background: cfg.color, boxShadow:`0 0 0 3px ${cfg.bg}`,
                  }}/>
                  {i < history.length - 1 && (
                    <div style={{width:1, flex:1, background:'var(--border)', marginTop:5}}/>
                  )}
                </div>
                {/* Entry content */}
                <div style={{flex:1, minWidth:0}}>
                  <div style={{display:'flex', alignItems:'center', gap:7, marginBottom:5, flexWrap:'wrap'}}>
                    <span style={{
                      padding:'1px 7px', borderRadius:'var(--radius-sm)',
                      fontSize:9, fontWeight:500, fontFamily:'var(--mono)',
                      letterSpacing:'.05em', textTransform:'uppercase',
                      color: cfg.color, background: cfg.bg,
                    }}>{cfg.label}</span>
                    {h.username && (
                      <span style={{fontSize:10, fontFamily:'var(--mono)', color:'var(--text3)'}}>
                        by <b style={{color:'var(--text2)'}}>{h.username}</b>
                      </span>
                    )}
                  </div>
                  {h.note && (
                    <div style={{
                      fontSize:11, color:'var(--text2)', lineHeight:1.5, fontStyle:'italic',
                      background:'var(--bg2)', border:'1px solid var(--border)',
                      borderRadius:'var(--radius-sm)', padding:'5px 8px', marginBottom:5,
                    }}>"{h.note}"</div>
                  )}
                  <div style={{fontSize:10, fontFamily:'var(--mono)', color:'var(--text3)'}}>
                    {dateStr} · {timeStr}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ── Raw JSON tab ── */}
      {tab === 'raw' && (
        <div className="dscroll">
          <div className="dsec-title" style={{marginBottom:8}}>Raw EVE JSON</div>
          <HighlightedJSON data={alert.raw || alert} />
        </div>
      )}
    </div>
  );
}



// ── FlowsView ─────────────────────────────────────────────────────────────────
function FlowsView({ rows, loading, selected, onSelect, onClear }) {
  const [search, setSearch] = useState('');
  const [showClearConfirm, setShowClearConfirm] = useState(false);
  const q = search.toLowerCase();
  const filtered = useMemo(() =>
    rows.filter(r =>
      !q || r.src_ip?.includes(q) || r.dst_ip?.includes(q) ||
      r.proto?.toLowerCase().includes(q) || r.app_proto?.toLowerCase().includes(q)
    ),
    [rows, q]
  );

  const handleClearClick = () => {
    setShowClearConfirm(true);
  };

  const handleConfirmClear = () => {
    setShowClearConfirm(false);
    onClear && onClear();
  };

  return (
    <div style={{display:'flex',flexDirection:'column',overflow:'hidden',flex:1}}>
      <div className="pane-head">
        <span className="pane-title" style={{color:'var(--teal)'}}>Flow Events</span>
        <span className="pane-cnt">{filtered.length.toLocaleString()}</span>
        <div className="pane-actions">
          <div className="search">
            <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="7" cy="7" r="4"/><path d="M10 10l3 3"/>
            </svg>
            <input placeholder="Filter flows…" value={search} onChange={e=>setSearch(e.target.value)}/>
          </div>
          <button className="btn" onClick={handleClearClick}>Clear</button>
        </div>
      </div>
      <div className="tscroll">
        {loading ? (
          <div className="empty"><div>Loading…</div></div>
        ) : filtered.length === 0 ? (
          <div className="empty">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
            <div>No flow events yet</div>
          </div>
        ) : (
          <table>
            <thead><tr>
              <th style={{width:80}}>Time</th>
              <th style={{width:52}}>Proto</th>
              <th style={{width:105}}>Source</th>
              <th style={{width:105}}>Destination</th>
              <th style={{width:72}}>App Proto</th>
              <th style={{width:70}}>State</th>
              <th style={{width:80}}>↑ Bytes</th>
              <th style={{width:80}}>↓ Bytes</th>
              <th style={{width:65}}>Duration</th>
              <th style={{width:52}}>Alert</th>
            </tr></thead>
            <tbody>
              {filtered.slice(0,300).map((r,i) => (
                <tr key={r.flow_id||i}
                    className={`arow${selected?.flow_id===r.flow_id?' sel':''}`}
                    onClick={()=>onSelect(r)}>
                  <td className="mono-dim">{fmtTime(r.ts)}</td>
                  <td><span className="proto">{r.proto}</span></td>
                  <td className="mono">{r.src_ip}:{r.src_port}</td>
                  <td className="mono">{r.dst_ip}:{r.dst_port}</td>
                  <td className="mono-dim">{r.app_proto||'—'}</td>
                  <td className="mono-dim">{r.state}</td>
                  <td className="mono-dim">{fmtBytes(r.bytes_toserver)}</td>
                  <td className="mono-dim">{fmtBytes(r.bytes_toclient)}</td>
                  <td className="mono-dim">{fmtDur(r.duration_s)}</td>
                  <td><span style={{color:r.alerted?'var(--red)':'var(--text3)',fontSize:10,fontFamily:'var(--mono)'}}>{r.alerted?'YES':'—'}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {showClearConfirm && (
        <div className="modal-bg" onClick={() => setShowClearConfirm(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div style={{ fontSize: 15, fontWeight: 500, marginBottom: 10 }}>
              Clear all flow events?
            </div>
            <div style={{
              fontSize: 12, color: 'var(--text2)',
              lineHeight: 1.7, marginBottom: 24,
            }}>
              This will permanently delete{' '}
              <b style={{ color: 'var(--text1)' }}>
                {rows.length.toLocaleString()} stored flows
              </b>{' '}
              from the database. This action cannot be undone.
            </div>
            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button className="btn"
                      onClick={() => setShowClearConfirm(false)}
                      style={{ minWidth: 80 }}>
                Cancel
              </button>
              <button onClick={handleConfirmClear}
                      style={{
                        minWidth: 80, padding: '4px 14px',
                        borderRadius: 'var(--radius-sm)',
                        border: '1px solid var(--red)',
                        background: 'var(--red-d)',
                        color: 'var(--red)', fontSize: 11,
                        fontFamily: 'var(--sans)',
                        cursor: 'pointer',
                        transition: 'all .15s',
                      }}>
                Yes, delete all
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── FlowDetail ────────────────────────────────────────────────────────────────
function FlowDetail({ item }) {
  if (!item) return (
    <div className="dscroll">
      <div className="empty" style={{height:'100%'}}>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
        <div>Select a flow</div>
      </div>
    </div>
  );
  const F = ({label,val,full,color})=>(
    <div className={`dfield${full?' dfull':''}`}>
      <div className="dfield-label">{label}</div>
      <div className="dfield-val" style={color?{color}:{}}>{val??'—'}</div>
    </div>
  );
  return (
    <div className="dscroll">
      <div className="dsec">
        <div className="dsec-title">Connection</div>
        <div className="dgrid">
          <F label="Source IP"    val={item.src_ip}/>
          <F label="Source Port"  val={item.src_port}/>
          <F label="Dest IP"      val={item.dst_ip}/>
          <F label="Dest Port"    val={item.dst_port}/>
          <F label="Protocol"     val={item.proto}/>
          <F label="App Protocol" val={item.app_proto||'—'}/>
          <F label="State"        val={item.state}/>
          <F label="Reason"       val={item.reason}/>
          <F label="Duration"     val={fmtDur(item.duration_s)}/>
          <F label="Alerted"      val={item.alerted?'Yes':'No'} color={item.alerted?'var(--red)':'var(--green)'}/>
        </div>
      </div>
      <div className="dsec">
        <div className="dsec-title">Traffic</div>
        <div className="dgrid">
          <F label="Pkts → Server"  val={item.pkts_toserver}/>
          <F label="Pkts → Client"  val={item.pkts_toclient}/>
          <F label="Bytes → Server" val={fmtBytes(item.bytes_toserver)}/>
          <F label="Bytes → Client" val={fmtBytes(item.bytes_toclient)}/>
          <F label="Timestamp" val={item.ts} full/>
        </div>
      </div>
    </div>
  );
}

// ── DNSView ───────────────────────────────────────────────────────────────────
function DNSView({ rows, loading, selected, onSelect, onClear }) {
  const [search, setSearch] = useState('');
  const [showClearConfirm, setShowClearConfirm] = useState(false);
  const q = search.toLowerCase();
  const filtered = useMemo(() =>
    rows.filter(r =>
      !q || r.rrname?.toLowerCase().includes(q) || r.src_ip?.includes(q) ||
      r.rrtype?.toLowerCase().includes(q) || r.rcode?.toLowerCase().includes(q)
    ),
    [rows, q]
  );

  const handleConfirmClear = () => {
    setShowClearConfirm(false);
    onClear && onClear();
  };

  return (
    <div style={{display:'flex',flexDirection:'column',overflow:'hidden',flex:1}}>
      <div className="pane-head">
        <span className="pane-title" style={{color:'var(--purple)'}}>DNS Queries</span>
        <span className="pane-cnt">{filtered.length.toLocaleString()}</span>
        <div className="pane-actions">
          <div className="search">
            <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="7" cy="7" r="4"/><path d="M10 10l3 3"/>
            </svg>
            <input placeholder="Filter by name, IP…" value={search} onChange={e=>setSearch(e.target.value)}/>
          </div>
          <button className="btn" onClick={() => setShowClearConfirm(true)}>Clear</button>
        </div>
      </div>
      <div className="tscroll">
        {loading ? (
          <div className="empty"><div>Loading…</div></div>
        ) : filtered.length === 0 ? (
          <div className="empty">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
            <div>No DNS events yet</div>
          </div>
        ) : (
          <table>
            <thead><tr>
              <th style={{width:80}}>Time</th>
              <th style={{width:90}}>Type</th>
              <th style={{width:70}}>RCode</th>
              <th style={{width:105}}>Source</th>
              <th style={{width:105}}>Resolver</th>
            </tr></thead>
            <tbody>
              {filtered.slice(0,300).map((r,i) => (
                <tr key={r.id||i}
                    className={`arow${selected?.id===r.id?' sel':''}`}
                    onClick={()=>onSelect(r)}>
                  <td className="mono-dim">{fmtTime(r.ts)}</td>
                  <td><span className="proto">{r.dns_type}</span></td>
                  <td className="mono-dim">{r.rcode||'—'}</td>
                  <td className="mono">{r.src_ip}</td>
                  <td className="mono">{r.dst_ip}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {showClearConfirm && (
        <div className="modal-bg" onClick={() => setShowClearConfirm(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div style={{ fontSize: 15, fontWeight: 500, marginBottom: 10 }}>
              Clear all DNS events?
            </div>
            <div style={{
              fontSize: 12, color: 'var(--text2)',
              lineHeight: 1.7, marginBottom: 24,
            }}>
              This will permanently delete{' '}
              <b style={{ color: 'var(--text1)' }}>
                {rows.length.toLocaleString()} stored DNS events
              </b>{' '}
              from the database. This action cannot be undone.
            </div>
            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button className="btn"
                      onClick={() => setShowClearConfirm(false)}
                      style={{ minWidth: 80 }}>
                Cancel
              </button>
              <button onClick={handleConfirmClear}
                      style={{
                        minWidth: 80, padding: '4px 14px',
                        borderRadius: 'var(--radius-sm)',
                        border: '1px solid var(--red)',
                        background: 'var(--red-d)',
                        color: 'var(--red)', fontSize: 11,
                        fontFamily: 'var(--sans)',
                        cursor: 'pointer',
                        transition: 'all .15s',
                      }}>
                Yes, delete all
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── DNSDetail ─────────────────────────────────────────────────────────────────
function DNSDetail({ item }) {
  if (!item) return (
    <div className="dscroll">
      <div className="empty" style={{height:'100%'}}>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/></svg>
        <div>Select a DNS event</div>
      </div>
    </div>
  );
  const F = ({label,val,full})=>(
    <div className={`dfield${full?' dfull':''}`}>
      <div className="dfield-label">{label}</div>
      <div className="dfield-val">{val??'—'}</div>
    </div>
  );
  return (
    <div className="dscroll">
      <div className="dsec">
        <div className="dsec-title">DNS Query</div>
        <div className="dgrid">
          <F label="Query Name"  val={item.rrname} full/>
          <F label="Type"       val={item.dns_type}/>
          <F label="RCode"      val={item.rcode}/>
          <F label="TTL"        val={item.ttl?item.ttl+'s':'—'}/>
          <F label="Source IP"  val={item.src_ip}/>
          <F label="Resolver"   val={item.dst_ip}/>
          <F label="Flow ID"    val={item.flow_id}/>
          <F label="TX ID"      val={item.tx_id}/>
          <F label="Timestamp"  val={item.ts} full/>
        </div>
      </div>
      {item.answers && item.answers.length > 0 && (
        <div className="dsec">
          <div className="dsec-title">Answers</div>
          <HighlightedJSON data={item.answers} />
        </div>
      )}
    </div>
  );
}

// ── Charts ─────────────────────────────────────────────────────────────────
// ── ChartsView ────────────────────────────────────────────────────────────────
// Pure SVG charts — no external charting library.
// Three panels: Top Talkers (bar), Alert Trend (area), Category Donut.

const CHART_SEV_COLORS = {
  critical: '#f05454', high: '#f5944a',
  medium:   '#f5c842', low:  '#4caf82', info: '#4f9cf9',
};

const CAT_PALETTE = [
  '#4f9cf9','#f5944a','#9f7aea','#2dd4bf','#f5c842',
  '#f05454','#4caf82','#e879f9','#60a5fa','#a3e635',
  '#fb923c','#94a3b8',
];

// ── Shared empty state ────────────────────────────────────────────────────────
function ChartEmpty({ message = 'No data for this period' }) {
  return (
    <div style={{display:'flex',flexDirection:'column',alignItems:'center',
                 justifyContent:'center',height:'100%',gap:10,
                 color:'var(--text3)',fontSize:12}}>
      <svg width="36" height="36" viewBox="0 0 24 24" fill="none"
           stroke="currentColor" strokeWidth="1" opacity=".3">
        <rect x="2" y="12" width="4" height="10" rx="1"/>
        <rect x="9" y="8"  width="4" height="14" rx="1"/>
        <rect x="16" y="4" width="4" height="18" rx="1"/>
      </svg>
      <span>{message}</span>
    </div>
  );
}

// ── Top Talkers — horizontal bar chart ───────────────────────────────────────
function TopTalkersChart({ data }) {
  if (!data || data.length === 0) return <ChartEmpty/>;
  const max = data[0].count;
  return (
    <div style={{padding:'4px 0',overflow:'hidden'}}>
      {data.map((row, i) => {
        const pct = max > 0 ? (row.count / max) * 100 : 0;
        return (
          <div key={row.ip} style={{
            display:'grid',
            gridTemplateColumns:'130px 1fr 52px',
            alignItems:'center',
            gap:10,
            padding:'5px 0',
            borderBottom: i < data.length-1 ? '1px solid var(--border)' : 'none',
          }}>
            <div style={{
              fontFamily:'var(--mono)',fontSize:11,color:'var(--text2)',
              overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',
              textAlign:'right',
            }}>{row.ip}</div>
            <div style={{position:'relative',height:18,background:'var(--bg2)',
                         borderRadius:3,overflow:'hidden'}}>
              <div style={{
                position:'absolute',inset:'0 auto 0 0',
                width:`${pct}%`,
                background:`linear-gradient(90deg, var(--accent), var(--accent) 60%, rgba(79,156,249,.5))`,
                borderRadius:3,
                transition:'width .4s ease',
              }}/>
              <div style={{
                position:'absolute',inset:0,
                display:'flex',alignItems:'center',paddingLeft:8,
                fontFamily:'var(--mono)',fontSize:10,color:'white',
                mixBlendMode:'screen',
              }}>{pct.toFixed(0)}%</div>
            </div>
            <div style={{
              fontFamily:'var(--mono)',fontSize:11,
              color:'var(--text1)',textAlign:'right',
            }}>{row.count.toLocaleString()}</div>
          </div>
        );
      })}
    </div>
  );
}

// ── Alert Trend — SVG area chart ─────────────────────────────────────────────
function TrendChart({ data, window }) {
  if (!data || data.length === 0) return <ChartEmpty/>;

  const W = 560, H = 140, PAD = { t:16, r:16, b:32, l:44 };
  const iW = W - PAD.l - PAD.r;
  const iH = H - PAD.t - PAD.b;

  const maxVal = Math.max(1, ...data.map(d => d.count));
  // Round up to a nice number for Y axis
  const yMax  = Math.ceil(maxVal / 5) * 5 || 5;
  const yTicks = [0, Math.round(yMax*0.25), Math.round(yMax*0.5),
                  Math.round(yMax*0.75), yMax];

  const xPos = i => PAD.l + (i / (data.length - 1)) * iW;
  const yPos = v => PAD.t + iH - (v / yMax) * iH;

  // Build path
  const pts = data.map((d, i) => `${xPos(i).toFixed(1)},${yPos(d.count).toFixed(1)}`);
  const linePath  = `M ${pts.join(' L ')}`;
  const areaPath  = `M ${xPos(0).toFixed(1)},${(PAD.t+iH).toFixed(1)} ` +
                    `L ${pts.join(' L ')} ` +
                    `L ${xPos(data.length-1).toFixed(1)},${(PAD.t+iH).toFixed(1)} Z`;

  // X-axis label indices — show every N-th to avoid crowding
  const labelStep = Math.ceil(data.length / 8);

  // Build the set of label indices to render, ensuring no two labels are
  // closer than half a labelStep apart (prevents end-of-chart overlap).
  const labelIndices = new Set();
  for (let i = 0; i < data.length; i++) {
    if (i % labelStep === 0) labelIndices.add(i);
  }
  // Only add the last index if it isn't too close to the previous label
  const lastRegular = Math.floor((data.length - 1) / labelStep) * labelStep;
  if (data.length - 1 - lastRegular >= Math.ceil(labelStep / 2)) {
    labelIndices.add(data.length - 1);
  }

  return (
    <svg viewBox={`0 0 ${W} ${H}`} style={{width:'100%',height:'auto',overflow:'visible'}}>
      <defs>
        <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%"   stopColor="var(--accent)" stopOpacity=".35"/>
          <stop offset="100%" stopColor="var(--accent)" stopOpacity=".02"/>
        </linearGradient>
      </defs>

      {/* Y-axis grid lines + labels */}
      {yTicks.map(v => (
        <g key={v}>
          <line x1={PAD.l} y1={yPos(v)} x2={PAD.l+iW} y2={yPos(v)}
                stroke="var(--border)" strokeWidth="1"/>
          <text x={PAD.l-6} y={yPos(v)} textAnchor="end"
                dominantBaseline="middle" fontSize="9"
                fill="var(--text3)" fontFamily="var(--mono)">{v}</text>
        </g>
      ))}

      {/* Area fill */}
      <path d={areaPath} fill="url(#areaGrad)"/>

      {/* Line */}
      <path d={linePath} fill="none" stroke="var(--accent)"
            strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round"/>

      {/* Data point dots on hover — simplified: just mark non-zero */}
      {data.map((d, i) => d.count > 0 && (
        <circle key={i} cx={xPos(i)} cy={yPos(d.count)} r="2.5"
                fill="var(--accent)" opacity=".8"/>
      ))}

      {/* X-axis labels */}
      {data.map((d, i) => {
        if (!labelIndices.has(i)) return null;
        return (
          <text key={i} x={xPos(i)} y={H - 6}
                textAnchor="middle" fontSize="9"
                fill="var(--text3)" fontFamily="var(--mono)">
            {d.ts}
          </text>
        );
      })}

      {/* Axis lines */}
      <line x1={PAD.l} y1={PAD.t} x2={PAD.l} y2={PAD.t+iH}
            stroke="var(--border2)" strokeWidth="1"/>
      <line x1={PAD.l} y1={PAD.t+iH} x2={PAD.l+iW} y2={PAD.t+iH}
            stroke="var(--border2)" strokeWidth="1"/>
    </svg>
  );
}

// ── Category Donut chart ──────────────────────────────────────────────────────
function DonutChart({ data }) {
  if (!data || data.length === 0) return <ChartEmpty/>;

  const total = data.reduce((s, d) => s + d.count, 0);
  if (total === 0) return <ChartEmpty/>;

  const R = 70, r = 42, CX = 90, CY = 90;
  let angle = -Math.PI / 2;  // start at top

  const slices = data.map((d, i) => {
    const sweep  = (d.count / total) * 2 * Math.PI;
    const x1 = CX + R * Math.cos(angle);
    const y1 = CY + R * Math.sin(angle);
    angle += sweep;
    const x2 = CX + R * Math.cos(angle);
    const y2 = CY + R * Math.sin(angle);
    const xi1 = CX + r * Math.cos(angle);
    const yi1 = CY + r * Math.sin(angle);
    angle -= sweep;
    const xi2 = CX + r * Math.cos(angle);
    const yi2 = CY + r * Math.sin(angle);
    angle += sweep;

    const large = sweep > Math.PI ? 1 : 0;
    const path  = `M ${x1.toFixed(2)} ${y1.toFixed(2)}
                   A ${R} ${R} 0 ${large} 1 ${x2.toFixed(2)} ${y2.toFixed(2)}
                   L ${xi1.toFixed(2)} ${yi1.toFixed(2)}
                   A ${r} ${r} 0 ${large} 0 ${xi2.toFixed(2)} ${yi2.toFixed(2)} Z`;
    return { ...d, path, color: CAT_PALETTE[i % CAT_PALETTE.length] };
  });

  return (
    <div style={{display:'flex',alignItems:'center',gap:20,flexWrap:'wrap'}}>
      <svg viewBox="0 0 180 180" style={{width:160,height:160,flexShrink:0}}>
        {slices.map((s, i) => (
          <path key={i} d={s.path} fill={s.color} opacity=".85"
                style={{transition:'opacity .15s'}}
                onMouseEnter={e=>e.target.setAttribute('opacity','1')}
                onMouseLeave={e=>e.target.setAttribute('opacity','.85')}/>
        ))}
        {/* Centre label */}
        <text x={CX} y={CY-6} textAnchor="middle" fontSize="18"
              fontWeight="600" fill="var(--text1)" fontFamily="var(--mono)">
          {total.toLocaleString()}
        </text>
        <text x={CX} y={CY+10} textAnchor="middle" fontSize="8"
              fill="var(--text3)" fontFamily="var(--mono)" letterSpacing=".08em">
          ALERTS
        </text>
      </svg>

      {/* Legend */}
      <div style={{flex:1,minWidth:120,display:'flex',flexDirection:'column',gap:6}}>
        {slices.map((s, i) => (
          <div key={i} style={{display:'flex',alignItems:'center',gap:7,fontSize:11}}>
            <div style={{width:8,height:8,borderRadius:2,
                         background:s.color,flexShrink:0}}/>
            <div style={{flex:1,color:'var(--text2)',overflow:'hidden',
                         textOverflow:'ellipsis',whiteSpace:'nowrap'}}>
              {s.category}
            </div>
            <div style={{fontFamily:'var(--mono)',fontSize:10,color:'var(--text3)'}}>
              {((s.count/total)*100).toFixed(1)}%
            </div>
            <div style={{fontFamily:'var(--mono)',fontSize:10,
                         color:'var(--text1)',minWidth:30,textAlign:'right'}}>
              {s.count}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Severity Bar chart ────────────────────────────────────────────────────────
function SeverityBars({ data }) {
  if (!data || data.length === 0) return <ChartEmpty/>;
  const total = data.reduce((s, d) => s + d.count, 0);
  if (total === 0) return <ChartEmpty/>;
  const order = ['critical','high','medium','low','info'];
  const sorted = [...data].sort((a,b) =>
    order.indexOf(a.severity) - order.indexOf(b.severity));

  return (
    <div style={{display:'flex',flexDirection:'column',gap:8,padding:'4px 0'}}>
      {sorted.map(row => {
        const pct   = (row.count / total) * 100;
        const color = CHART_SEV_COLORS[row.severity] || 'var(--accent)';
        return (
          <div key={row.severity} style={{
            display:'grid',gridTemplateColumns:'70px 1fr 48px',
            alignItems:'center',gap:10,
          }}>
            <div style={{
              fontFamily:'var(--mono)',fontSize:10,color,
              textTransform:'uppercase',letterSpacing:'.05em',textAlign:'right',
            }}>{row.severity}</div>
            <div style={{height:20,background:'var(--bg2)',borderRadius:3,
                         overflow:'hidden',position:'relative'}}>
              <div style={{
                position:'absolute',inset:'0 auto 0 0',
                width:`${pct}%`,
                background:color,
                opacity:.75,
                borderRadius:3,
                transition:'width .4s ease',
              }}/>
              <div style={{
                position:'absolute',inset:0,display:'flex',
                alignItems:'center',paddingLeft:8,
                fontFamily:'var(--mono)',fontSize:10,color:'white',
                mixBlendMode:'screen',
              }}>{pct.toFixed(1)}%</div>
            </div>
            <div style={{fontFamily:'var(--mono)',fontSize:11,
                         color:'var(--text1)',textAlign:'right'}}>
              {row.count.toLocaleString()}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── ChartsView — main container ───────────────────────────────────────────────
function ChartsView() {
  const [data,     setData]     = useState(null);
  const [loading,  setLoading]  = useState(true);
  const [trend,    setTrend]    = useState(24);   // 24h or 168h (7d)
  const [days,     setDays]     = useState(1);    // data window for other charts

  function load(trendHours, daysWindow) {
    setLoading(true);
    fetch(`/charts?trend=${trendHours}&days=${daysWindow}`)
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }

  useEffect(() => { load(trend, days); }, []);

  function switchTrend(h) {
    setTrend(h);
    const d = Math.max(1, h / 24);  // 24h→1, 168h→7, 720h→30, 1440h→60, 2160h→90
    setDays(d);
    load(h, d);
  }

  const Card = ({ title, subtitle, children, extra }) => (
    <div style={{
      background:'var(--bg1)', border:'1px solid var(--border)',
      borderRadius:'var(--radius-lg)', overflow:'hidden',
    }}>
      <div style={{
        display:'flex',alignItems:'center',gap:8,
        padding:'12px 16px',
        borderBottom:'1px solid var(--border)',
        background:'var(--bg1)',
      }}>
        <div>
          <div style={{fontSize:12,fontWeight:500,color:'var(--text1)'}}>{title}</div>
          {subtitle && <div style={{fontSize:10,color:'var(--text3)',marginTop:1,fontFamily:'var(--mono)'}}>{subtitle}</div>}
        </div>
        {extra && <div style={{marginLeft:'auto'}}>{extra}</div>}
      </div>
      <div style={{padding:'14px 16px',minHeight:120}}>
        {loading
          ? <div style={{display:'flex',alignItems:'center',justifyContent:'center',
                         height:120,color:'var(--text3)',fontSize:12,
                         fontFamily:'var(--mono)'}}>Loading…</div>
          : children
        }
      </div>
    </div>
  );

  const TREND_OPTIONS = [
    {label:'24h', val:24},
    {label:'7d',  val:168},
    {label:'30d', val:720},
    {label:'60d', val:1440},
    {label:'90d', val:2160},
  ];

  const TrendToggle = () => (
    <div style={{display:'flex',gap:1,background:'var(--bg2)',
                 border:'1px solid var(--border)',borderRadius:'var(--radius-sm)',
                 padding:2}}>
      {TREND_OPTIONS.map(({label,val}) => (
        <button key={val}
          onClick={() => switchTrend(val)}
          style={{
            padding:'2px 10px',borderRadius:'var(--radius-sm)',border:'none',
            background: trend===val ? 'var(--accent)' : 'transparent',
            color:      trend===val ? 'white' : 'var(--text3)',
            fontSize:11,fontFamily:'var(--mono)',cursor:'pointer',
            transition:'all .15s',
          }}>{label}</button>
      ))}
    </div>
  );

  const opt = TREND_OPTIONS.find(o => o.val === trend);
  const window_label = opt ? 'Last ' + opt.label : 'Last ' + trend + 'h';

  return (
    <main className="main" style={{overflow:'auto'}}>
      <div style={{padding:'20px 24px',display:'flex',flexDirection:'column',gap:20}}>

        {/* Row 1: Trend chart (full width) */}
        <Card
          title="Alert Trend"
          subtitle={window_label}
          extra={<TrendToggle/>}
        >
          <TrendChart data={data?.trend} window={trend}/>
        </Card>

        {/* Row 2: Top Talkers + Severity side by side */}
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:20}}>
          <Card
            title="Top Talkers"
            subtitle={`Top 10 source IPs · ${window_label}`}
          >
            <TopTalkersChart data={data?.top_talkers}/>
          </Card>
          <Card
            title="Alerts by Severity"
            subtitle={window_label}
          >
            <SeverityBars data={data?.by_severity}/>
          </Card>
        </div>

        {/* Row 3: Category Donut (full width) */}
        <Card
          title="Alerts by Category"
          subtitle={window_label}
        >
          <DonutChart data={data?.by_category}/>
        </Card>

      </div>
    </main>
  );
}

// ── SettingsView — User Management (Admin only) ───────────────────────────────
function UserForm({ initial, onSave, onCancel }) {
  const editing = !!initial?.id;
  const [username, setUsername] = useState(initial?.username || '');
  const [password, setPassword] = useState('');
  const [role,     setRole]     = useState(initial?.role || 'analyst');
  const [enabled,  setEnabled]  = useState(initial?.enabled !== false);
  const [saving,   setSaving]   = useState(false);
  const [err,      setErr]      = useState('');

  async function save() {
    if (!username.trim()) { setErr('Username is required'); return; }
    if (!editing && !password.trim()) { setErr('Password is required'); return; }
    setSaving(true); setErr('');
    const body = { username: username.trim(), role, enabled };
    if (password.trim()) body.password = password.trim();
    const method   = editing ? 'PUT'  : 'POST';
    const endpoint = editing ? `/users/${initial.id}` : '/users';
    try {
      const r = await fetch(endpoint, {
        method, headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const d = await r.json();
      if (!r.ok) { setErr(d.error || 'Save failed'); return; }
      onSave(d);
    } catch { setErr('Network error'); }
    finally  { setSaving(false); }
  }

  const ROLE_INFO = {
    admin:   'Full access — all views, clear data, manage users & webhooks',
    analyst: 'Read-only — all views, no destructive actions',
    viewer:  'Stream only — alert list, no detail panel or controls',
  };

  return (
    <div className="modal-bg" onClick={onCancel}>
      <div className="modal" style={{width:440,maxWidth:'95vw'}}
           onClick={e => e.stopPropagation()}>
        <div style={{fontSize:15,fontWeight:500,marginBottom:20}}>
          {editing ? `Edit user: ${initial.username}` : 'Create user'}
        </div>

        <div className="form-row">
          <label className="form-label">Username</label>
          <input className="form-input" placeholder="e.g. analyst1"
                 value={username} onChange={e => setUsername(e.target.value)}
                 disabled={editing}/>
        </div>

        <div className="form-row">
          <label className="form-label">{editing ? 'New Password (leave blank to keep)' : 'Password'}</label>
          <input className="form-input" type="password"
                 placeholder={editing ? '(unchanged)' : 'Set a strong password'}
                 value={password} onChange={e => setPassword(e.target.value)}/>
        </div>

        <div className="form-row">
          <label className="form-label">Role</label>
          <select className="form-input" value={role}
                  onChange={e => setRole(e.target.value)}>
            <option value="admin">Admin</option>
            <option value="analyst">Analyst</option>
            <option value="viewer">Viewer</option>
          </select>
          <span style={{fontSize:11,color:'var(--text3)',marginTop:3}}>
            {ROLE_INFO[role]}
          </span>
        </div>

        {editing && (
          <div className="form-row">
            <label className="form-label">Status</label>
            <label style={{display:'flex',alignItems:'center',gap:8,cursor:'pointer',width:'fit-content'}}>
              <div className="toggle">
                <input type="checkbox" checked={enabled}
                       onChange={e => setEnabled(e.target.checked)}/>
                <div className="toggle-track"/>
                <div className="toggle-thumb"/>
              </div>
              <span style={{fontSize:12,color:'var(--text2)'}}>
                {enabled ? 'Active' : 'Disabled'}
              </span>
            </label>
          </div>
        )}

        {err && <div className="wh-error">{err}</div>}

        <div style={{display:'flex',gap:10,justifyContent:'flex-end',marginTop:20}}>
          <button className="btn" onClick={onCancel} disabled={saving}
                  style={{minWidth:80}}>Cancel</button>
          <button className="btn on" onClick={save} disabled={saving}
                  style={{minWidth:80}}>{saving ? 'Saving…' : editing ? 'Save' : 'Create'}</button>
        </div>
      </div>
    </div>
  );
}

function SettingsView({ currentUser, webhooks, whLoading, setWhLoading, onRefreshWebhooks }) {
  const [tab,      setTab]      = useState('users');  // 'users' | 'webhooks'
  const [triggerNewWh, setTriggerNewWh] = useState(false);
  const [users,    setUsers]    = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editing,  setEditing]  = useState(null);
  const [delId,    setDelId]    = useState(null);

  useEffect(() => {
    fetch('/users').then(r => r.json())
      .then(d => { setUsers(Array.isArray(d) ? d : []); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  function onSaved(user) {
    setUsers(prev => {
      const idx = prev.findIndex(u => u.id === user.id);
      return idx >= 0 ? prev.map(u => u.id === user.id ? user : u) : [...prev, user];
    });
    setShowForm(false); setEditing(null);
  }

  async function deleteUser(uid) {
    await fetch(`/users/${uid}`, { method: 'DELETE' });
    setUsers(prev => prev.filter(u => u.id !== uid));
    setDelId(null);
  }

  const ROLE_COLOR = {
    admin:   'var(--accent)',
    analyst: 'var(--green)',
    viewer:  'var(--text3)',
  };

  const fmtDate = ts => ts
    ? new Date(ts * 1000).toLocaleDateString(undefined, { month:'short', day:'numeric', year:'numeric' })
    : 'Never';

  return (
    <div style={{display:'flex',flexDirection:'column',overflow:'hidden',flex:1}}>
      <div className="pane-head">
        <span className="pane-title">Settings</span>
        <div style={{display:'flex',gap:1,background:'var(--bg2)',
                     border:'1px solid var(--border)',borderRadius:'var(--radius-sm)',
                     padding:2,marginLeft:10}}>
          {[{id:'users',label:'Users'},{id:'webhooks',label:'Webhooks'}].map(t => (
            <button key={t.id} onClick={() => setTab(t.id)} style={{
              padding:'2px 12px',borderRadius:'var(--radius-sm)',border:'none',
              background: tab===t.id ? 'var(--accent)' : 'transparent',
              color:      tab===t.id ? 'white' : 'var(--text3)',
              fontSize:11,fontFamily:'var(--mono)',cursor:'pointer',
              transition:'all .15s',
            }}>{t.label}</button>
          ))}
        </div>
        <div className="pane-actions">
          {tab === 'users' && (
            <button className="btn-add"
                    onClick={() => { setEditing(null); setShowForm(true); }}>
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none"
                   stroke="currentColor" strokeWidth="2">
                <line x1="6" y1="1" x2="6" y2="11"/>
                <line x1="1" y1="6" x2="11" y2="6"/>
              </svg>
              Add user
            </button>
          )}
          {tab === 'webhooks' && (
            <button className="btn-add"
                    onClick={() => { setTab('webhooks'); setTriggerNewWh(t => !t); }}>
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none"
                   stroke="currentColor" strokeWidth="2">
                <line x1="6" y1="1" x2="6" y2="11"/>
                <line x1="1" y1="6" x2="11" y2="6"/>
              </svg>
              Add webhook
            </button>
          )}
        </div>
      </div>

      <div className="wh-panel">
        {tab === 'webhooks' && (
          <WebhooksView
            webhooks={webhooks}
            loading={whLoading}
            setLoading={setWhLoading}
            onRefresh={onRefreshWebhooks}
            embedded={true}
            triggerNew={triggerNewWh}
          />
        )}
        {tab === 'users' && (<>
        <div className="wh-section">
          <div className="wh-section-title">User Accounts</div>

          {loading && (
            <div style={{color:'var(--text3)',fontSize:12,
                         fontFamily:'var(--mono)',padding:'20px 0'}}>Loading…</div>
          )}

          {!loading && users.map(u => (
            <div key={u.id} className="wh-card"
                 style={{opacity: u.enabled ? 1 : 0.55}}>
              <div className="wh-card-header">
                <div style={{
                  width:30,height:30,borderRadius:'50%',
                  background:`${ROLE_COLOR[u.role]}22`,
                  border:`1px solid ${ROLE_COLOR[u.role]}44`,
                  display:'flex',alignItems:'center',justifyContent:'center',
                  fontFamily:'var(--mono)',fontSize:12,fontWeight:600,
                  color:ROLE_COLOR[u.role],flexShrink:0,
                }}>
                  {u.username[0].toUpperCase()}
                </div>
                <div>
                  <div style={{display:'flex',alignItems:'center',gap:8}}>
                    <span className="wh-name">{u.username}</span>
                    {u.username === currentUser && (
                      <span style={{fontSize:9,fontFamily:'var(--mono)',
                                    color:'var(--accent)',letterSpacing:'.06em'}}>YOU</span>
                    )}
                    {!u.enabled && (
                      <span style={{fontSize:9,fontFamily:'var(--mono)',
                                    color:'var(--text3)',letterSpacing:'.06em'}}>DISABLED</span>
                    )}
                  </div>
                  <div style={{fontSize:10,fontFamily:'var(--mono)',
                               color:ROLE_COLOR[u.role],letterSpacing:'.06em',
                               textTransform:'uppercase',marginTop:2}}>
                    {u.role}
                  </div>
                </div>
                <div style={{marginLeft:'auto',fontSize:10,fontFamily:'var(--mono)',
                              color:'var(--text3)',textAlign:'right'}}>
                  <div>Created {fmtDate(u.created_at)}</div>
                  <div>Last login {fmtDate(u.last_login)}</div>
                </div>
              </div>
              <div className="wh-footer">
                <button className="btn-test"
                        onClick={() => { setEditing(u); setShowForm(true); }}>
                  Edit
                </button>
                {u.username !== currentUser && (
                  <button className="btn-danger"
                          onClick={() => setDelId(u.id)}>
                    Delete
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>

        <div className="wh-section">
          <div className="wh-section-title">Role Permissions</div>
          <div style={{fontSize:12,color:'var(--text2)',lineHeight:1.9}}>
            <div style={{display:'grid',gridTemplateColumns:'1fr 60px 70px 60px',
                         gap:'0 12px',fontSize:11}}>
              <div style={{color:'var(--text3)',fontWeight:600,
                           textTransform:'uppercase',letterSpacing:'.08em',fontSize:9,
                           paddingBottom:6,borderBottom:'1px solid var(--border)'}}>
                Permission
              </div>
              {['Admin','Analyst','Viewer'].map(r => (
                <div key={r} style={{color:'var(--text3)',fontWeight:600,
                                     textTransform:'uppercase',letterSpacing:'.08em',
                                     fontSize:9,paddingBottom:6,
                                     borderBottom:'1px solid var(--border)',
                                     textAlign:'center'}}>{r}</div>
              ))}
              {[
                ['View alerts / flows / DNS / charts', true,  true,  true],
                ['Alert detail panel',                 true,  true,  false],
                ['Search & severity filter',           true,  true,  false],
                ['Pause / Resume stream',              true,  true,  false],
                ['Clear alerts / flows',               true,  false, false],
                ['Webhook notifications',              true,  false, false],
                ['User management',                    true,  false, false],
              ].map(([label, a, b, c]) => (
                [
                  <div key={label} style={{color:'var(--text2)',padding:'5px 0',
                                            borderBottom:'1px solid var(--border)'}}>{label}</div>,
                  ...[a,b,c].map((ok,i) => (
                    <div key={i} style={{textAlign:'center',padding:'5px 0',
                                         borderBottom:'1px solid var(--border)',
                                         color: ok ? 'var(--green)' : 'var(--red)',fontSize:13}}>
                      {ok ? '✓' : '✗'}
                    </div>
                  ))
                ]
              ))}
            </div>
          </div>
        </div>
      </>)}
      </div>

      {showForm && (
        <UserForm
          initial={editing}
          onSave={onSaved}
          onCancel={() => { setShowForm(false); setEditing(null); }}
        />
      )}

      {delId !== null && (
        <div className="modal-bg" onClick={() => setDelId(null)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div style={{fontSize:15,fontWeight:500,marginBottom:10}}>Delete user?</div>
            <div style={{fontSize:12,color:'var(--text2)',marginBottom:24,lineHeight:1.7}}>
              This user will be permanently removed and immediately logged out.
            </div>
            <div style={{display:'flex',gap:10,justifyContent:'flex-end'}}>
              <button className="btn" onClick={() => setDelId(null)}
                      style={{minWidth:80}}>Cancel</button>
              <button className="btn-danger" onClick={() => deleteUser(delId)}
                      style={{padding:'4px 14px',borderRadius:'var(--radius-sm)'}}>
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── WebhooksView component ────────────────────────────────────────────────────
const SEV_OPTIONS = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_COLORS_WH = {
  critical: 'var(--red)', high: 'var(--orange)',
  medium: 'var(--yellow)', low: 'var(--green)', info: 'var(--accent)',
};
const TYPE_LABELS = { slack: 'Slack', discord: 'Discord', generic: 'Generic / Other' };

function WebhookForm({ initial, onSave, onCancel }) {
  const blank = { name: '', type: 'generic', url: '', enabled: true,
                  severities: ['critical', 'high', 'medium', 'low', 'info'] };
  const [form, setForm] = useState(initial || blank);
  const [saving, setSaving]   = useState(false);
  const [error,  setError]    = useState('');

  function toggleSev(s) {
    setForm(f => {
      const sevs = f.severities.includes(s)
        ? f.severities.filter(x => x !== s)
        : [...f.severities, s];
      return { ...f, severities: sevs };
    });
  }

  async function handleSave() {
    if (!form.name.trim()) { setError('Name is required.'); return; }
    if (!form.url.trim())  { setError('URL is required.');  return; }
    if (form.severities.length === 0) { setError('Select at least one severity.'); return; }
    setSaving(true); setError('');
    try {
      const method = form.id ? 'PUT' : 'POST';
      const url    = form.id ? `/webhooks/${form.id}` : '/webhooks';
      const r = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      });
      const data = await r.json();
      if (!r.ok) { setError(data.error || 'Save failed.'); return; }
      onSave(data);
    } catch { setError('Network error.'); }
    finally { setSaving(false); }
  }

  const inputStyle = {
    width: '100%', padding: '8px 10px',
    background: 'var(--bg2)', border: '1px solid var(--border2)',
    borderRadius: 'var(--radius-sm)', color: 'var(--text1)',
    fontSize: 12, fontFamily: 'var(--sans)', outline: 'none',
  };
  const labelStyle = {
    display: 'block', fontSize: 10, fontWeight: 600,
    letterSpacing: '.09em', textTransform: 'uppercase',
    color: 'var(--text3)', marginBottom: 5,
  };
  const rowStyle = { marginBottom: 14 };

  return (
    <div style={{
      background: 'var(--bg2)', border: '1px solid var(--border2)',
      borderRadius: 'var(--radius-lg)', padding: 20, marginBottom: 16,
    }}>
      <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 16 }}>
        {form.id ? 'Edit Webhook' : 'New Webhook'}
      </div>

      <div style={rowStyle}>
        <label style={labelStyle}>Name</label>
        <input style={inputStyle} placeholder="e.g. Security Alerts"
          value={form.name} onChange={e => setForm(f => ({...f, name: e.target.value}))}/>
      </div>

      <div style={rowStyle}>
        <label style={labelStyle}>Type</label>
        <select style={{...inputStyle, cursor: 'pointer'}}
          value={form.type} onChange={e => setForm(f => ({...f, type: e.target.value}))}>
          <option value="slack">Slack</option>
          <option value="discord">Discord</option>
          <option value="generic">Generic / Other (Teams, Mattermost, custom…)</option>
        </select>
      </div>

      <div style={rowStyle}>
        <label style={labelStyle}>Webhook URL</label>
        <input style={{...inputStyle, fontFamily: 'var(--mono)', fontSize: 11}}
          placeholder={
            form.type === 'slack'   ? 'https://hooks.slack.com/services/…' :
            form.type === 'discord' ? 'https://discord.com/api/webhooks/…' :
                                     'https://your-endpoint.com/webhook'
          }
          value={form.url} onChange={e => setForm(f => ({...f, url: e.target.value}))}/>
      </div>

      <div style={rowStyle}>
        <label style={labelStyle}>Trigger on Severities</label>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {SEV_OPTIONS.map(s => {
            const on = form.severities.includes(s);
            return (
              <div key={s} onClick={() => toggleSev(s)} style={{
                display: 'flex', alignItems: 'center', gap: 5,
                padding: '4px 10px', borderRadius: 20,
                border: `1px solid ${on ? SEV_COLORS_WH[s] : 'var(--border)'}`,
                background: on ? `${SEV_COLORS_WH[s]}18` : 'transparent',
                color: on ? SEV_COLORS_WH[s] : 'var(--text3)',
                fontSize: 11, fontFamily: 'var(--mono)',
                cursor: 'pointer', userSelect: 'none', transition: 'all .15s',
                textTransform: 'uppercase',
              }}>
                <div style={{
                  width: 6, height: 6, borderRadius: '50%',
                  background: on ? SEV_COLORS_WH[s] : 'var(--text3)',
                }}/>
                {s}
              </div>
            );
          })}
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
        <div onClick={() => setForm(f => ({...f, enabled: !f.enabled}))} style={{
          width: 34, height: 18, borderRadius: 9,
          background: form.enabled ? 'var(--green)' : 'var(--bg3)',
          position: 'relative', cursor: 'pointer', transition: 'background .2s',
          border: '1px solid var(--border2)',
        }}>
          <div style={{
            position: 'absolute', top: 2,
            left: form.enabled ? 17 : 2,
            width: 12, height: 12, borderRadius: '50%',
            background: 'white', transition: 'left .2s',
          }}/>
        </div>
        <span style={{ fontSize: 12, color: 'var(--text2)' }}>
          {form.enabled ? 'Enabled' : 'Disabled'}
        </span>
      </div>

      {error && (
        <div style={{
          marginBottom: 12, padding: '7px 10px', borderRadius: 5,
          background: 'var(--red-d)', border: '1px solid var(--red)',
          color: 'var(--red)', fontSize: 12,
        }}>{error}</div>
      )}

      <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
        <button className="btn" onClick={onCancel} disabled={saving}>Cancel</button>
        <button onClick={handleSave} disabled={saving} style={{
          padding: '4px 14px', borderRadius: 'var(--radius-sm)',
          border: '1px solid var(--accent)', background: 'var(--accent-d)',
          color: 'var(--accent)', fontSize: 11, fontFamily: 'var(--sans)',
          cursor: saving ? 'wait' : 'pointer',
        }}>
          {saving ? 'Saving…' : (form.id ? 'Save Changes' : 'Create Webhook')}
        </button>
      </div>
    </div>
  );
}

function WebhookCard({ wh, onEdit, onDelete, onTest }) {
  const [testing,    setTesting]    = useState(false);
  const [testResult, setTestResult] = useState(null); // null | 'ok' | 'error: ...'
  const [delConfirm, setDelConfirm] = useState(false);

  async function handleTest() {
    setTesting(true); setTestResult(null);
    try {
      const r = await fetch(`/webhooks/${wh.id}/test`, { method: 'POST' });
      const d = await r.json();
      setTestResult(d.ok ? 'ok' : (d.error || 'failed'));
    } catch { setTestResult('Network error'); }
    finally { setTesting(false); }
  }

  const firedAt = wh.last_fired
    ? new Date(wh.last_fired * 1000).toLocaleString('en-GB', {hour12:false})
    : 'Never';

  return (
    <div style={{
      background: 'var(--bg1)', border: '1px solid var(--border)',
      borderRadius: 'var(--radius-lg)', padding: '14px 16px', marginBottom: 10,
      borderLeft: `3px solid ${wh.enabled ? 'var(--green)' : 'var(--border2)'}`,
    }}>
      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
        <div style={{
          padding: '2px 8px', borderRadius: 4,
          background: 'var(--bg3)', border: '1px solid var(--border)',
          fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--text2)',
          textTransform: 'uppercase',
        }}>{wh.type}</div>
        <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text1)' }}>{wh.name}</span>
        <div style={{
          marginLeft: 'auto', padding: '2px 8px', borderRadius: 10, fontSize: 10,
          background: wh.enabled ? 'var(--green-d)' : 'var(--bg3)',
          color: wh.enabled ? 'var(--green)' : 'var(--text3)',
          border: `1px solid ${wh.enabled ? 'var(--green)' : 'var(--border)'}`,
          fontFamily: 'var(--mono)',
        }}>{wh.enabled ? 'ENABLED' : 'DISABLED'}</div>
      </div>

      {/* URL */}
      <div style={{
        fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--text3)',
        background: 'var(--bg2)', padding: '5px 8px', borderRadius: 4,
        marginBottom: 10, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
      }}>{wh.url}</div>

      {/* Severity pills */}
      <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 10 }}>
        {SEV_OPTIONS.map(s => {
          const on = (wh.severities || []).includes(s);
          return (
            <span key={s} style={{
              padding: '1px 7px', borderRadius: 10, fontSize: 10,
              fontFamily: 'var(--mono)', textTransform: 'uppercase',
              background: on ? `${SEV_COLORS_WH[s]}18` : 'transparent',
              color: on ? SEV_COLORS_WH[s] : 'var(--text3)',
              border: `1px solid ${on ? SEV_COLORS_WH[s] : 'var(--border)'}`,
              opacity: on ? 1 : 0.4,
            }}>{s}</span>
          );
        })}
      </div>

      {/* Stats row */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 16,
        fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--text3)',
        marginBottom: 12,
      }}>
        <span>Fired: <b style={{color:'var(--text2)'}}>{wh.fire_count || 0}</b></span>
        <span>Last: <b style={{color:'var(--text2)'}}>{firedAt}</b></span>
        {wh.last_error && (
          <span style={{ color: 'var(--red)', marginLeft: 'auto' }}>
            ⚠ {wh.last_error.slice(0, 60)}
          </span>
        )}
      </div>

      {/* Test result */}
      {testResult && (
        <div style={{
          marginBottom: 10, padding: '6px 10px', borderRadius: 5, fontSize: 11,
          background: testResult === 'ok' ? 'var(--green-d)' : 'var(--red-d)',
          border: `1px solid ${testResult === 'ok' ? 'var(--green)' : 'var(--red)'}`,
          color: testResult === 'ok' ? 'var(--green)' : 'var(--red)',
        }}>
          {testResult === 'ok' ? '✓ Test delivered successfully' : `✗ ${testResult}`}
        </div>
      )}

      {/* Action buttons */}
      <div style={{ display: 'flex', gap: 7 }}>
        <button className="btn" onClick={handleTest} disabled={testing} style={{ fontSize: 11 }}>
          {testing ? 'Sending…' : 'Test'}
        </button>
        <button className="btn" onClick={() => onEdit(wh)} style={{ fontSize: 11 }}>
          Edit
        </button>
        {!delConfirm ? (
          <button className="btn" onClick={() => setDelConfirm(true)}
            style={{ fontSize: 11, marginLeft: 'auto' }}>
            Delete
          </button>
        ) : (
          <div style={{ display: 'flex', gap: 6, marginLeft: 'auto', alignItems: 'center' }}>
            <span style={{ fontSize: 11, color: 'var(--text3)' }}>Confirm?</span>
            <button className="btn" onClick={() => setDelConfirm(false)} style={{ fontSize: 11 }}>
              Cancel
            </button>
            <button onClick={() => onDelete(wh.id)} style={{
              padding: '4px 10px', borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--red)', background: 'var(--red-d)',
              color: 'var(--red)', fontSize: 11, fontFamily: 'var(--sans)', cursor: 'pointer',
            }}>
              Delete
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function WebhooksView({ webhooks, loading, setLoading, onRefresh, embedded = false, triggerNew }) {
  const [showForm, setShowForm]   = useState(false);
  const [editing,  setEditing]    = useState(null); // null = new

  // Open the new-webhook form whenever the parent flips triggerNew.
  // useRef skips the initial mount so arriving on the tab doesn't auto-open.
  const triggerNewMounted = useRef(false);
  useEffect(() => {
    if (!triggerNewMounted.current) { triggerNewMounted.current = true; return; }
    if (triggerNew !== undefined) { setEditing(null); setShowForm(true); }
  }, [triggerNew]);

  async function handleDelete(id) {
    await fetch(`/webhooks/${id}`, { method: 'DELETE' }).catch(() => {});
    onRefresh();
  }

  function handleEdit(wh) {
    setEditing(wh);
    setShowForm(true);
  }

  function handleNew() {
    setEditing(null);
    setShowForm(true);
  }

  function handleSaved() {
    setShowForm(false);
    setEditing(null);
    onRefresh();
  }

  return (
    <div style={{
      flex: 1, display: 'flex', flexDirection: 'column',
      overflow: 'hidden', background: 'var(--bg0)',
    }}>
      {/* Header */}
      <div className="pane-head">
        <span className="pane-title">Webhook Notifications</span>
        <span className="pane-cnt">{webhooks.length} configured</span>
      </div>

      {/* Scrollable content */}
      <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>

        {/* Guidance box */}
        <div style={{
          background: 'var(--accent-d)', border: '1px solid rgba(79,156,249,.2)',
          borderRadius: 'var(--radius-md)', padding: '10px 14px',
          fontSize: 12, color: 'var(--text2)', marginBottom: 20, lineHeight: 1.7,
        }}>
          <b style={{color:'var(--accent)'}}>Webhooks</b> send a POST request to your URL whenever
          a matching alert fires. Choose <b style={{color:'var(--text1)'}}>Slack</b> or{' '}
          <b style={{color:'var(--text1)'}}>Discord</b> for formatted messages, or{' '}
          <b style={{color:'var(--text1)'}}>Generic</b> for a plain JSON payload compatible
          with Teams, Mattermost, or any custom endpoint.
          Use the <b style={{color:'var(--text1)'}}>severity filter</b> to only send the alerts
          that matter.
        </div>

        {/* Add / Edit form */}
        {showForm && (
          <WebhookForm
            initial={editing}
            onSave={handleSaved}
            onCancel={() => { setShowForm(false); setEditing(null); }}
          />
        )}

        {/* Webhook cards */}
        {webhooks.length === 0 && !showForm && (
          <div className="empty" style={{ height: 200 }}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
              <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
              <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
            </svg>
            <div>No webhooks configured</div>
            <div style={{fontSize:11}}>Click "+ Add Webhook" above to get started</div>
          </div>
        )}
        {webhooks.map(wh => (
          <WebhookCard
            key={wh.id}
            wh={wh}
            onEdit={handleEdit}
            onDelete={handleDelete}
            onTest={() => {}}
          />
        ))}
      </div>
    </div>
  );
}

// ── App ───────────────────────────────────────────────────────────────────────
function App() {
  // ── State ──────────────────────────────────────────────────────────────────
  const [alerts,       setAlerts]       = useState([]);
  const [selected,     setSelected]     = useState(null);
  const [paused,       setPaused]       = useState(false);
  const [search,       setSearch]       = useState('');
  const [activeSev,    setActiveSev]    = useState(
    new Set(['critical', 'high', 'medium', 'low', 'info'])
  );
  const [connState,    setConnState]    = useState('connecting');
  const [sparkData,    setSparkData]    = useState(new Array(30).fill(0));
  const [rate,         setRate]         = useState(0);
  const [historyCount, setHistoryCount] = useState(0);
  const [showConfirm,  setShowConfirm]  = useState(false);
  const [clearing,     setClearing]     = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleting,     setDeleting]     = useState(false);
  const [theme,        setTheme]        = useState(
    () => localStorage.getItem('watcher-theme') || 'night'
  );
  const [activeView,   setActiveView]   = useState('alerts'); // 'alerts' | 'flows' | 'dns' | 'charts' | 'settings'
  const [webhooks,     setWebhooks]     = useState([]);
  const [whLoading,    setWhLoading]    = useState(false);
  const [flows,        setFlows]        = useState([]);
  const [dnsEvents,    setDnsEvents]    = useState([]);
  const [flowSel,      setFlowSel]      = useState(null);
  const [dnsSel,       setDnsSel]       = useState(null);
  const [evtLoading,   setEvtLoading]   = useState(false);
  const [currentUser,  setCurrentUser]  = useState('');
  const [role,         setRole]         = useState('admin');
  // ── Bulk select ──
  const [selectedIds,  setSelectedIds]  = useState(new Set());
  const [bulkStatus,   setBulkStatus]   = useState('acknowledged');
  const [bulkNote,     setBulkNote]     = useState('');
  const [bulkSaving,   setBulkSaving]   = useState(false);

  const pausedRef   = useRef(false);
  const accumRef    = useRef(0);
  const sparkIdxRef = useRef(0);
  const newIdsRef   = useRef(new Set());

  // ── Theme ──────────────────────────────────────────────────────────────────
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('watcher-theme', theme);
  }, [theme]);

  // ── Fetch webhooks ────────────────────────────────────────────────────────────
  const fetchWebhooks = useCallback(() => {
    fetch('/webhooks')
      .then(r => r.json())
      .then(data => { if (Array.isArray(data)) setWebhooks(data); })
      .catch(() => {});
  }, []);
  useEffect(() => { fetchWebhooks(); }, []);

  // ── Fetch current user + role ─────────────────────────────────────────────
  useEffect(() => {
    fetch('/me').then(r => r.json()).then(d => {
      setCurrentUser(d.username || '');
      setRole(d.role || 'admin');
    }).catch(() => {});
  }, []);

  // ── Load history ───────────────────────────────────────────────────────────
  useEffect(() => {
    fetch('/alerts?limit=5000')
      .then(r => {
        if (r.status === 401) { window.location.href = '/login'; throw new Error(); }
        return r.json();
      })
      .then(rows => {
        if (!Array.isArray(rows)) return;
        const loaded = rows.map(r => ({ ...r, tsStr: fmtTime(r.ts) }));
        setAlerts(loaded);
        setHistoryCount(loaded.length);
      })
      .catch(() => {});
  }, []);

  // ── Load flow/dns history on first view ────────────────────────────────
  useEffect(() => {
    if (activeView === 'flows' && flows.length === 0) {
      setEvtLoading(true);
      fetch('/flows?limit=5000').then(r=>r.json()).then(d=>{
        if(Array.isArray(d)) setFlows(d.map(r=>({...r,tsStr:fmtTime(r.ts)})));
        setEvtLoading(false);
      }).catch(()=>setEvtLoading(false));
    }
    if (activeView === 'dns' && dnsEvents.length === 0) {
      setEvtLoading(true);
      fetch('/dns?limit=5000').then(r=>r.json()).then(d=>{
        if(Array.isArray(d)) setDnsEvents(d.map(r=>({...r,tsStr:fmtTime(r.ts)})));
        setEvtLoading(false);
      }).catch(()=>setEvtLoading(false));
    }
  }, [activeView]);

  // ── SSE connection ─────────────────────────────────────────────────────────
  useEffect(() => {
    let es;
    let retryTimer;

    function connect() {
      setConnState('connecting');
      es = new EventSource(SSE_URL);

      es.addEventListener('ping', () => setConnState('live'));

      es.addEventListener('alert', e => {
        setConnState('live');
        if (pausedRef.current) return;
        try {
          const evt = JSON.parse(e.data);
          evt.tsStr = fmtTime(evt.ts);
          accumRef.current++;
          newIdsRef.current.add(evt.id);
          setTimeout(() => newIdsRef.current.delete(evt.id), 400);
          setAlerts(prev => {
            if (prev.length > 0 && prev[0].id === evt.id) return prev; // duplicate guard (fast path)
            if (prev.some(x => x.id === evt.id)) return prev;
            const next = [evt, ...prev];
            return next.length > MAX_ALERTS ? next.slice(0, MAX_ALERTS) : next;
          });
        } catch {}
      });

      es.addEventListener('flow', e => {
        try {
          const evt = JSON.parse(e.data);
          evt.tsStr = fmtTime(evt.ts);
          setFlows(prev => {
            if (prev.length > 0 && prev[0].flow_id === evt.flow_id) return prev;
            if (prev.some(x => x.flow_id === evt.flow_id)) return prev;
            const next = [evt, ...prev];
            return next.length > MAX_ALERTS ? next.slice(0, MAX_ALERTS) : next;
          });
        } catch {}
      });

      es.addEventListener('dns', e => {
        try {
          const evt = JSON.parse(e.data);
          evt.tsStr = fmtTime(evt.ts);
          setDnsEvents(prev => {
            const next = [evt, ...prev];
            return next.length > MAX_ALERTS ? next.slice(0, MAX_ALERTS) : next;
          });
        } catch {}
      });

      es.onerror = () => {
        es.close();
        fetch('/health')
          .then(r => {
            if (r.status === 401) {
              window.location.href = '/login';
            } else {
              setConnState('reconnecting');
              retryTimer = setTimeout(connect, 3000);
            }
          })
          .catch(() => {
            setConnState('reconnecting');
            retryTimer = setTimeout(connect, 3000);
          });
      };
    }

    connect();
    return () => { es && es.close(); clearTimeout(retryTimer); };
  }, []);

  // ── Pause ref sync ─────────────────────────────────────────────────────────
  useEffect(() => { pausedRef.current = paused; }, [paused]);

  // ── Sparkline ticker (1 s) ─────────────────────────────────────────────────
  useEffect(() => {
    const id = setInterval(() => {
      const n = accumRef.current;
      accumRef.current = 0;
      setRate(n);
      setSparkData(prev => {
        const next = [...prev];
        next[sparkIdxRef.current % 30] = n;
        sparkIdxRef.current++;
        return next;
      });
    }, 1000);
    return () => clearInterval(id);
  }, []);

  // ── Acknowledgement handler ──────────────────────────────────────────────────
  function handleAck(alertId, status, note) {
    setAlerts(prev => prev.map(a =>
      a.id === alertId ? { ...a, ack_status: status, ack_note: note } : a
    ));
    if (selected?.id === alertId) {
      setSelected(s => s ? { ...s, ack_status: status, ack_note: note } : s);
    }
  }

  async function handleBulkAck() {
    if (selectedIds.size === 0) return;
    setBulkSaving(true);
    try {
      const r = await fetch('/alerts/bulk-ack', {
        method:  'POST',
        headers: {'Content-Type':'application/json'},
        body:    JSON.stringify({ ids: [...selectedIds], status: bulkStatus, note: bulkNote }),
      });
      if (r.ok) {
        const ids = new Set(selectedIds);
        setAlerts(prev => prev.map(a =>
          ids.has(a.id) ? { ...a, ack_status: bulkStatus, ack_note: bulkNote } : a
        ));
        setSelectedIds(new Set());
        setBulkNote('');
      }
    } catch {}
    setBulkSaving(false);
  }

  function toggleSelectId(id) {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  function toggleSelectAll() {
    const visible = filtered.slice(0, 300).map(a => a.id);
    const allOn   = visible.every(id => selectedIds.has(id));
    if (allOn) { setSelectedIds(new Set()); }
    else        { setSelectedIds(new Set(visible)); }
  }

  // ── Clear handlers ──────────────────────────────────────────────────────────
  async function handleClearAlerts() {
    setClearing(true);
    try { await fetch('/alerts', { method: 'DELETE' }); } catch {}
    setAlerts([]);
    setSelected(null);
    setHistoryCount(0);
    setClearing(false);
    setShowConfirm(false);
  }

  async function handleDeleteSelected() {
    setDeleting(true);
    const ids = [...selectedIds];
    try {
      await fetch('/alerts/delete-selected', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ ids }),
      });
      setAlerts(prev => prev.filter(a => !selectedIds.has(a.id)));
      if (selected && selectedIds.has(selected.id)) setSelected(null);
      setSelectedIds(new Set());
    } catch {}
    setDeleting(false);
    setShowDeleteConfirm(false);
  }

  const handleClearFlows = async () => {
    try {
      await fetch('/flows', { method: 'DELETE' });
      setFlows([]);
      setFlowSel(null);
    } catch (e) {
      alert('Failed to clear flows');
    }
  };

  // ── DNS clear handler — calls DELETE /dns on the server ────────────────────
  const handleClearDns = async () => {
    try {
      await fetch('/dns', { method: 'DELETE' });
      setDnsEvents([]);
      setDnsSel(null);
    } catch {
      alert('Failed to clear DNS events');
    }
  };

  // ── Derived state — memoized so they only recompute when alerts changes ───
  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    alerts.forEach(a => { c[a.severity] = (c[a.severity] || 0) + 1; });
    return c;
  }, [alerts]);

  const uniqueSrcs = useMemo(
    () => new Set(alerts.map(a => a.src_ip)).size,
    [alerts]
  );

  const topCat = useMemo(() => {
    const cc = {};
    alerts.forEach(a => { cc[a.category] = (cc[a.category] || 0) + 1; });
    let top = '—', mx = 0;
    for (const [k, v] of Object.entries(cc)) { if (v > mx) { mx = v; top = k; } }
    return { name: top, count: mx };
  }, [alerts]);

  const topSrcs = useMemo(() => {
    const cc = {};
    alerts.forEach(a => { cc[a.src_ip] = (cc[a.src_ip] || 0) + 1; });
    return Object.entries(cc).sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [alerts]);

  const q = search.toLowerCase();
  const filtered = useMemo(() =>
    alerts.filter(a =>
      activeSev.has(a.severity) && (
        !q ||
        a.sig_msg?.toLowerCase().includes(q) ||
        a.src_ip?.includes(q) ||
        a.dst_ip?.includes(q) ||
        String(a.sig_id).includes(q) ||
        a.category?.toLowerCase().includes(q)
      )
    ),
    [alerts, activeSev, q]
  );

  function toggleSev(s) {
    setActiveSev(prev => {
      const next = new Set(prev);
      if (next.has(s)) { if (next.size > 1) next.delete(s); }
      else next.add(s);
      return next;
    });
  }

  const connColor = {
    live: 'var(--green)', connecting: 'var(--yellow)', reconnecting: 'var(--text3)',
  }[connState];
  const connLabel = {
    live: 'LIVE', connecting: 'CONNECTING…', reconnecting: 'RECONNECTING…',
  }[connState];

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div className="shell">

      {/* ── Topbar ── */}
      <header className="topbar">
        <div className="logo">
          <div className="logo-box">
            <svg className="logo-eye" viewBox="0 0 24 24" fill="none">
              <ellipse cx="12" cy="12" rx="10" ry="7"
                       stroke="white" strokeWidth="1.8" strokeOpacity=".9"/>
              <circle  cx="12" cy="12" r="3"
                       fill="white" fillOpacity=".9"/>
              <circle  cx="12" cy="12" r="1.2"
                       fill="white" fillOpacity=".4"/>
            </svg>
          </div>
          WATCHER
        </div>
        <div className="sep"/>
        <div className="badge">
          <div className="dot" style={{ background: connColor }}/>
          <span style={{
            color: connColor,
            fontFamily: 'var(--mono)',
            fontSize: 11,
            letterSpacing: '.06em',
          }}>{connLabel}</span>
        </div>
        <div className="sep"/>
        <div className="pill">Interface: <b style={{ marginLeft: 4 }}>eth0</b></div>
        <div className="pill">Engine:
          <b style={{ marginLeft: 4, color: 'var(--green)' }}>Running</b>
        </div>
        {role !== 'admin' && (
          <div className="pill" style={{borderColor:'var(--yellow)',background:'var(--yellow-d)'}}>
            <span style={{color:'var(--yellow)',fontWeight:500,letterSpacing:'.04em'}}>
              {role.toUpperCase()}
            </span>
          </div>
        )}
        <div className="right">
          <div className="pill">Alerts/s: <b style={{ marginLeft: 4 }}>{rate}</b></div>
          <Clock/>
          <ThemePicker theme={theme} onChange={setTheme}/>
          <a href="/logout" className="signout">SIGN OUT</a>
        </div>
      </header>

      {/* ── Sidebar ── */}
      <aside className="sidebar">
        <div className="s-label">Views</div>
        <div className={`nav-item${activeView === 'alerts' ? ' active' : ''}`}
             onClick={() => setActiveView('alerts')}>
          <svg width="14" height="14" viewBox="0 0 16 16"
               fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M8 2L14 13H2L8 2Z"/>
            <line x1="8" y1="7" x2="8" y2="10"/>
            <circle cx="8" cy="12" r=".5" fill="currentColor"/>
          </svg>
          Alerts
          <span className="nav-badge">
            {alerts.length > 999 ? '999+' : alerts.length}
          </span>
        </div>
        <div className={`nav-item${activeView === 'flows' ? ' active' : ''}`}
             style={activeView==='flows'?{background:'var(--teal-d)',color:'var(--teal)',borderColor:'rgba(45,212,191,.2)'}:{}}
             onClick={() => setActiveView('flows')}>
          <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M2 4h12M2 8h8M2 12h10"/>
          </svg>
          Flow Events
          <span style={{marginLeft:'auto',fontFamily:'var(--mono)',fontSize:10,
                        padding:'1px 6px',borderRadius:10,
                        background:'var(--teal-d)',color:'var(--teal)'}}>
            {flows.length > 999 ? '999+' : flows.length}
          </span>
        </div>

        <div className={`nav-item${activeView === 'dns' ? ' active' : ''}`}
             style={activeView==='dns'?{background:'rgba(159,122,234,.14)',color:'var(--purple)',borderColor:'rgba(159,122,234,.2)'}:{}}
             onClick={() => setActiveView('dns')}>
          <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
            <circle cx="8" cy="8" r="6"/><path d="M2 8h12M8 2a9 9 0 010 12"/>
          </svg>
          DNS Queries
          <span style={{marginLeft:'auto',fontFamily:'var(--mono)',fontSize:10,
                        padding:'1px 6px',borderRadius:10,
                        background:'rgba(159,122,234,.14)',color:'var(--purple)'}}>
            {dnsEvents.length > 999 ? '999+' : dnsEvents.length}
          </span>
        </div>

        <div className={`nav-item${activeView === 'charts' ? ' active' : ''}`}
             style={activeView==='charts'?{background:'rgba(245,148,74,.13)',color:'var(--orange)',borderColor:'rgba(245,148,74,.2)'}:{}}
             onClick={() => setActiveView('charts')}>
          <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
            <rect x="2" y="10" width="3" height="4" rx=".5"/>
            <rect x="6" y="6"  width="3" height="8" rx=".5"/>
            <rect x="10" y="2" width="3" height="12" rx=".5"/>
          </svg>
          Charts
        </div>



        {role === 'admin' && (
          <div className={`nav-item${activeView === 'settings' ? ' active' : ''}`}
               onClick={() => setActiveView('settings')}>
            <svg width="14" height="14" viewBox="0 0 16 16" fill="none"
                 stroke="currentColor" strokeWidth="1.5">
              <circle cx="8" cy="8" r="2.5"/>
              <path d="M8 1v2M8 13v2M1 8h2M13 8h2M3.05 3.05l1.41 1.41M11.54 11.54l1.41 1.41M3.05 12.95l1.41-1.41M11.54 4.46l1.41-1.41"/>
            </svg>
            Settings
          </div>
        )}

        {activeView === 'alerts' && <div className="divider"/>}

        {activeView === 'alerts' && <div className="s-label">Severity</div>}
        {activeView === 'alerts' && ['critical', 'high', 'medium', 'low', 'info'].map(s => (
          <div key={s}
               className={`sev-row${activeSev.has(s) ? ' on' : ''}`}
               onClick={() => toggleSev(s)}>
            <div className="sev-dot" style={{ background: SEV_COLORS[s] }}/>
            {s.charAt(0).toUpperCase() + s.slice(1)}
            <span className="sev-cnt">{counts[s]}</span>
          </div>
        ))}

        {activeView === 'alerts' && <div className="divider"/>}

        {activeView === 'alerts' && <div className="s-label">Top Sources</div>}
        {activeView === 'alerts' && topSrcs.length === 0 && (
          <div style={{
            padding: '4px 18px', fontSize: 11,
            color: 'var(--text3)', fontFamily: 'var(--mono)',
          }}>no data yet</div>
        )}
        {activeView === 'alerts' && topSrcs.length > 0 && (
          <div style={{padding:'0 12px'}}>
            {topSrcs.map(([ip, cnt]) => {
              const maxCount = topSrcs[0][1];
              const percent = (cnt / maxCount) * 100;
              const isActive = search === ip;
              return (
                <div key={ip}
                  onClick={() => setSearch(isActive ? '' : ip)}
                  title={isActive ? 'Click to clear filter' : ('Click to filter: ' + ip)}
                  style={{
                    marginBottom:8, cursor:'pointer',
                    padding:'4px 6px', margin:'0 -6px 8px',
                    borderRadius:'var(--radius-sm)',
                    background: isActive ? 'var(--accent-d)' : 'transparent',
                    border: isActive ? '1px solid rgba(79,156,249,.25)' : '1px solid transparent',
                    transition:'background .12s, border-color .12s',
                  }}>
                  <div style={{display:'flex',justifyContent:'space-between',fontSize:11,marginBottom:3}}>
                    <span className="src-ip" style={{
                      overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',maxWidth:100,
                      color: isActive ? 'var(--accent)' : '',
                      fontWeight: isActive ? 500 : 'normal',
                    }}>{ip}</span>
                    <span className="src-cnt" style={{color: isActive ? 'var(--accent)' : ''}}>{cnt}</span>
                  </div>
                  <div style={{height:4,background:'var(--bg3)',borderRadius:2,overflow:'hidden'}}>
                    <div style={{width:(percent + '%'),height:'100%',borderRadius:2,
                      background: isActive ? 'var(--accent)' : 'var(--accent)',
                      opacity: isActive ? 1 : 0.5,
                      transition:'opacity .12s',
                    }}/>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </aside>

      {/* ── Main ── */}
      <main className="main" style={{display: activeView === 'alerts' ? '' : 'none'}}>

        {/* Metrics — 5 columns only */}
        <div className="metrics" style={{gridTemplateColumns: 'repeat(5,1fr)'}}>
          <div className="metric">
            <div className="metric-label">Total Alerts</div>
            <div className="metric-val">{alerts.length.toLocaleString()}</div>
          </div>
          <div className="metric">
            <div className="metric-label">Critical</div>
            <div className="metric-val" style={{color:'var(--red)'}}>{counts.critical}</div>
          </div>
          <div className="metric">
            <div className="metric-label">High</div>
            <div className="metric-val" style={{color:'var(--orange)'}}>{counts.high}</div>
          </div>
          <div className="metric">
            <div className="metric-label">Medium</div>
            <div className="metric-val" style={{color:'var(--yellow)'}}>{counts.medium}</div>
          </div>
          <div className="metric">
            <div className="metric-label">Unique Sources</div>
            <div className="metric-val">{uniqueSrcs}</div>
          </div>
        </div>

        {/* Content area */}
        <div className="content">

          {/* Alert table */}
          <div style={{
            display: 'flex', flexDirection: 'column',
            overflow: 'hidden', borderRight: '1px solid var(--border)',
          }}>
            <div className="pane-head">
              <span className="pane-title">Alert Stream</span>
              <span className="pane-cnt">{filtered.length.toLocaleString()}</span>
              {historyCount > 0 && (
                <span style={{
                  fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--text3)',
                  background: 'var(--bg2)', border: '1px solid var(--border)',
                  padding: '1px 7px', borderRadius: 10,
                }}>
                  {historyCount.toLocaleString()} stored
                </span>
              )}
              <div className="pane-actions">
                <div className="search">
                  <svg width="12" height="12" viewBox="0 0 16 16"
                       fill="none" stroke="currentColor" strokeWidth="1.5">
                    <circle cx="7" cy="7" r="4"/>
                    <path d="M10 10l3 3"/>
                  </svg>
                  <input placeholder="Search alerts…"
                         value={search}
                         onChange={e => setSearch(e.target.value)}/>
                </div>
                {(role === 'admin' || role === 'analyst') && (
                  <button className={`btn${paused ? '' : ' on'}`}
                          onClick={() => setPaused(p => !p)}>
                    {paused ? 'Resume' : 'Pause'}
                  </button>
                )}
                {role === 'admin' && (
                  <button className="btn"
                          onClick={() => setShowConfirm(true)}>
                    Clear
                  </button>
                )}
              </div>
            </div>

            <div className="tscroll">
              {/* ── Bulk action bar — shown when at least one row is checked ── */}
              {selectedIds.size > 0 && (role === 'admin' || role === 'analyst') && (
                <div style={{
                  display:'flex', alignItems:'center', gap:8, flexWrap:'wrap',
                  padding:'7px 12px', background:'var(--accent-d)',
                  borderBottom:'1px solid rgba(79,156,249,.2)', fontSize:12, flexShrink:0,
                }}>
                  <span style={{fontFamily:'var(--mono)', color:'var(--accent)', fontWeight:500, whiteSpace:'nowrap'}}>
                    {selectedIds.size} selected
                  </span>
                  <select value={bulkStatus} onChange={e => setBulkStatus(e.target.value)}
                    style={{padding:'3px 7px', borderRadius:'var(--radius-sm)',
                            border:'1px solid var(--border2)', background:'var(--bg2)',
                            color:'var(--text1)', fontSize:11, fontFamily:'var(--mono)',
                            cursor:'pointer', outline:'none'}}>
                    <option value="new">New</option>
                    <option value="investigating">Investigating</option>
                    <option value="acknowledged">Acknowledged</option>
                    <option value="false_positive">False Positive</option>
                  </select>
                  <input value={bulkNote} onChange={e => setBulkNote(e.target.value)}
                    placeholder="Optional note for all…"
                    style={{flex:1, minWidth:100, padding:'3px 8px',
                            borderRadius:'var(--radius-sm)', border:'1px solid var(--border2)',
                            background:'var(--bg2)', color:'var(--text1)',
                            fontSize:11, fontFamily:'var(--sans)', outline:'none'}}/>
                  <button onClick={handleBulkAck} disabled={bulkSaving} style={{
                    padding:'3px 12px', borderRadius:'var(--radius-sm)',
                    border:'1px solid var(--accent)', background:'var(--accent)',
                    color:'white', fontSize:11, fontFamily:'var(--sans)',
                    cursor: bulkSaving ? 'wait' : 'pointer', whiteSpace:'nowrap',
                  }}>{bulkSaving ? 'Saving…' : 'Apply to all'}</button>
                  {role === 'admin' && (
                    <button onClick={() => setShowDeleteConfirm(true)} style={{
                      padding:'3px 12px', borderRadius:'var(--radius-sm)',
                      border:'1px solid var(--red)', background:'var(--red-d)',
                      color:'var(--red)', fontSize:11, fontFamily:'var(--sans)',
                      cursor:'pointer', whiteSpace:'nowrap',
                    }}>Delete</button>
                  )}
                  <button onClick={() => setSelectedIds(new Set())} style={{
                    padding:'3px 9px', borderRadius:'var(--radius-sm)',
                    border:'1px solid var(--border2)', background:'transparent',
                    color:'var(--text3)', fontSize:11, fontFamily:'var(--sans)', cursor:'pointer',
                  }}>✕</button>
                </div>
              )}
              {filtered.length === 0 ? (
                <div className="empty">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
                    <rect x="3" y="3" width="18" height="18" rx="2"/>
                    <line x1="3" y1="9"  x2="21" y2="9"/>
                    <line x1="9" y1="21" x2="9"  y2="9"/>
                  </svg>
                  <div>
                    {connState === 'live'
                      ? 'No alerts match current filters'
                      : 'Connecting…'}
                  </div>
                </div>
              ) : (
                <table>
                  <thead>
                    <tr>
                      {(role === 'admin' || role === 'analyst') && (
                        <th style={{width:32, textAlign:'center', paddingLeft:8}}>
                           <input type="checkbox" className="hm-check"
                            checked={filtered.slice(0,300).length > 0 &&
                                     filtered.slice(0,300).every(a => selectedIds.has(a.id))}
                            onChange={toggleSelectAll}/>
                        </th>
                      )}
                      <th style={{ width: 148 }}>Time</th>
                      <th style={{ width: 82  }}>Severity</th>
                      <th style={{ width: 110 }}>Status</th>
                      <th style={{ width: 72  }}>Protocol</th>
                      <th>Signature</th>
                      <th style={{ width: 115 }}>Source</th>
                      <th style={{ width: 115 }}>Destination</th>
                      <th style={{ width: 80  }}>SID</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.slice(0, 300).map((a, i) => {
                      const isSel = selectedIds.has(a.id);
                      return (
                        <tr key={a.id || i}
                            className={[
                              'arow',
                              selected?.id === a.id       ? 'sel' : '',
                              newIdsRef.current.has(a.id) ? 'new' : '',
                            ].filter(Boolean).join(' ')}
                            style={isSel ? {background:'var(--accent-d)'} : {}}
                            onClick={() => setSelected(a)}>
                          {(role === 'admin' || role === 'analyst') && (
                            <td style={{textAlign:'center', width:32, paddingLeft:8}}
                                onClick={e => e.stopPropagation()}>
                               <input type="checkbox" className="hm-check"
                                checked={isSel}
                                onChange={() => toggleSelectId(a.id)}/>
                            </td>
                          )}
                          <td className="mono-dim" style={{width:148, whiteSpace:'nowrap'}}>{a.tsStr || fmtTime(a.ts)}</td>
                          <td>
                            <span className={`sbadge ${a.severity}`}>
                              {a.severity}
                            </span>
                          </td>
                          <td style={{width:110}}>
                            <AckBadge status={a.ack_status||'new'}/>
                          </td>
                          <td><span className="proto">{a.proto}</span></td>
                          <td style={{ fontSize: 12, color: 'var(--text1)' }}>
                            {a.sig_msg}
                          </td>
                          <td className="mono">{a.src_ip}:{a.src_port}</td>
                          <td className="mono">{a.dst_ip}:{a.dst_port}</td>
                          <td className="mono-dim" style={{width:80, whiteSpace:'nowrap'}}>{a.sig_id}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          {/* Detail + sparkline + timeline */}
          <div className="detail">
            <div className="pane-head">
              <span className="pane-title">Event Detail</span>
            </div>
            {role === 'viewer'
              ? <div className="dscroll"><div className="empty" style={{height:'100%'}}>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                  <div>Viewer access</div>
                  <div style={{fontSize:10}}>Detail panel not available</div>
                </div></div>
              : <Detail alert={selected} onAck={handleAck} role={role}/>}
            <Sparkline data={sparkData}/>
            <Timeline alerts={alerts}/>
          </div>
        </div>
      </main>

      {/* ── Flow Events view ── */}
      {activeView === 'flows' && (
        <main className="main">
          <div className="content" style={{gridTemplateColumns:'1fr 310px'}}>
            <FlowsView rows={flows} loading={evtLoading} selected={flowSel} onSelect={setFlowSel} onClear={handleClearFlows}/>
            <div className="detail">
              <div className="pane-head"><span className="pane-title">Flow Detail</span></div>
              <FlowDetail item={flowSel}/>
            </div>
          </div>
        </main>
      )}

      {/* ── DNS view ── */}
      {activeView === 'dns' && (
        <main className="main">
          <div className="content" style={{gridTemplateColumns:'1fr 310px'}}>
            <DNSView rows={dnsEvents} loading={evtLoading} selected={dnsSel} onSelect={setDnsSel} onClear={handleClearDns}/>
            <div className="detail">
              <div className="pane-head"><span className="pane-title">DNS Detail</span></div>
              <DNSDetail item={dnsSel}/>
            </div>
          </div>
        </main>
      )}

      {/* ── Charts view ── */}
      {activeView === 'charts' && <ChartsView/>}

      {/* ── Settings view ── */}
      {activeView === 'settings' && role === 'admin' && (
        <SettingsView
          currentUser={currentUser}
          webhooks={webhooks}
          whLoading={whLoading}
          setWhLoading={setWhLoading}
          onRefreshWebhooks={fetchWebhooks}
        />
      )}

      {/* Confirm delete selected alerts modal */}
      {showDeleteConfirm && (
        <div className="modal-bg" onClick={() => setShowDeleteConfirm(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div style={{ fontSize: 15, fontWeight: 500, marginBottom: 10 }}>
              Delete {selectedIds.size} selected alert{selectedIds.size !== 1 ? 's' : ''}?
            </div>
            <div style={{
              fontSize: 12, color: 'var(--text2)',
              lineHeight: 1.7, marginBottom: 24,
            }}>
              This will permanently remove{' '}
              <b style={{ color: 'var(--text1)' }}>
                {selectedIds.size} alert{selectedIds.size !== 1 ? 's' : ''}
              </b>{' '}
              and their acknowledgement history. This action cannot be undone.
            </div>
            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button className="btn"
                      onClick={() => setShowDeleteConfirm(false)}
                      disabled={deleting}
                      style={{ minWidth: 80 }}>
                Cancel
              </button>
              <button onClick={handleDeleteSelected}
                      disabled={deleting}
                      style={{
                        minWidth: 80, padding: '4px 14px',
                        borderRadius: 'var(--radius-sm)',
                        border: '1px solid var(--red)',
                        background: 'var(--red-d)',
                        color: 'var(--red)', fontSize: 11,
                        fontFamily: 'var(--sans)',
                        cursor: deleting ? 'wait' : 'pointer',
                        transition: 'all .15s',
                      }}>
                {deleting ? 'Deleting…' : `Yes, delete ${selectedIds.size}`}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Confirm clear alerts modal */}
      {showConfirm && (
        <div className="modal-bg" onClick={() => setShowConfirm(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div style={{ fontSize: 15, fontWeight: 500, marginBottom: 10 }}>
              Clear all alerts?
            </div>
            <div style={{
              fontSize: 12, color: 'var(--text2)',
              lineHeight: 1.7, marginBottom: 24,
            }}>
              This will permanently delete{' '}
              <b style={{ color: 'var(--text1)' }}>
                {(historyCount || alerts.length).toLocaleString()} stored alerts
              </b>{' '}
              from the database. This action cannot be undone.
            </div>
            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button className="btn"
                      onClick={() => setShowConfirm(false)}
                      disabled={clearing}
                      style={{ minWidth: 80 }}>
                Cancel
              </button>
              <button onClick={handleClearAlerts}
                      disabled={clearing}
                      style={{
                        minWidth: 80, padding: '4px 14px',
                        borderRadius: 'var(--radius-sm)',
                        border: '1px solid var(--red)',
                        background: 'var(--red-d)',
                        color: 'var(--red)', fontSize: 11,
                        fontFamily: 'var(--sans)',
                        cursor: clearing ? 'wait' : 'pointer',
                        transition: 'all .15s',
                      }}>
                {clearing ? 'Clearing…' : 'Yes, delete all'}
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}

// ── Mount ─────────────────────────────────────────────────────────────────────
ReactDOM.createRoot(document.getElementById('root')).render(<App/>);