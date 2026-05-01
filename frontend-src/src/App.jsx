import { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { ThemePicker } from './themes.jsx';
import { Clock, Sparkline, Timeline, AckBadge } from './components.jsx';
import { Detail } from './Detail.jsx';
import { FlowsView, FlowDetail, DNSView, DNSDetail } from './FlowsDns.jsx';
import { ChartsView } from './Charts.jsx';
import { SettingsView } from './Settings.jsx';
import { fmtTime, MAX_ALERTS, SSE_URL, SEV_COLORS } from './utils.js';
import { ExplainDialog } from './ThreatIntel.jsx';

export default function App() {
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
  const [activeView,   setActiveView]   = useState('alerts');
  const [webhooks,     setWebhooks]     = useState([]);
  const [flows,        setFlows]        = useState([]);
  const [dnsEvents,    setDnsEvents]    = useState([]);
  const [flowSel,      setFlowSel]      = useState(null);
  const [dnsSel,       setDnsSel]       = useState(null);
  const [evtLoading,   setEvtLoading]   = useState(false);
  const [currentUser,  setCurrentUser]  = useState('');
  const [role,         setRole]         = useState('admin');
  const [selectedIds,  setSelectedIds]  = useState(new Set());
  const [bulkStatus,   setBulkStatus]   = useState('acknowledged');
  const [bulkNote,     setBulkNote]     = useState('');
  const [bulkSaving,   setBulkSaving]   = useState(false);
  const [showExplain,  setShowExplain]  = useState(false);

  const pausedRef   = useRef(false);
  const accumRef    = useRef(0);
  const sparkIdxRef = useRef(0);
  const newIdsRef   = useRef(new Set());

  // ── Theme ──────────────────────────────────────────────────────────────────
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('watcher-theme', theme);
  }, [theme]);

  // ── Webhooks ───────────────────────────────────────────────────────────────
  const fetchWebhooks = useCallback(() => {
    fetch('/webhooks')
      .then(r => r.json())
      .then(data => { if (Array.isArray(data)) setWebhooks(data); })
      .catch(() => {});
  }, []);
  useEffect(() => { fetchWebhooks(); }, []);

  // ── Current user ───────────────────────────────────────────────────────────
  useEffect(() => {
    fetch('/me').then(r => r.json()).then(d => {
      setCurrentUser(d.username || '');
      setRole(d.role || 'admin');
    }).catch(() => {});
  }, []);

  // ── Load alert history ─────────────────────────────────────────────────────
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

  // ── Load flows / dns on first visit to that view ───────────────────────────
  useEffect(() => {
    if (activeView === 'flows' && flows.length === 0) {
      setEvtLoading(true);
      fetch('/flows?limit=5000').then(r => r.json()).then(d => {
        if (Array.isArray(d)) setFlows(d.map(r => ({ ...r, tsStr: fmtTime(r.ts) })));
        setEvtLoading(false);
      }).catch(() => setEvtLoading(false));
    }
    if (activeView === 'dns' && dnsEvents.length === 0) {
      setEvtLoading(true);
      fetch('/dns?limit=5000').then(r => r.json()).then(d => {
        if (Array.isArray(d)) setDnsEvents(d.map(r => ({ ...r, tsStr: fmtTime(r.ts) })));
        setEvtLoading(false);
      }).catch(() => setEvtLoading(false));
    }
  }, [activeView]);

  // ── SSE connection ─────────────────────────────────────────────────────────
  useEffect(() => {
    let es, retryTimer;

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
            if (prev.length > 0 && prev[0].id === evt.id) return prev;
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
            if (r.status === 401) window.location.href = '/login';
            else { setConnState('reconnecting'); retryTimer = setTimeout(connect, 3000); }
          })
          .catch(() => { setConnState('reconnecting'); retryTimer = setTimeout(connect, 3000); });
      };
    }

    connect();
    return () => { es && es.close(); clearTimeout(retryTimer); };
  }, []);

  useEffect(() => { pausedRef.current = paused; }, [paused]);

  // ── Sparkline ticker ───────────────────────────────────────────────────────
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

  // ── Acknowledgement ────────────────────────────────────────────────────────
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
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ ids:[...selectedIds], status:bulkStatus, note:bulkNote }),
      });
      if (r.ok) {
        const ids = new Set(selectedIds);
        setAlerts(prev => prev.map(a =>
          ids.has(a.id) ? { ...a, ack_status:bulkStatus, ack_note:bulkNote } : a
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
    if (allOn) setSelectedIds(new Set());
    else       setSelectedIds(new Set(visible));
  }

  // ── Clear handlers ─────────────────────────────────────────────────────────
  async function handleClearAlerts() {
    setClearing(true);
    try { await fetch('/alerts', { method:'DELETE' }); } catch {}
    setAlerts([]); setSelected(null); setHistoryCount(0);
    setClearing(false); setShowConfirm(false);
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
    setDeleting(false); setShowDeleteConfirm(false);
  }

  const handleClearFlows = async () => {
    try { await fetch('/flows', { method:'DELETE' }); setFlows([]); setFlowSel(null); }
    catch { alert('Failed to clear flows'); }
  };

  const handleClearDns = async () => {
    try { await fetch('/dns', { method:'DELETE' }); setDnsEvents([]); setDnsSel(null); }
    catch { alert('Failed to clear DNS events'); }
  };

  // ── Derived state ──────────────────────────────────────────────────────────
  const counts = useMemo(() => {
    const c = { critical:0, high:0, medium:0, low:0, info:0 };
    alerts.forEach(a => { c[a.severity] = (c[a.severity] || 0) + 1; });
    return c;
  }, [alerts]);

  const uniqueSrcs = useMemo(() => new Set(alerts.map(a => a.src_ip)).size, [alerts]);

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
    ), [alerts, activeSev, q]);

  function toggleSev(s) {
    setActiveSev(prev => {
      const next = new Set(prev);
      if (next.has(s)) { if (next.size > 1) next.delete(s); }
      else next.add(s);
      return next;
    });
  }

  const connColor = { live:'var(--green)', connecting:'var(--yellow)', reconnecting:'var(--text3)' }[connState];
  const connLabel = { live:'LIVE', connecting:'CONNECTING…', reconnecting:'RECONNECTING…' }[connState];

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
              <circle cx="12" cy="12" r="3" fill="white" fillOpacity=".9"/>
              <circle cx="12" cy="12" r="1.2" fill="white" fillOpacity=".4"/>
            </svg>
          </div>
          WATCHER
        </div>
        <div className="sep"/>
        <div className="badge">
          <div className="dot" style={{ background: connColor }}/>
          <span style={{ color:connColor, fontFamily:'var(--mono)', fontSize:11, letterSpacing:'.06em' }}>
            {connLabel}
          </span>
        </div>
        <div className="sep"/>
        <div className="pill">Interface: <b style={{ marginLeft:4 }}>eth0</b></div>
        <div className="pill">Engine: <b style={{ marginLeft:4, color:'var(--green)' }}>Running</b></div>
        {role !== 'admin' && (
          <div className="pill" style={{ borderColor:'var(--yellow)', background:'var(--yellow-d)' }}>
            <span style={{ color:'var(--yellow)', fontWeight:500, letterSpacing:'.04em' }}>
              {role.toUpperCase()}
            </span>
          </div>
        )}
        <div className="right">
          <div className="pill">Alerts/s: <b style={{ marginLeft:4 }}>{rate}</b></div>
          <Clock/>
          <ThemePicker theme={theme} onChange={setTheme}/>
          <a href="/logout" className="signout">SIGN OUT</a>
        </div>
      </header>

      {/* ── Sidebar ── */}
      <aside className="sidebar">
        <div className="s-label">Views</div>
        <div className={`nav-item${activeView==='alerts'?' active':''}`}
             onClick={() => setActiveView('alerts')}>
          <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M8 2L14 13H2L8 2Z"/>
            <line x1="8" y1="7" x2="8" y2="10"/>
            <circle cx="8" cy="12" r=".5" fill="currentColor"/>
          </svg>
          Alerts
          <span className="nav-badge">{alerts.length > 999 ? '999+' : alerts.length}</span>
        </div>

        <div className={`nav-item${activeView==='flows'?' active':''}`}
             style={activeView==='flows'?{background:'var(--teal-d)',color:'var(--teal)',borderColor:'rgba(45,212,191,.2)'}:{}}
             onClick={() => setActiveView('flows')}>
          <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M2 4h12M2 8h8M2 12h10"/>
          </svg>
          Flow Events
          <span style={{ marginLeft:'auto', fontFamily:'var(--mono)', fontSize:10,
                         padding:'1px 6px', borderRadius:10,
                         background:'var(--teal-d)', color:'var(--teal)' }}>
            {flows.length > 999 ? '999+' : flows.length}
          </span>
        </div>

        <div className={`nav-item${activeView==='dns'?' active':''}`}
             style={activeView==='dns'?{background:'rgba(159,122,234,.14)',color:'var(--purple)',borderColor:'rgba(159,122,234,.2)'}:{}}
             onClick={() => setActiveView('dns')}>
          <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
            <circle cx="8" cy="8" r="6"/><path d="M2 8h12M8 2a9 9 0 010 12"/>
          </svg>
          DNS Queries
          <span style={{ marginLeft:'auto', fontFamily:'var(--mono)', fontSize:10,
                         padding:'1px 6px', borderRadius:10,
                         background:'rgba(159,122,234,.14)', color:'var(--purple)' }}>
            {dnsEvents.length > 999 ? '999+' : dnsEvents.length}
          </span>
        </div>

        <div className={`nav-item${activeView==='charts'?' active':''}`}
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
          <div className={`nav-item${activeView==='settings'?' active':''}`}
               onClick={() => setActiveView('settings')}>
            <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="8" cy="8" r="2.5"/>
              <path d="M8 1v2M8 13v2M1 8h2M13 8h2M3.05 3.05l1.41 1.41M11.54 11.54l1.41 1.41M3.05 12.95l1.41-1.41M11.54 4.46l1.41-1.41"/>
            </svg>
            Settings
          </div>
        )}

        {activeView === 'alerts' && <div className="divider"/>}
        {activeView === 'alerts' && <div className="s-label">Severity</div>}
        {activeView === 'alerts' && ['critical','high','medium','low','info'].map(s => (
          <div key={s} className={`sev-row${activeSev.has(s)?' on':''}`} onClick={() => toggleSev(s)}>
            <div className="sev-dot" style={{ background: SEV_COLORS[s] }}/>
            {s.charAt(0).toUpperCase() + s.slice(1)}
            <span className="sev-cnt">{counts[s]}</span>
          </div>
        ))}

        {activeView === 'alerts' && <div className="divider"/>}
        {activeView === 'alerts' && <div className="s-label">Top Sources</div>}
        {activeView === 'alerts' && topSrcs.length === 0 && (
          <div style={{ padding:'4px 18px', fontSize:11, color:'var(--text3)', fontFamily:'var(--mono)' }}>
            no data yet
          </div>
        )}
        {activeView === 'alerts' && topSrcs.length > 0 && (
          <div style={{ padding:'0 12px' }}>
            {topSrcs.map(([ip, cnt]) => {
              const maxCount = topSrcs[0][1];
              const percent  = (cnt / maxCount) * 100;
              const isActive = search === ip;
              return (
                <div key={ip}
                     onClick={() => setSearch(isActive ? '' : ip)}
                     title={isActive ? 'Click to clear filter' : `Click to filter: ${ip}`}
                     style={{
                       marginBottom:8, cursor:'pointer', padding:'4px 6px', margin:'0 -6px 8px',
                       borderRadius:'var(--radius-sm)',
                       background: isActive ? 'var(--accent-d)' : 'transparent',
                       border: isActive ? '1px solid rgba(79,156,249,.25)' : '1px solid transparent',
                       transition:'background .12s, border-color .12s',
                     }}>
                  <div style={{ display:'flex', justifyContent:'space-between', fontSize:11, marginBottom:3 }}>
                    <span className="src-ip" style={{
                      overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', maxWidth:100,
                      color: isActive ? 'var(--accent)' : '',
                      fontWeight: isActive ? 500 : 'normal',
                    }}>{ip}</span>
                    <span className="src-cnt" style={{ color: isActive ? 'var(--accent)' : '' }}>{cnt}</span>
                  </div>
                  <div style={{ height:4, background:'var(--bg3)', borderRadius:2, overflow:'hidden' }}>
                    <div style={{ width:`${percent}%`, height:'100%', borderRadius:2,
                                  background:'var(--accent)', opacity: isActive ? 1 : 0.5,
                                  transition:'opacity .12s' }}/>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </aside>

      {/* ── Alerts view ── */}
      <main className="main" style={{ display: activeView === 'alerts' ? '' : 'none' }}>
        <div className="metrics" style={{ gridTemplateColumns:'repeat(5,1fr)' }}>
          <div className="metric">
            <div className="metric-label">Total Alerts</div>
            <div className="metric-val">{alerts.length.toLocaleString()}</div>
          </div>
          <div className="metric">
            <div className="metric-label">Critical</div>
            <div className="metric-val" style={{ color:'var(--red)' }}>{counts.critical}</div>
          </div>
          <div className="metric">
            <div className="metric-label">High</div>
            <div className="metric-val" style={{ color:'var(--orange)' }}>{counts.high}</div>
          </div>
          <div className="metric">
            <div className="metric-label">Medium</div>
            <div className="metric-val" style={{ color:'var(--yellow)' }}>{counts.medium}</div>
          </div>
          <div className="metric">
            <div className="metric-label">Unique Sources</div>
            <div className="metric-val">{uniqueSrcs}</div>
          </div>
        </div>

        <div className="content">
          {/* Alert table */}
          <div style={{ display:'flex', flexDirection:'column', overflow:'hidden', borderRight:'1px solid var(--border)' }}>
            <div className="pane-head">
              <span className="pane-title">Alert Stream</span>
              <span className="pane-cnt">{filtered.length.toLocaleString()}</span>
              {historyCount > 0 && (
                <span style={{ fontSize:10, fontFamily:'var(--mono)', color:'var(--text3)',
                               background:'var(--bg2)', border:'1px solid var(--border)',
                               padding:'1px 7px', borderRadius:10 }}>
                  {historyCount.toLocaleString()} stored
                </span>
              )}
              <div className="pane-actions">
                <div className="search">
                  <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <circle cx="7" cy="7" r="4"/><path d="M10 10l3 3"/>
                  </svg>
                  <input placeholder="Search alerts…" value={search} onChange={e => setSearch(e.target.value)}/>
                </div>
                {selected && (role === 'admin' || role === 'analyst') && (
                  <button className="btn" onClick={() => setShowExplain(true)}
                          style={{ color: 'var(--accent)', borderColor: 'rgba(79,156,249,.35)' }}>
                    Explain
                  </button>
                )}
                {(role === 'admin' || role === 'analyst') && (
                  <button className={`btn${paused?'':' on'}`} onClick={() => setPaused(p => !p)}>
                    {paused ? 'Resume' : 'Pause'}
                  </button>
                )}
                {role === 'admin' && (
                  <button className="btn" onClick={() => setShowConfirm(true)}>Clear</button>
                )}
              </div>
            </div>

            <div className="tscroll">
              {/* Bulk action bar */}
              {selectedIds.size > 0 && (role === 'admin' || role === 'analyst') && (
                <div style={{ display:'flex', alignItems:'center', gap:8, flexWrap:'wrap',
                              padding:'7px 12px', background:'var(--accent-d)',
                              borderBottom:'1px solid rgba(79,156,249,.2)', fontSize:12, flexShrink:0 }}>
                  <span style={{ fontFamily:'var(--mono)', color:'var(--accent)', fontWeight:500, whiteSpace:'nowrap' }}>
                    {selectedIds.size} selected
                  </span>
                  <select value={bulkStatus} onChange={e => setBulkStatus(e.target.value)}
                          style={{ padding:'3px 7px', borderRadius:'var(--radius-sm)',
                                   border:'1px solid var(--border2)', background:'var(--bg2)',
                                   color:'var(--text1)', fontSize:11, fontFamily:'var(--mono)',
                                   cursor:'pointer', outline:'none' }}>
                    <option value="new">New</option>
                    <option value="investigating">Investigating</option>
                    <option value="acknowledged">Acknowledged</option>
                    <option value="false_positive">False Positive</option>
                  </select>
                  <input value={bulkNote} onChange={e => setBulkNote(e.target.value)}
                         placeholder="Optional note for all…"
                         style={{ flex:1, minWidth:100, padding:'3px 8px',
                                  borderRadius:'var(--radius-sm)', border:'1px solid var(--border2)',
                                  background:'var(--bg2)', color:'var(--text1)',
                                  fontSize:11, fontFamily:'var(--sans)', outline:'none' }}/>
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
                      color:'var(--red)', fontSize:11, fontFamily:'var(--sans)', cursor:'pointer', whiteSpace:'nowrap',
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
                    <line x1="3" y1="9" x2="21" y2="9"/>
                    <line x1="9" y1="21" x2="9" y2="9"/>
                  </svg>
                  <div>{connState === 'live' ? 'No alerts match current filters' : 'Connecting…'}</div>
                </div>
              ) : (
                <table>
                  <thead>
                    <tr>
                      {(role === 'admin' || role === 'analyst') && (
                        <th style={{ width:32, textAlign:'center', paddingLeft:8 }}>
                          <input type="checkbox" className="hm-check"
                                 checked={filtered.slice(0,300).length > 0 &&
                                          filtered.slice(0,300).every(a => selectedIds.has(a.id))}
                                 onChange={toggleSelectAll}/>
                        </th>
                      )}
                      <th style={{ width:148 }}>Time</th>
                      <th style={{ width:82 }}>Severity</th>
                      <th style={{ width:110 }}>Status</th>
                      <th style={{ width:72 }}>Protocol</th>
                      <th>Signature</th>
                      <th style={{ width:115 }}>Source</th>
                      <th style={{ width:115 }}>Destination</th>
                      <th style={{ width:80 }}>SID</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.slice(0, 300).map((a, i) => {
                      const isSel = selectedIds.has(a.id);
                      return (
                        <tr key={a.id || i}
                            className={['arow', selected?.id===a.id?'sel':'',
                                        newIdsRef.current.has(a.id)?'new':''].filter(Boolean).join(' ')}
                            style={isSel ? { background:'var(--accent-d)' } : {}}
                            onClick={() => setSelected(a)}>
                          {(role === 'admin' || role === 'analyst') && (
                            <td style={{ textAlign:'center', width:32, paddingLeft:8 }}
                                onClick={e => e.stopPropagation()}>
                              <input type="checkbox" className="hm-check"
                                     checked={isSel} onChange={() => toggleSelectId(a.id)}/>
                            </td>
                          )}
                          <td className="mono-dim" style={{ width:148, whiteSpace:'nowrap' }}>
                            {a.tsStr || fmtTime(a.ts)}
                          </td>
                          <td><span className={`sbadge ${a.severity}`}>{a.severity}</span></td>
                          <td style={{ width:110 }}><AckBadge status={a.ack_status || 'new'}/></td>
                          <td><span className="proto">{a.proto}</span></td>
                          <td style={{ fontSize:12, color:'var(--text1)' }}>{a.sig_msg}</td>
                          <td className="mono">{a.src_ip}:{a.src_port}</td>
                          <td className="mono">{a.dst_ip}:{a.dst_port}</td>
                          <td className="mono-dim" style={{ width:80, whiteSpace:'nowrap' }}>{a.sig_id}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          {/* Detail panel */}
          <div className="detail">
            <div className="pane-head">
              <span className="pane-title">Event Detail</span>
            </div>
            {role === 'viewer'
              ? <div className="dscroll"><div className="empty" style={{ height:'100%' }}>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="12" y1="8" x2="12" y2="12"/>
                    <line x1="12" y1="16" x2="12.01" y2="16"/>
                  </svg>
                  <div>Viewer access</div>
                  <div style={{ fontSize:10 }}>Detail panel not available</div>
                </div></div>
              : <Detail alert={selected} onAck={handleAck} role={role}/>}
            <Sparkline data={sparkData}/>
            <Timeline alerts={alerts}/>
          </div>
        </div>
      </main>

      {/* ── Flows view ── */}
      {activeView === 'flows' && (
        <main className="main">
          <div className="content" style={{ gridTemplateColumns:'1fr 310px' }}>
            <FlowsView rows={flows} loading={evtLoading} selected={flowSel}
                       onSelect={setFlowSel} onClear={handleClearFlows}/>
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
          <div className="content" style={{ gridTemplateColumns:'1fr 310px' }}>
            <DNSView rows={dnsEvents} loading={evtLoading} selected={dnsSel}
                     onSelect={setDnsSel} onClear={handleClearDns}/>
            <div className="detail">
              <div className="pane-head"><span className="pane-title">DNS Detail</span></div>
              <DNSDetail item={dnsSel}/>
            </div>
          </div>
        </main>
      )}

      {activeView === 'charts'   && <ChartsView/>}
      {activeView === 'settings' && role === 'admin' && (
        <SettingsView currentUser={currentUser} webhooks={webhooks}
                      onRefreshWebhooks={fetchWebhooks} role={role}/>
      )}

      {/* Delete selected modal */}
      {showDeleteConfirm && (
        <div className="modal-bg" onClick={() => setShowDeleteConfirm(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div style={{ fontSize:15, fontWeight:500, marginBottom:10 }}>
              Delete {selectedIds.size} selected alert{selectedIds.size !== 1 ? 's' : ''}?
            </div>
            <div style={{ fontSize:12, color:'var(--text2)', lineHeight:1.7, marginBottom:24 }}>
              This will permanently remove{' '}
              <b style={{ color:'var(--text1)' }}>{selectedIds.size} alert{selectedIds.size !== 1 ? 's' : ''}</b>{' '}
              and their acknowledgement history. This action cannot be undone.
            </div>
            <div style={{ display:'flex', gap:10, justifyContent:'flex-end' }}>
              <button className="btn" onClick={() => setShowDeleteConfirm(false)}
                      disabled={deleting} style={{ minWidth:80 }}>Cancel</button>
              <button onClick={handleDeleteSelected} disabled={deleting} style={{
                minWidth:80, padding:'4px 14px', borderRadius:'var(--radius-sm)',
                border:'1px solid var(--red)', background:'var(--red-d)',
                color:'var(--red)', fontSize:11, fontFamily:'var(--sans)',
                cursor: deleting ? 'wait' : 'pointer', transition:'all .15s',
              }}>{deleting ? 'Deleting…' : `Yes, delete ${selectedIds.size}`}</button>
            </div>
          </div>
        </div>
      )}

      {/* Clear all alerts modal */}
      {showConfirm && (
        <div className="modal-bg" onClick={() => setShowConfirm(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div style={{ fontSize:15, fontWeight:500, marginBottom:10 }}>Clear all alerts?</div>
            <div style={{ fontSize:12, color:'var(--text2)', lineHeight:1.7, marginBottom:24 }}>
              This will permanently delete{' '}
              <b style={{ color:'var(--text1)' }}>{(historyCount || alerts.length).toLocaleString()} stored alerts</b>{' '}
              from the database. This action cannot be undone.
            </div>
            <div style={{ display:'flex', gap:10, justifyContent:'flex-end' }}>
              <button className="btn" onClick={() => setShowConfirm(false)}
                      disabled={clearing} style={{ minWidth:80 }}>Cancel</button>
              <button onClick={handleClearAlerts} disabled={clearing} style={{
                minWidth:80, padding:'4px 14px', borderRadius:'var(--radius-sm)',
                border:'1px solid var(--red)', background:'var(--red-d)',
                color:'var(--red)', fontSize:11, fontFamily:'var(--sans)',
                cursor: clearing ? 'wait' : 'pointer', transition:'all .15s',
              }}>{clearing ? 'Clearing…' : 'Yes, delete all'}</button>
            </div>
          </div>
        </div>
      )}

      {/* Explain dialog */}
      {showExplain && selected && (
        <ExplainDialog
          alert={selected}
          role={role}
          onClose={() => setShowExplain(false)}
        />
      )}
    </div>
  );
}
