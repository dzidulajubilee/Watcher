import { useState, useEffect } from 'react';
import { ACK_STATUSES, ACK_MAP, HighlightedJSON } from './components.jsx';

export function Detail({ alert, onAck, role }) {
  const [ackStatus,   setAckStatus]   = useState(alert?.ack_status || 'new');
  const [ackNote,     setAckNote]     = useState(alert?.ack_note   || '');
  const [saving,      setSaving]      = useState(false);
  const [saveMsg,     setSaveMsg]     = useState('');
  const [tab,         setTab]         = useState('details');
  const [history,     setHistory]     = useState([]);
  const [histLoading, setHistLoading] = useState(false);

  useEffect(() => {
    setAckStatus(alert?.ack_status || 'new');
    setAckNote(alert?.ack_note     || '');
    setSaveMsg('');
    setTab('details');
    setHistory([]);
  }, [alert?.id]);

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
        body:    JSON.stringify({ status: ackStatus, note: ackNote }),
      });
      const d = await r.json();
      if (r.ok) {
        setSaveMsg('✓ Saved');
        onAck && onAck(alert.id, ackStatus, ackNote);
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
    <div style={{ display:'flex', flexDirection:'column', flex:1, overflow:'hidden' }}>
      {/* Tab bar */}
      <div style={{
        display:'flex', alignItems:'center', padding:'8px 12px',
        borderBottom:'1px solid var(--border)', background:'var(--bg1)', flexShrink:0,
      }}>
        <div style={{ display:'flex', gap:1, background:'var(--bg3)',
                      border:'1px solid var(--border)', borderRadius:'var(--radius-sm)', padding:2 }}>
          {tabBtn('details', 'Details')}
          {tabBtn('history', 'History')}
          {tabBtn('raw',     'Raw JSON')}
        </div>
      </div>

      {/* ── Details ── */}
      {tab === 'details' && (
        <div className="dscroll">
          <div className="dsec">
            <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:12 }}>
              <span className={`sbadge ${alert.severity}`}>{alert.severity}</span>
              <span style={{ fontSize:13, fontWeight:500, lineHeight:1.3 }}>{alert.sig_msg}</span>
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
              <div style={{ display:'flex', flexWrap:'wrap', gap:6, marginBottom:10 }}>
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
              <div style={{ display:'flex', alignItems:'center', gap:8, marginTop:8 }}>
                <button onClick={submitAck} disabled={saving} style={{
                  padding:'4px 14px', borderRadius:'var(--radius-sm)',
                  border:'1px solid var(--accent)', background:'var(--accent-d)',
                  color:'var(--accent)', fontSize:11, fontFamily:'var(--sans)',
                  cursor: saving ? 'wait' : 'pointer', transition:'all .15s',
                }}>{saving ? 'Saving…' : 'Save'}</button>
                {saveMsg && (
                  <span style={{ fontSize:11, fontFamily:'var(--mono)',
                    color: saveMsg.startsWith('✓') ? 'var(--green)' : 'var(--red)' }}>
                    {saveMsg}
                  </span>
                )}
                {alert.ack_by && (
                  <span style={{ fontSize:10, fontFamily:'var(--mono)',
                                 color:'var(--text3)', marginLeft:'auto' }}>
                    by {alert.ack_by}
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── History ── */}
      {tab === 'history' && (
        <div className="dscroll">
          <div className="dsec-title" style={{ marginBottom:14 }}>Acknowledgement History</div>
          {histLoading && (
            <div style={{ color:'var(--text3)', fontSize:12, fontFamily:'var(--mono)',
                          textAlign:'center', padding:'30px 0' }}>Loading…</div>
          )}
          {!histLoading && history.length === 0 && (
            <div className="empty" style={{ height:160 }}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
                <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
              </svg>
              <div>No history yet</div>
              <div style={{ fontSize:10 }}>Changes appear here after the first save</div>
            </div>
          )}
          {!histLoading && history.map((h, i) => {
            const cfg     = ACK_MAP[h.status] || ACK_MAP['new'];
            const date    = new Date(h.changed_at * 1000);
            const dateStr = date.toLocaleDateString(undefined, { month:'short', day:'numeric', year:'numeric' });
            const timeStr = date.toLocaleTimeString('en-GB', { hour12:false });
            return (
              <div key={i} style={{
                display:'flex', gap:10, paddingBottom:14, marginBottom:14,
                borderBottom: i < history.length - 1 ? '1px solid var(--border)' : 'none',
              }}>
                <div style={{ display:'flex', flexDirection:'column', alignItems:'center', flexShrink:0 }}>
                  <div style={{
                    width:10, height:10, borderRadius:'50%', marginTop:3, flexShrink:0,
                    background: cfg.color, boxShadow:`0 0 0 3px ${cfg.bg}`,
                  }}/>
                  {i < history.length - 1 && (
                    <div style={{ width:1, flex:1, background:'var(--border)', marginTop:5 }}/>
                  )}
                </div>
                <div style={{ flex:1, minWidth:0 }}>
                  <div style={{ display:'flex', alignItems:'center', gap:7, marginBottom:5, flexWrap:'wrap' }}>
                    <span style={{
                      padding:'1px 7px', borderRadius:'var(--radius-sm)',
                      fontSize:9, fontWeight:500, fontFamily:'var(--mono)',
                      letterSpacing:'.05em', textTransform:'uppercase',
                      color: cfg.color, background: cfg.bg,
                    }}>{cfg.label}</span>
                    {h.username && (
                      <span style={{ fontSize:10, fontFamily:'var(--mono)', color:'var(--text3)' }}>
                        by <b style={{ color:'var(--text2)' }}>{h.username}</b>
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
                  <div style={{ fontSize:10, fontFamily:'var(--mono)', color:'var(--text3)' }}>
                    {dateStr} · {timeStr}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ── Raw JSON ── */}
      {tab === 'raw' && (
        <div className="dscroll">
          <div className="dsec-title" style={{ marginBottom:8 }}>Raw EVE JSON</div>
          <HighlightedJSON data={alert.raw || alert} />
        </div>
      )}
    </div>
  );
}
