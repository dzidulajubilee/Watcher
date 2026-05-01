import { useState, useMemo } from 'react';
import { fmtTime, fmtBytes, fmtDur } from './utils.js';
import { HighlightedJSON } from './components.jsx';

// ── Shared confirm modal ──────────────────────────────────────────────────────
function ClearModal({ title, body, onConfirm, onCancel }) {
  return (
    <div className="modal-bg" onClick={onCancel}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <div style={{ fontSize:15, fontWeight:500, marginBottom:10 }}>{title}</div>
        <div style={{ fontSize:12, color:'var(--text2)', lineHeight:1.7, marginBottom:24 }}>{body}</div>
        <div style={{ display:'flex', gap:10, justifyContent:'flex-end' }}>
          <button className="btn" onClick={onCancel} style={{ minWidth:80 }}>Cancel</button>
          <button onClick={onConfirm} style={{
            minWidth:80, padding:'4px 14px', borderRadius:'var(--radius-sm)',
            border:'1px solid var(--red)', background:'var(--red-d)',
            color:'var(--red)', fontSize:11, fontFamily:'var(--sans)',
            cursor:'pointer', transition:'all .15s',
          }}>Yes, delete all</button>
        </div>
      </div>
    </div>
  );
}

// ── FlowsView ─────────────────────────────────────────────────────────────────
export function FlowsView({ rows, loading, selected, onSelect, onClear }) {
  const [search, setSearch] = useState('');
  const [showClear, setShowClear] = useState(false);
  const q = search.toLowerCase();
  const filtered = useMemo(() =>
    rows.filter(r =>
      !q || r.src_ip?.includes(q) || r.dst_ip?.includes(q) ||
      r.proto?.toLowerCase().includes(q) || r.app_proto?.toLowerCase().includes(q)
    ), [rows, q]);

  return (
    <div style={{ display:'flex', flexDirection:'column', overflow:'hidden', flex:1 }}>
      <div className="pane-head">
        <span className="pane-title" style={{ color:'var(--teal)' }}>Flow Events</span>
        <span className="pane-cnt">{filtered.length.toLocaleString()}</span>
        <div className="pane-actions">
          <div className="search">
            <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="7" cy="7" r="4"/><path d="M10 10l3 3"/>
            </svg>
            <input placeholder="Filter flows…" value={search} onChange={e => setSearch(e.target.value)}/>
          </div>
          <button className="btn" onClick={() => setShowClear(true)}>Clear</button>
        </div>
      </div>

      <div className="tscroll">
        {loading ? (
          <div className="empty"><div>Loading…</div></div>
        ) : filtered.length === 0 ? (
          <div className="empty">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
              <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
            </svg>
            <div>No flow events yet</div>
          </div>
        ) : (
          <table>
            <thead><tr>
              <th style={{ width:80 }}>Time</th>
              <th style={{ width:52 }}>Proto</th>
              <th style={{ width:105 }}>Source</th>
              <th style={{ width:105 }}>Destination</th>
              <th style={{ width:72 }}>App Proto</th>
              <th style={{ width:70 }}>State</th>
              <th style={{ width:80 }}>↑ Bytes</th>
              <th style={{ width:80 }}>↓ Bytes</th>
              <th style={{ width:65 }}>Duration</th>
              <th style={{ width:52 }}>Alert</th>
            </tr></thead>
            <tbody>
              {filtered.slice(0, 300).map((r, i) => (
                <tr key={r.flow_id || i}
                    className={`arow${selected?.flow_id === r.flow_id ? ' sel' : ''}`}
                    onClick={() => onSelect(r)}>
                  <td className="mono-dim">{fmtTime(r.ts)}</td>
                  <td><span className="proto">{r.proto}</span></td>
                  <td className="mono">{r.src_ip}:{r.src_port}</td>
                  <td className="mono">{r.dst_ip}:{r.dst_port}</td>
                  <td className="mono-dim">{r.app_proto || '—'}</td>
                  <td className="mono-dim">{r.state}</td>
                  <td className="mono-dim">{fmtBytes(r.bytes_toserver)}</td>
                  <td className="mono-dim">{fmtBytes(r.bytes_toclient)}</td>
                  <td className="mono-dim">{fmtDur(r.duration_s)}</td>
                  <td><span style={{ color:r.alerted?'var(--red)':'var(--text3)', fontSize:10, fontFamily:'var(--mono)' }}>
                    {r.alerted ? 'YES' : '—'}
                  </span></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {showClear && (
        <ClearModal
          title="Clear all flow events?"
          body={<>This will permanently delete{' '}
            <b style={{ color:'var(--text1)' }}>{rows.length.toLocaleString()} stored flows</b>{' '}
            from the database. This action cannot be undone.</>}
          onConfirm={() => { setShowClear(false); onClear && onClear(); }}
          onCancel={() => setShowClear(false)}
        />
      )}
    </div>
  );
}

// ── FlowDetail ────────────────────────────────────────────────────────────────
export function FlowDetail({ item }) {
  if (!item) return (
    <div className="dscroll">
      <div className="empty" style={{ height:'100%' }}>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
          <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
        </svg>
        <div>Select a flow</div>
      </div>
    </div>
  );

  const F = ({ label, val, full, color }) => (
    <div className={`dfield${full ? ' dfull' : ''}`}>
      <div className="dfield-label">{label}</div>
      <div className="dfield-val" style={color ? { color } : {}}>{val ?? '—'}</div>
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
          <F label="App Protocol" val={item.app_proto || '—'}/>
          <F label="State"        val={item.state}/>
          <F label="Reason"       val={item.reason}/>
          <F label="Duration"     val={fmtDur(item.duration_s)}/>
          <F label="Alerted"      val={item.alerted ? 'Yes' : 'No'}
             color={item.alerted ? 'var(--red)' : 'var(--green)'}/>
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
export function DNSView({ rows, loading, selected, onSelect, onClear }) {
  const [search, setSearch] = useState('');
  const [showClear, setShowClear] = useState(false);
  const q = search.toLowerCase();
  const filtered = useMemo(() =>
    rows.filter(r =>
      !q || r.rrname?.toLowerCase().includes(q) || r.src_ip?.includes(q) ||
      r.rrtype?.toLowerCase().includes(q) || r.rcode?.toLowerCase().includes(q)
    ), [rows, q]);

  return (
    <div style={{ display:'flex', flexDirection:'column', overflow:'hidden', flex:1 }}>
      <div className="pane-head">
        <span className="pane-title" style={{ color:'var(--purple)' }}>DNS Queries</span>
        <span className="pane-cnt">{filtered.length.toLocaleString()}</span>
        <div className="pane-actions">
          <div className="search">
            <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="7" cy="7" r="4"/><path d="M10 10l3 3"/>
            </svg>
            <input placeholder="Filter by name, IP…" value={search} onChange={e => setSearch(e.target.value)}/>
          </div>
          <button className="btn" onClick={() => setShowClear(true)}>Clear</button>
        </div>
      </div>

      <div className="tscroll">
        {loading ? (
          <div className="empty"><div>Loading…</div></div>
        ) : filtered.length === 0 ? (
          <div className="empty">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
              <circle cx="12" cy="12" r="10"/>
              <path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
            </svg>
            <div>No DNS events yet</div>
          </div>
        ) : (
          <table>
            <thead><tr>
              <th style={{ width:80 }}>Time</th>
              <th style={{ width:90 }}>Type</th>
              <th style={{ width:70 }}>RCode</th>
              <th style={{ width:105 }}>Source</th>
              <th style={{ width:105 }}>Resolver</th>
            </tr></thead>
            <tbody>
              {filtered.slice(0, 300).map((r, i) => (
                <tr key={r.id || i}
                    className={`arow${selected?.id === r.id ? ' sel' : ''}`}
                    onClick={() => onSelect(r)}>
                  <td className="mono-dim">{fmtTime(r.ts)}</td>
                  <td><span className="proto">{r.dns_type}</span></td>
                  <td className="mono-dim">{r.rcode || '—'}</td>
                  <td className="mono">{r.src_ip}</td>
                  <td className="mono">{r.dst_ip}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {showClear && (
        <ClearModal
          title="Clear all DNS events?"
          body={<>This will permanently delete{' '}
            <b style={{ color:'var(--text1)' }}>{rows.length.toLocaleString()} stored DNS events</b>{' '}
            from the database. This action cannot be undone.</>}
          onConfirm={() => { setShowClear(false); onClear && onClear(); }}
          onCancel={() => setShowClear(false)}
        />
      )}
    </div>
  );
}

// ── DNSDetail ─────────────────────────────────────────────────────────────────
export function DNSDetail({ item }) {
  if (!item) return (
    <div className="dscroll">
      <div className="empty" style={{ height:'100%' }}>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
          <circle cx="12" cy="12" r="10"/><path d="M2 12h20"/>
        </svg>
        <div>Select a DNS event</div>
      </div>
    </div>
  );

  const F = ({ label, val, full }) => (
    <div className={`dfield${full ? ' dfull' : ''}`}>
      <div className="dfield-label">{label}</div>
      <div className="dfield-val">{val ?? '—'}</div>
    </div>
  );

  return (
    <div className="dscroll">
      <div className="dsec">
        <div className="dsec-title">DNS Query</div>
        <div className="dgrid">
          <F label="Query Name"  val={item.rrname} full/>
          <F label="Type"        val={item.dns_type}/>
          <F label="RCode"       val={item.rcode}/>
          <F label="TTL"         val={item.ttl ? item.ttl + 's' : '—'}/>
          <F label="Source IP"   val={item.src_ip}/>
          <F label="Resolver"    val={item.dst_ip}/>
          <F label="Flow ID"     val={item.flow_id}/>
          <F label="TX ID"       val={item.tx_id}/>
          <F label="Timestamp"   val={item.ts} full/>
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
