import { useState, useEffect } from 'react';

const SEV_COLORS = {
  critical: 'var(--red)', high: 'var(--orange)',
  medium: 'var(--yellow)', low: 'var(--green)', info: 'var(--accent)',
};

// ── provider accent colours (mirrors Settings.jsx PROVIDER_META) ─────────────
const PROVIDER_COLOR = { deepseek: '#4D6BFE', openai: '#10A37F', anthropic: '#D4793B', nvidia: '#76B900' };

// ── ExplainDialog — pops up when user clicks Explain on a selected alert ──────
export function ExplainDialog({ alert, role, aiEnabled: aiEnabledProp, onClose }) {
  const [aiEnabled, setAiEnabled] = useState(null);  // null = loading
  const [tab,       setTab]       = useState(null);   // set after config loaded
  const [intel,     setIntel]     = useState(null);
  const [intelLoad, setIntelLoad] = useState(true);
  const [editing,   setEditing]   = useState(false);

  // AI explanation state
  const [aiData,    setAiData]    = useState(null);
  const [aiLoading, setAiLoading] = useState(true);
  const [aiError,   setAiError]   = useState(null);

  // Use the aiEnabled prop passed from App (fetched once at app level — no per-click fetch)
  useEffect(() => {
    if (alert === null) return;
    const enabled = aiEnabledProp ?? false;
    setAiEnabled(enabled);
    setTab(enabled ? 'ai' : 'intel');
  }, [alert?.sig_id, aiEnabledProp]);

  // Fetch threat-intel notes
  useEffect(() => {
    if (!alert) return;
    setIntelLoad(true); setIntel(null); setEditing(false);
    fetch(`/threat-intel/lookup?sig_id=${alert.sig_id}&category=${encodeURIComponent(alert.category || '')}`)
      .then(r => r.json())
      .then(d => { setIntel(d && d.id ? d : null); setIntelLoad(false); })
      .catch(() => setIntelLoad(false));
  }, [alert?.sig_id, alert?.category]);

  // Fetch AI explanation on open (if enabled) — expected to be cached
  useEffect(() => {
    if (!alert || !aiEnabled) return;
    if (aiData && aiData.sig_id === alert.sig_id) return;
    fetchAi(false);
  }, [alert?.sig_id, aiEnabled]);

  function fetchAi(force) {
    setAiLoading(true); setAiError(null);
    fetch('/alerts/explain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sig_id:   alert.sig_id,
        sig_msg:  alert.sig_msg,
        src_ip:   alert.src_ip,
        dest_ip:  alert.dst_ip,
        proto:    alert.proto,
        category: alert.category,
        severity: alert.severity,
        force,
      }),
    })
      .then(r => r.json())
      .then(d => {
        if (d.error) { setAiError(d.message || d.error); setAiLoading(false); return; }
        setAiData(d); setAiLoading(false);
      })
      .catch(() => { setAiError('Network error — could not reach the server.'); setAiLoading(false); });
  }

  if (!alert || tab === null) return null;  // wait for config

  const fmtAge = ts => {
    const s = Math.floor(Date.now() / 1000 - ts);
    if (s < 60)    return 'just now';
    if (s < 3600)  return `${Math.floor(s/60)}m ago`;
    if (s < 86400) return `${Math.floor(s/3600)}h ago`;
    return `${Math.floor(s/86400)}d ago`;
  };

  return (
    <div className="modal-bg" onClick={onClose}>
      <div onClick={e => e.stopPropagation()} style={{
        background: 'var(--bg1)', border: '1px solid var(--border2)',
        borderRadius: 'var(--radius-lg)', width: 560, maxWidth: '95vw',
        maxHeight: '85vh', display: 'flex', flexDirection: 'column',
        animation: 'slideUp .2s ease-out',
      }}>
        {/* Header */}
        <div style={{
          padding: '14px 20px', borderBottom: '1px solid var(--border)',
          display: 'flex', alignItems: 'flex-start', gap: 12, flexShrink: 0,
        }}>
          <div style={{
            width: 34, height: 34, borderRadius: 'var(--radius-md)', flexShrink: 0,
            background: 'var(--accent-d)', border: '1px solid var(--accent-b)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
                 stroke="var(--accent)" strokeWidth="1.8">
              <circle cx="12" cy="12" r="10"/>
              <line x1="12" y1="8" x2="12" y2="12"/>
              <line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text1)',
                          marginBottom: 4, lineHeight: 1.3 }}>
              {alert.sig_msg}
            </div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
              <span className={`sbadge ${alert.severity}`}>{alert.severity}</span>
              <span style={{ fontFamily: 'var(--mono)', fontSize: 10,
                             color: 'var(--text3)' }}>SID {alert.sig_id}</span>
              {alert.category && (
                <span style={{ fontFamily: 'var(--mono)', fontSize: 10,
                               color: 'var(--text3)' }}>{alert.category}</span>
              )}
            </div>
          </div>
          <button onClick={onClose} style={{
            background: 'none', border: 'none', color: 'var(--text3)',
            cursor: 'pointer', padding: 4, flexShrink: 0,
          }}>
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"
                 stroke="currentColor" strokeWidth="2">
              <line x1="2" y1="2" x2="14" y2="14"/>
              <line x1="14" y1="2" x2="2" y2="14"/>
            </svg>
          </button>
        </div>

        {/* Tabs — AI tab only shown when enabled */}
        <div style={{
          display: 'flex', gap: 0, borderBottom: '1px solid var(--border)',
          padding: '0 20px', flexShrink: 0, background: 'var(--bg1)',
        }}>
          {[
            aiEnabled ? { id:'ai', label:'AI Explanation' } : null,
            { id:'intel', label:'Threat Intel' },
          ].filter(Boolean).map(t => (
            <button key={t.id} onClick={() => setTab(t.id)} style={{
              background: 'none', border: 'none', padding: '8px 14px',
              fontSize: 11, fontFamily: 'var(--mono)', cursor: 'pointer',
              color:        tab === t.id ? 'var(--accent)'  : 'var(--text3)',
              borderBottom: tab === t.id ? '2px solid var(--accent)' : '2px solid transparent',
              marginBottom: -1, transition: 'color .15s',
            }}>{t.label}</button>
          ))}
        </div>

        {/* AI Explanation tab */}
        {tab === 'ai' && (
          <div style={{ flex: 1, overflowY: 'auto', padding: '18px 20px' }}>
            {aiLoading && (
              <div style={{ color: 'var(--text3)', fontFamily: 'var(--mono)',
                            fontSize: 12, textAlign: 'center', padding: '30px 0' }}>
                <div style={{ marginBottom: 8, color: 'var(--text2)' }}>Loading summary…</div>
                <div style={{
                  width: 24, height: 24, border: '2px solid var(--border2)',
                  borderTopColor: 'var(--accent)', borderRadius: '50%',
                  animation: 'spin .8s linear infinite', margin: '0 auto',
                }}/>
              </div>
            )}

            {!aiLoading && aiError && (
              <div>
                <div style={{
                  background: 'var(--red-d)', border: '1px solid var(--red-b)',
                  borderRadius: 'var(--radius-md)', padding: '12px 14px',
                  color: 'var(--red)', fontSize: 12, lineHeight: 1.6, marginBottom: 12,
                }}>
                  {aiError.startsWith('no_key:')
                    ? aiError.replace('no_key: ', '') + ' Summaries are generated automatically once a key is set in Settings → AI Explain.'
                    : aiError}
                </div>
                <button className="btn" onClick={() => fetchAi(false)}
                  style={{ fontSize: 11 }}>Retry</button>
              </div>
            )}

            {!aiLoading && aiData && !aiError && (
              <div>
                {/* Meta row */}
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  marginBottom: 14, flexWrap: 'wrap',
                }}>
                  <span style={{
                    fontSize: 9, fontFamily: 'var(--mono)', letterSpacing: '.08em',
                    textTransform: 'uppercase', padding: '2px 8px', borderRadius: 20,
                    background: aiData.cached ? 'var(--green-d)'   : 'var(--accent-d)',
                    color:      aiData.cached ? 'var(--green)'       : 'var(--accent)',
                    border:     aiData.cached ? '1px solid var(--green-b)' : '1px solid var(--accent-b)',
                  }}>
                    {aiData.cached ? '✓ Saved' : '⚡ Generated'}
                  </span>
                  <span style={{ fontSize: 10, color: 'var(--text3)', fontFamily: 'var(--mono)' }}>
                    {fmtAge(aiData.generated_at)} · {aiData.model}
                    {aiData.provider && (
                      <span style={{
                        display: 'inline-block', width: 7, height: 7,
                        borderRadius: '50%', marginLeft: 4, verticalAlign: 'middle',
                        background: PROVIDER_COLOR[aiData.provider] || 'var(--accent)',
                      }}/>
                    )}
                  </span>
                  <div style={{ marginLeft:'auto', display:'flex', gap:6, alignItems:'center' }}>
                    {!aiData.cached && (
                      <span style={{
                        fontSize:9, fontFamily:'var(--mono)', color:'var(--green)',
                        padding:'2px 6px', borderRadius:4,
                        background:'var(--green-d)', border:'1px solid var(--green-b)',
                      }}>✓ Auto-saved</span>
                    )}
                    {(role === 'admin' || role === 'analyst') && (
                      <button onClick={() => fetchAi(true)} style={{
                        background: 'none', border: 'none',
                        color: 'var(--text3)', fontSize: 11, cursor: 'pointer',
                        fontFamily: 'var(--mono)', padding: '2px 6px',
                        borderRadius: 4, transition: 'color .15s',
                      }} onMouseOver={e => e.target.style.color='var(--text1)'}
                         onMouseOut={e  => e.target.style.color='var(--text3)'}>
                        ↺ Regenerate
                      </button>
                    )}
                  </div>
                </div>

                {/* Explanation body */}
                <div style={{
                  fontSize: 12.5, lineHeight: 1.75, color: 'var(--text1)',
                  whiteSpace: 'pre-wrap', fontFamily: 'var(--sans)',
                }}>
                  {aiData.explanation}
                </div>

                {/* Token usage */}
                {(aiData.prompt_tokens > 0 || aiData.completion_tokens > 0) && (
                  <div style={{
                    marginTop: 16, paddingTop: 12,
                    borderTop: '1px solid var(--border)',
                    fontSize: 10, color: 'var(--text3)', fontFamily: 'var(--mono)',
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  }}>
                    <span>{aiData.prompt_tokens} prompt + {aiData.completion_tokens} completion tokens</span>
                    <span style={{ color:'var(--text3)', fontSize:9 }}>
                      {aiData.cached
                        ? 'Loaded from saved explanation'
                        : 'Explanation saved — next click loads instantly'}
                    </span>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Threat Intel tab */}
        {tab === 'intel' && (
          <div style={{ flex: 1, overflowY: 'auto', padding: '18px 20px' }}>
            {intelLoad && (
              <div style={{ color: 'var(--text3)', fontFamily: 'var(--mono)',
                            fontSize: 12, textAlign: 'center', padding: '30px 0' }}>
                Looking up intel…
              </div>
            )}
            {!intelLoad && intel && !editing && (
              <IntelDisplay intel={intel} alert={alert} role={role}
                            onEdit={() => setEditing(true)}/>
            )}
            {!intelLoad && !intel && !editing && (
              <NoIntel alert={alert} role={role} onAdd={() => setEditing(true)}/>
            )}
            {!intelLoad && editing && (
              <IntelEditor
                alert={alert} existing={intel} role={role}
                onSaved={d => { setIntel(d); setEditing(false); }}
                onCancel={() => setEditing(false)}
              />
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ── IntelDisplay — read-only view of an existing explanation ──────────────────
function IntelDisplay({ intel, alert, role, onEdit }) {
  const matchType = intel.sig_id === alert.sig_id ? 'Exact SID match' : 'Category match';
  const fmtDate   = ts => new Date(ts * 1000).toLocaleDateString(undefined,
    { month: 'short', day: 'numeric', year: 'numeric' });

  return (
    <div>
      {/* Match type badge */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
        <span style={{
          fontSize: 9, fontFamily: 'var(--mono)', letterSpacing: '.08em',
          textTransform: 'uppercase', padding: '2px 8px', borderRadius: 20,
          background: 'var(--green-d)', color: 'var(--green)',
          border: '1px solid var(--green)',
        }}>{matchType}</span>
        <span style={{ fontSize: 10, color: 'var(--text3)', fontFamily: 'var(--mono)' }}>
          by {intel.created_by || 'system'} · {fmtDate(intel.updated_at)}
        </span>
        {(role === 'admin' || role === 'analyst') && (
          <button onClick={onEdit} style={{
            marginLeft: 'auto', padding: '2px 10px', borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border2)', background: 'transparent',
            color: 'var(--text2)', fontSize: 11, cursor: 'pointer',
          }}>Edit</button>
        )}
      </div>

      {/* Explanation */}
      <div style={{
        fontSize: 13, color: 'var(--text1)', lineHeight: 1.75,
        background: 'var(--bg2)', border: '1px solid var(--border)',
        borderRadius: 'var(--radius-md)', padding: '14px 16px',
        marginBottom: 16, whiteSpace: 'pre-wrap',
      }}>{intel.explanation}</div>

      {/* Tags */}
      {intel.tags && intel.tags.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 9, fontFamily: 'var(--mono)', letterSpacing: '.1em',
                        textTransform: 'uppercase', color: 'var(--text3)',
                        marginBottom: 7 }}>Tags</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {intel.tags.map(t => (
              <span key={t} style={{
                padding: '2px 9px', borderRadius: 20, fontSize: 11,
                background: 'var(--bg3)', border: '1px solid var(--border)',
                color: 'var(--text2)', fontFamily: 'var(--mono)',
              }}>{t}</span>
            ))}
          </div>
        </div>
      )}

      {/* References */}
      {intel.refs && intel.refs.length > 0 && (
        <div>
          <div style={{ fontSize: 9, fontFamily: 'var(--mono)', letterSpacing: '.1em',
                        textTransform: 'uppercase', color: 'var(--text3)',
                        marginBottom: 7 }}>References</div>
          {intel.refs.map((r, i) => (
            <div key={i} style={{ marginBottom: 4 }}>
              <a href={r.startsWith('http') ? r : `https://${r}`}
                 target="_blank" rel="noopener noreferrer"
                 style={{ fontSize: 11, color: 'var(--accent)',
                          fontFamily: 'var(--mono)', wordBreak: 'break-all' }}>
                {r}
              </a>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── NoIntel — shown when no explanation exists yet ────────────────────────────
function NoIntel({ alert, role, onAdd }) {
  return (
    <div style={{ textAlign: 'center', padding: '20px 0' }}>
      <svg width="48" height="48" viewBox="0 0 24 24" fill="none"
           stroke="var(--text3)" strokeWidth="1" style={{ marginBottom: 12, opacity: .4 }}>
        <circle cx="12" cy="12" r="10"/>
        <line x1="12" y1="8" x2="12" y2="12"/>
        <line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
      <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--text2)',
                    marginBottom: 6 }}>No explanation yet</div>
      <div style={{ fontSize: 12, color: 'var(--text3)', marginBottom: 20,
                    lineHeight: 1.6 }}>
        SID {alert.sig_id} · {alert.category || 'Uncategorized'}<br/>
        Add an explanation to help analysts understand this alert.
      </div>
      {(role === 'admin' || role === 'analyst') && (
        <button onClick={onAdd} style={{
          padding: '7px 20px', borderRadius: 'var(--radius-sm)',
          border: '1px solid var(--accent)', background: 'var(--accent-d)',
          color: 'var(--accent)', fontSize: 12, fontFamily: 'var(--sans)',
          cursor: 'pointer',
        }}>+ Add Explanation</button>
      )}
    </div>
  );
}

// ── IntelEditor — create/edit form ────────────────────────────────────────────
function IntelEditor({ alert, existing, role, onSaved, onCancel }) {
  const [explanation, setExplanation] = useState(existing?.explanation || '');
  const [tagInput,    setTagInput]    = useState('');
  const [tags,        setTags]        = useState(existing?.tags || []);
  const [refInput,    setRefInput]    = useState('');
  const [refs,        setRefs]        = useState(existing?.refs || []);
  const [scope,       setScope]       = useState(existing?.sig_id ? 'sid' : 'category');
  const [saving,      setSaving]      = useState(false);
  const [err,         setErr]         = useState('');

  function addTag() {
    const t = tagInput.trim();
    if (t && !tags.includes(t)) setTags(prev => [...prev, t]);
    setTagInput('');
  }
  function addRef() {
    const r = refInput.trim();
    if (r && !refs.includes(r)) setRefs(prev => [...prev, r]);
    setRefInput('');
  }

  async function save() {
    if (!explanation.trim()) { setErr('Explanation is required'); return; }
    setSaving(true); setErr('');
    const body = {
      explanation: explanation.trim(),
      tags, refs,
      sig_id:   scope === 'sid'      ? alert.sig_id   : null,
      sig_msg:  scope === 'sid'      ? alert.sig_msg   : null,
      category: scope === 'category' ? alert.category  : null,
    };
    const method   = existing?.id ? 'PUT'  : 'POST';
    const endpoint = existing?.id ? `/threat-intel/${existing.id}` : '/threat-intel';
    try {
      const r = await fetch(endpoint, {
        method, headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const d = await r.json();
      if (!r.ok) { setErr(d.error || 'Save failed'); return; }
      onSaved(d);
    } catch { setErr('Network error'); }
    finally { setSaving(false); }
  }

  const inputStyle = {
    width: '100%', padding: '7px 10px', background: 'var(--bg2)',
    border: '1px solid var(--border2)', borderRadius: 'var(--radius-sm)',
    color: 'var(--text1)', fontSize: 12, fontFamily: 'var(--sans)',
    outline: 'none', boxSizing: 'border-box',
  };
  const labelStyle = {
    fontSize: 9, fontWeight: 600, letterSpacing: '.1em', textTransform: 'uppercase',
    color: 'var(--text3)', display: 'block', marginBottom: 6,
  };

  return (
    <div>
      {/* Scope selector */}
      {!existing && (
        <div style={{ marginBottom: 16 }}>
          <label style={labelStyle}>Apply this explanation to</label>
          <div style={{ display: 'flex', gap: 8 }}>
            {[
              { val: 'sid',      label: `SID ${alert.sig_id} only` },
              { val: 'category', label: `All "${alert.category || 'Uncategorized'}" alerts` },
            ].map(opt => (
              <button key={opt.val} onClick={() => setScope(opt.val)} style={{
                flex: 1, padding: '6px 12px', borderRadius: 'var(--radius-sm)',
                border: `1px solid ${scope === opt.val ? 'var(--accent)' : 'var(--border)'}`,
                background: scope === opt.val ? 'var(--accent-d)' : 'transparent',
                color: scope === opt.val ? 'var(--accent)' : 'var(--text2)',
                fontSize: 11, fontFamily: 'var(--sans)', cursor: 'pointer',
              }}>{opt.label}</button>
            ))}
          </div>
        </div>
      )}

      {/* Explanation textarea */}
      <div style={{ marginBottom: 14 }}>
        <label style={labelStyle}>Explanation</label>
        <textarea
          style={{ ...inputStyle, minHeight: 120, resize: 'vertical', lineHeight: 1.65 }}
          placeholder="Describe what this alert means, what triggered it, and whether it typically indicates malicious activity or a false positive…"
          value={explanation}
          onChange={e => setExplanation(e.target.value)}
        />
      </div>

      {/* Tags */}
      <div style={{ marginBottom: 14 }}>
        <label style={labelStyle}>Tags</label>
        <div style={{ display: 'flex', gap: 6, marginBottom: 7, flexWrap: 'wrap' }}>
          {tags.map(t => (
            <span key={t} style={{
              display: 'inline-flex', alignItems: 'center', gap: 5,
              padding: '2px 9px', borderRadius: 20, fontSize: 11,
              background: 'var(--bg3)', border: '1px solid var(--border)',
              color: 'var(--text2)', fontFamily: 'var(--mono)',
            }}>
              {t}
              <span onClick={() => setTags(prev => prev.filter(x => x !== t))}
                    style={{ cursor: 'pointer', color: 'var(--text3)',
                             lineHeight: 1, fontSize: 13 }}>×</span>
            </span>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <input style={{ ...inputStyle, flex: 1 }}
                 placeholder="e.g. lateral-movement, false-positive, c2…"
                 value={tagInput}
                 onChange={e => setTagInput(e.target.value)}
                 onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addTag(); } }}/>
          <button onClick={addTag} style={{
            padding: '6px 12px', borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border2)', background: 'var(--bg3)',
            color: 'var(--text2)', fontSize: 11, cursor: 'pointer',
          }}>Add</button>
        </div>
      </div>

      {/* References */}
      <div style={{ marginBottom: 16 }}>
        <label style={labelStyle}>References (URLs)</label>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 7 }}>
          {refs.map(r => (
            <div key={r} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ flex: 1, fontFamily: 'var(--mono)', fontSize: 11,
                             color: 'var(--accent)', overflow: 'hidden',
                             textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r}</span>
              <span onClick={() => setRefs(prev => prev.filter(x => x !== r))}
                    style={{ cursor: 'pointer', color: 'var(--text3)', fontSize: 13 }}>×</span>
            </div>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <input style={{ ...inputStyle, flex: 1, fontFamily: 'var(--mono)', fontSize: 11 }}
                 placeholder="https://docs.suricata.io/…"
                 value={refInput}
                 onChange={e => setRefInput(e.target.value)}
                 onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addRef(); } }}/>
          <button onClick={addRef} style={{
            padding: '6px 12px', borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border2)', background: 'var(--bg3)',
            color: 'var(--text2)', fontSize: 11, cursor: 'pointer',
          }}>Add</button>
        </div>
      </div>

      {err && (
        <div style={{ marginBottom: 12, padding: '7px 10px', fontSize: 12,
                      background: 'var(--red-d)', border: '1px solid var(--red)',
                      borderRadius: 'var(--radius-sm)', color: 'var(--red)' }}>{err}</div>
      )}

      <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
        <button onClick={onCancel} disabled={saving} style={{
          padding: '5px 16px', borderRadius: 'var(--radius-sm)',
          border: '1px solid var(--border2)', background: 'transparent',
          color: 'var(--text2)', fontSize: 12, cursor: 'pointer',
        }}>Cancel</button>
        <button onClick={save} disabled={saving} style={{
          padding: '5px 20px', borderRadius: 'var(--radius-sm)',
          border: '1px solid var(--accent)', background: 'var(--accent-d)',
          color: 'var(--accent)', fontSize: 12, cursor: saving ? 'wait' : 'pointer',
        }}>{saving ? 'Saving…' : existing ? 'Save Changes' : 'Save Explanation'}</button>
      </div>
    </div>
  );
}

// ── ThreatIntelPanel — full settings tab ──────────────────────────────────────
export function ThreatIntelPanel({ role }) {
  const [entries,  setEntries]  = useState([]);
  const [gaps,     setGaps]     = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editing,  setEditing]  = useState(null);
  const [delId,    setDelId]    = useState(null);
  const [tab,      setTab]      = useState('entries');
  // Import/Export state
  const [importFile,    setImportFile]    = useState(null);
  const [importParsed,  setImportParsed]  = useState(null);  // parsed JSON array
  const [importError,   setImportError]   = useState(null);
  const [importResult,  setImportResult]  = useState(null);
  const [importing,     setImporting]     = useState(false);

  function load() {
    setLoading(true);
    Promise.all([
      fetch('/threat-intel').then(r => r.json()),
      fetch('/threat-intel/gaps').then(r => r.json()),
    ]).then(([e, g]) => {
      setEntries(Array.isArray(e) ? e : []);
      setGaps(Array.isArray(g) ? g : []);
      setLoading(false);
    }).catch(() => setLoading(false));
  }
  useEffect(() => { load(); }, []);

  async function doDelete(id) {
    await fetch(`/threat-intel/${id}`, { method: 'DELETE' });
    setDelId(null); load();
  }

  const fmtDate = ts => new Date(ts * 1000).toLocaleDateString(undefined,
    { month: 'short', day: 'numeric', year: 'numeric' });

  const tabBtn = (id, label, count) => (
    <button onClick={() => setTab(id)} style={{
      padding: '2px 12px', borderRadius: 'var(--radius-sm)', border: 'none',
      background: tab === id ? 'var(--accent)' : 'transparent',
      color:      tab === id ? 'white' : 'var(--text3)',
      fontSize: 11, fontFamily: 'var(--mono)', cursor: 'pointer',
    }}>
      {label}{count !== undefined ? ` (${count})` : ''}
    </button>
  );

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Sub-tab bar */}
      <div style={{ padding: '10px 20px', borderBottom: '1px solid var(--border)',
                    display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
        <div style={{ display: 'flex', gap: 1, background: 'var(--bg2)',
                      border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)',
                      padding: 2 }}>
          {tabBtn('entries', 'Explanations', entries.length)}
          {tabBtn('gaps',    'Coverage Gaps', gaps.length)}
          {tabBtn('io', '↑↓ Import / Export')}
        </div>
        {(role === 'admin' || role === 'analyst') && (
          <button onClick={() => { setEditing(null); setShowForm(true); }} style={{
            marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6,
            padding: '5px 14px', borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--accent)', background: 'var(--accent-d)',
            color: 'var(--accent)', fontSize: 12, cursor: 'pointer',
          }}>+ Add Explanation</button>
        )}
      </div>

      <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
        {/* ── Explanations tab ── */}
        {tab === 'entries' && (
          <>
            <div style={{ marginBottom: 16, padding: '10px 14px', fontSize: 12,
                          color: 'var(--text2)', lineHeight: 1.7,
                          background: 'var(--accent-d)', borderRadius: 'var(--radius-md)',
                          border: '1px solid var(--accent-b)' }}>
              <b style={{ color: 'var(--accent)' }}>Threat Intel</b> explanations appear
              in the <b style={{ color: 'var(--text1)' }}>Explain</b> dialog when analysts
              click an alert. SID-specific entries take priority over category entries.
            </div>

            {loading && <div style={{ color: 'var(--text3)', fontSize: 12,
                                      fontFamily: 'var(--mono)', padding: '20px 0' }}>Loading…</div>}

            {showForm && (
              <ManualIntelForm
                existing={editing} role={role}
                onSaved={() => { setShowForm(false); setEditing(null); load(); }}
                onCancel={() => { setShowForm(false); setEditing(null); }}
              />
            )}

            {!loading && entries.length === 0 && !showForm && (
              <div className="empty" style={{ height: 180 }}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
                  <circle cx="12" cy="12" r="10"/>
                  <line x1="12" y1="8" x2="12" y2="12"/>
                  <line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
                <div>No explanations yet</div>
                <div style={{ fontSize: 11 }}>Add entries manually or click Explain on any alert</div>
              </div>
            )}

            {!loading && entries.map(e => (
              <div key={e.id} style={{
                background: 'var(--bg1)', border: '1px solid var(--border)',
                borderRadius: 'var(--radius-lg)', padding: '14px 16px', marginBottom: 10,
                borderLeft: `3px solid ${e.sig_id ? 'var(--accent)' : 'var(--purple)'}`,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                  <span style={{
                    fontSize: 9, fontFamily: 'var(--mono)', letterSpacing: '.08em',
                    textTransform: 'uppercase', padding: '2px 7px', borderRadius: 20,
                    background: e.sig_id ? 'var(--accent-d)' : 'rgba(159,122,234,.15)',
                    color: e.sig_id ? 'var(--accent)' : 'var(--purple)',
                    border: `1px solid ${e.sig_id ? 'var(--accent-b)' : 'rgba(159,122,234,.3)'}`,
                  }}>{e.sig_id ? `SID ${e.sig_id}` : `Category`}</span>
                  <span style={{ fontWeight: 500, fontSize: 13, color: 'var(--text1)' }}>
                    {e.sig_msg || e.category || '—'}
                  </span>
                  <span style={{ marginLeft: 'auto', fontSize: 10, fontFamily: 'var(--mono)',
                                 color: 'var(--text3)' }}>
                    {fmtDate(e.updated_at)} · {e.created_by || 'system'}
                  </span>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.65,
                              marginBottom: 10, overflow: 'hidden',
                              display: '-webkit-box', WebkitLineClamp: 3,
                              WebkitBoxOrient: 'vertical' }}>
                  {e.explanation}
                </div>
                {e.tags && e.tags.length > 0 && (
                  <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 10 }}>
                    {e.tags.map(t => (
                      <span key={t} style={{
                        padding: '1px 7px', borderRadius: 20, fontSize: 10,
                        background: 'var(--bg3)', border: '1px solid var(--border)',
                        color: 'var(--text3)', fontFamily: 'var(--mono)',
                      }}>{t}</span>
                    ))}
                  </div>
                )}
                {(role === 'admin' || role === 'analyst') && (
                  <div style={{ display: 'flex', gap: 7 }}>
                    <button className="btn" style={{ fontSize: 11 }}
                            onClick={() => { setEditing(e); setShowForm(true); }}>Edit</button>
                    {role === 'admin' && (
                      <button className="btn-danger" style={{ fontSize: 11 }}
                              onClick={() => setDelId(e.id)}>Delete</button>
                    )}
                  </div>
                )}
              </div>
            ))}
          </>
        )}

        {/* ── Coverage Gaps tab ── */}
        {tab === 'gaps' && (
          <>
            <div style={{ marginBottom: 16, padding: '10px 14px', fontSize: 12,
                          color: 'var(--text2)', lineHeight: 1.7,
                          background: 'var(--yellow-d)', borderRadius: 'var(--radius-md)',
                          border: '1px solid rgba(245,200,66,.2)' }}>
              <b style={{ color: 'var(--yellow)' }}>Coverage Gaps</b> — your top-firing
              signatures that have no explanation yet. Click <b style={{ color: 'var(--text1)' }}>
              Add</b> to document them.
            </div>
            {gaps.length === 0 && (
              <div className="empty" style={{ height: 160 }}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
                  <polyline points="20 6 9 17 4 12"/>
                </svg>
                <div>Full coverage!</div>
                <div style={{ fontSize: 11 }}>All top-firing SIDs have explanations</div>
              </div>
            )}
            {gaps.map(g => (
              <div key={g.sig_id} style={{
                background: 'var(--bg1)', border: '1px solid var(--border)',
                borderRadius: 'var(--radius-md)', padding: '12px 16px',
                marginBottom: 8, display: 'flex', alignItems: 'center', gap: 12,
              }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontFamily: 'var(--mono)', fontSize: 11,
                                color: 'var(--text3)', marginBottom: 3 }}>
                    SID {g.sig_id}
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--text1)',
                                overflow: 'hidden', textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap' }}>{g.sig_msg}</div>
                </div>
                <div style={{ fontFamily: 'var(--mono)', fontSize: 11,
                              color: 'var(--orange)', whiteSpace: 'nowrap' }}>
                  {g.count.toLocaleString()} fires
                </div>
                {(role === 'admin' || role === 'analyst') && (
                  <button onClick={() => {
                    setEditing({
                      _prefill: true, sig_id: g.sig_id, sig_msg: g.sig_msg,
                    });
                    setShowForm(true); setTab('entries');
                  }} style={{
                    padding: '4px 12px', borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--accent)', background: 'var(--accent-d)',
                    color: 'var(--accent)', fontSize: 11, cursor: 'pointer',
                    whiteSpace: 'nowrap',
                  }}>+ Add</button>
                )}
              </div>
            ))}
          </>
        )}

        {/* ── Import / Export tab ── */}
        {tab === 'io' && (
          <div style={{ maxWidth: 600 }}>

            {/* ── Export ── */}
            <div style={{ marginBottom: 24 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text1)', marginBottom: 8 }}>
                Export
              </div>
              <div style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.7, marginBottom: 12 }}>
                Download all {entries.length} threat intel entries as a <code style={{ fontFamily:'var(--mono)', fontSize:11 }}>.json</code> file.
                The file can be re-imported into any Watcher instance.
              </div>
              <a href="/threat-intel/export" download="watcher-threat-intel.json">
                <button style={{
                  display: 'flex', alignItems: 'center', gap: 7,
                  padding: '7px 16px', borderRadius: 'var(--radius-md)',
                  background: 'var(--accent-d)', border: '1px solid var(--accent)',
                  color: 'var(--accent)', fontSize: 12, cursor: 'pointer',
                  fontFamily: 'var(--mono)',
                }}>
                  <svg width="13" height="13" viewBox="0 0 16 16" fill="none"
                       stroke="currentColor" strokeWidth="2">
                    <path d="M8 2v8M4 10l4 4 4-4"/><line x1="2" y1="15" x2="14" y2="15"/>
                  </svg>
                  Export {entries.length} {entries.length === 1 ? 'entry' : 'entries'} (.json)
                </button>
              </a>
            </div>

            <div style={{ height: 1, background: 'var(--border)', marginBottom: 24 }}/>

            {/* ── Import ── */}
            <div>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text1)', marginBottom: 8 }}>
                Import
              </div>

              {/* Format guide */}
              <div style={{
                marginBottom: 14, padding: '12px 14px', fontSize: 11,
                background: 'var(--accent-d)', border: '1px solid var(--accent-b)',
                borderRadius: 'var(--radius-md)', lineHeight: 1.8,
              }}>
                <div style={{ fontWeight: 600, color: 'var(--accent)', marginBottom: 6, fontSize: 12 }}>
                  📋 File format guide
                </div>
                <div style={{ color: 'var(--text2)' }}>
                  The file must be a <b>.json</b> file containing an array of objects.
                  Each object may have:
                </div>
                <div style={{ marginTop: 8, fontFamily: 'var(--mono)', fontSize: 10,
                              color: 'var(--text1)', background: 'var(--bg2)',
                              padding: '8px 10px', borderRadius: 6, lineHeight: 1.9 }}>
                  {`[
  {
    "sig_id":      2100498,          ← Suricata SID (optional)
    "sig_msg":     "GPL ATTACK ...", ← Signature name (optional)
    "category":    "Web Attack",    ← Category (optional)
    "explanation": "This fires …",  ← Required
    "tags":        ["web","sqli"],  ← Array of tags (optional)
    "refs":        ["https://…"]   ← Reference URLs (optional)
  }
]`}
                </div>
                <div style={{ marginTop: 8, color: 'var(--text3)', fontSize: 10 }}>
                  ⚠ Each entry needs at least <b>sig_id</b> or <b>category</b> — and must have an <b>explanation</b>.
                  If a matching entry already exists it will be <b>updated</b>, not duplicated.
                </div>
              </div>

              {/* File picker */}
              {role === 'admin' && (<>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                  <label style={{
                    display: 'flex', alignItems: 'center', gap: 7, cursor: 'pointer',
                    padding: '7px 14px', borderRadius: 'var(--radius-md)',
                    background: 'var(--bg2)', border: '1px solid var(--border2)',
                    color: 'var(--text2)', fontSize: 12, fontFamily: 'var(--mono)',
                    transition: 'border-color .15s',
                  }}
                  onMouseEnter={e => e.currentTarget.style.borderColor='var(--accent)'}
                  onMouseLeave={e => e.currentTarget.style.borderColor='var(--border2)'}>
                    <svg width="13" height="13" viewBox="0 0 16 16" fill="none"
                         stroke="currentColor" strokeWidth="2">
                      <path d="M8 10V2M4 6l4-4 4 4"/><line x1="2" y1="15" x2="14" y2="15"/>
                    </svg>
                    {importFile ? importFile.name : 'Choose .json file…'}
                    <input type="file" accept=".json,application/json"
                      style={{ display: 'none' }}
                      onChange={e => {
                        const file = e.target.files?.[0];
                        if (!file) return;
                        setImportFile(file);
                        setImportError(null);
                        setImportResult(null);
                        setImportParsed(null);
                        const reader = new FileReader();
                        reader.onload = ev => {
                          try {
                            const parsed = JSON.parse(ev.target.result);
                            if (!Array.isArray(parsed)) throw new Error('File must contain a JSON array.');
                            setImportParsed(parsed);
                            setImportError(null);
                          } catch (err) {
                            setImportError(`Parse error: ${err.message}`);
                            setImportParsed(null);
                          }
                        };
                        reader.readAsText(file);
                      }}/>
                  </label>
                  {importParsed && (
                    <span style={{ fontSize: 11, fontFamily: 'var(--mono)', color: 'var(--green)' }}>
                      ✓ {importParsed.length} {importParsed.length === 1 ? 'entry' : 'entries'} ready
                    </span>
                  )}
                </div>

                {importError && (
                  <div style={{
                    marginBottom: 12, padding: '8px 12px', fontSize: 11,
                    fontFamily: 'var(--mono)', color: 'var(--red)',
                    background: 'var(--red-d)', border: '1px solid var(--red-b)',
                    borderRadius: 'var(--radius-md)',
                  }}>{importError}</div>
                )}

                {importParsed && (
                  <button
                    onClick={() => {
                      setImporting(true); setImportResult(null);
                      fetch('/threat-intel/import', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(importParsed),
                      })
                        .then(r => r.json())
                        .then(d => {
                          setImportResult(d);
                          setImporting(false);
                          if ((d.imported || 0) + (d.updated || 0) > 0) load();
                        })
                        .catch(() => {
                          setImportError('Network error during import.');
                          setImporting(false);
                        });
                    }}
                    disabled={importing}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 7,
                      padding: '7px 16px', borderRadius: 'var(--radius-md)',
                      background: importing ? 'var(--bg2)' : 'var(--green-d)',
                      border: `1px solid ${importing ? 'var(--border)' : 'var(--green-b)'}`,
                      color: importing ? 'var(--text3)' : 'var(--green)',
                      fontSize: 12, cursor: importing ? 'default' : 'pointer',
                      fontFamily: 'var(--mono)', transition: 'all .15s',
                    }}>
                    {importing ? 'Importing…' : `↑ Import ${importParsed.length} entries`}
                  </button>
                )}

                {importResult && (
                  <div style={{
                    marginTop: 14, padding: '10px 14px', fontSize: 11,
                    fontFamily: 'var(--mono)', borderRadius: 'var(--radius-md)',
                    background: 'var(--green-d)', border: '1px solid var(--green-b)',
                    lineHeight: 1.8,
                  }}>
                    <div style={{ color: 'var(--green)', fontWeight: 600, marginBottom: 4 }}>
                      ✓ Import complete
                    </div>
                    <div style={{ color: 'var(--text2)' }}>
                      {importResult.imported} new · {importResult.updated} updated · {importResult.skipped} skipped
                    </div>
                    {importResult.errors?.length > 0 && (
                      <div style={{ marginTop: 8, color: 'var(--orange)' }}>
                        {importResult.errors.slice(0, 5).map((e, i) => (
                          <div key={i}>⚠ {e}</div>
                        ))}
                        {importResult.errors.length > 5 && (
                          <div>…and {importResult.errors.length - 5} more warnings</div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </>)}

              {role !== 'admin' && (
                <div style={{ fontSize: 12, color: 'var(--text3)', fontFamily: 'var(--mono)' }}>
                  Import is restricted to admins.
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Delete confirm */}
      {delId !== null && (
        <div className="modal-bg" onClick={() => setDelId(null)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div style={{ fontSize: 15, fontWeight: 500, marginBottom: 10 }}>
              Delete explanation?
            </div>
            <div style={{ fontSize: 12, color: 'var(--text2)', marginBottom: 24 }}>
              This will remove the explanation permanently.
            </div>
            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button className="btn" onClick={() => setDelId(null)}>Cancel</button>
              <button onClick={() => doDelete(delId)} style={{
                padding: '4px 14px', borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--red)', background: 'var(--red-d)',
                color: 'var(--red)', fontSize: 11, cursor: 'pointer',
              }}>Delete</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── ManualIntelForm — used in settings panel ──────────────────────────────────
function ManualIntelForm({ existing, role, onSaved, onCancel }) {
  const prefill = existing?._prefill;
  const [sigId,       setSigId]       = useState(existing?.sig_id     ? String(existing.sig_id) : '');
  const [sigMsg,      setSigMsg]      = useState(existing?.sig_msg    || '');
  const [category,    setCategory]    = useState(existing?.category   || '');
  const [explanation, setExplanation] = useState(existing?.explanation|| '');
  const [tagInput,    setTagInput]    = useState('');
  const [tags,        setTags]        = useState(existing?.tags        || []);
  const [refInput,    setRefInput]    = useState('');
  const [refs,        setRefs]        = useState(existing?.refs        || []);
  const [saving,      setSaving]      = useState(false);
  const [err,         setErr]         = useState('');

  const isEdit = existing?.id;

  function addTag() {
    const t = tagInput.trim();
    if (t && !tags.includes(t)) setTags(p => [...p, t]);
    setTagInput('');
  }
  function addRef() {
    const r = refInput.trim();
    if (r && !refs.includes(r)) setRefs(p => [...p, r]);
    setRefInput('');
  }

  async function save() {
    if (!explanation.trim()) { setErr('Explanation is required'); return; }
    if (!sigId && !category.trim()) { setErr('SID or Category is required'); return; }
    setSaving(true); setErr('');
    const body = {
      sig_id:      sigId ? parseInt(sigId) : null,
      sig_msg:     sigMsg.trim() || null,
      category:    category.trim() || null,
      explanation: explanation.trim(),
      tags, refs,
    };
    const method   = isEdit ? 'PUT'  : 'POST';
    const endpoint = isEdit ? `/threat-intel/${existing.id}` : '/threat-intel';
    try {
      const r = await fetch(endpoint, {
        method, headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const d = await r.json();
      if (!r.ok) { setErr(d.error || 'Save failed'); return; }
      onSaved(d);
    } catch { setErr('Network error'); }
    finally { setSaving(false); }
  }

  const inputStyle = {
    width: '100%', padding: '7px 10px', background: 'var(--bg2)',
    border: '1px solid var(--border2)', borderRadius: 'var(--radius-sm)',
    color: 'var(--text1)', fontSize: 12, fontFamily: 'var(--sans)',
    outline: 'none', boxSizing: 'border-box',
  };
  const labelStyle = {
    fontSize: 9, fontWeight: 600, letterSpacing: '.1em', textTransform: 'uppercase',
    color: 'var(--text3)', display: 'block', marginBottom: 5,
  };

  return (
    <div style={{ background: 'var(--bg2)', border: '1px solid var(--border2)',
                  borderRadius: 'var(--radius-lg)', padding: 20, marginBottom: 20 }}>
      <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 16 }}>
        {isEdit ? 'Edit Explanation' : 'New Explanation'}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
        <div>
          <label style={labelStyle}>SID (optional)</label>
          <input style={{ ...inputStyle, fontFamily: 'var(--mono)' }}
                 type="number" placeholder="e.g. 2100498"
                 value={sigId} onChange={e => setSigId(e.target.value)}/>
        </div>
        <div>
          <label style={labelStyle}>Category (optional)</label>
          <input style={inputStyle} placeholder="e.g. trojan-activity"
                 value={category} onChange={e => setCategory(e.target.value)}/>
        </div>
      </div>

      <div style={{ marginBottom: 12 }}>
        <label style={labelStyle}>Signature Name (optional)</label>
        <input style={inputStyle} placeholder="Human-readable signature name"
               value={sigMsg} onChange={e => setSigMsg(e.target.value)}/>
      </div>

      <div style={{ marginBottom: 12 }}>
        <label style={labelStyle}>Explanation</label>
        <textarea style={{ ...inputStyle, minHeight: 100, resize: 'vertical', lineHeight: 1.65 }}
                  placeholder="What does this alert mean? What triggered it? Is it typically malicious?"
                  value={explanation} onChange={e => setExplanation(e.target.value)}/>
      </div>

      <div style={{ marginBottom: 12 }}>
        <label style={labelStyle}>Tags</label>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginBottom: 6 }}>
          {tags.map(t => (
            <span key={t} style={{
              display: 'inline-flex', alignItems: 'center', gap: 4,
              padding: '2px 8px', borderRadius: 20, fontSize: 11,
              background: 'var(--bg3)', border: '1px solid var(--border)',
              color: 'var(--text2)', fontFamily: 'var(--mono)',
            }}>
              {t}
              <span onClick={() => setTags(p => p.filter(x => x !== t))}
                    style={{ cursor: 'pointer', color: 'var(--text3)' }}>×</span>
            </span>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <input style={{ ...inputStyle, flex: 1 }} placeholder="Add tag…"
                 value={tagInput} onChange={e => setTagInput(e.target.value)}
                 onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addTag(); } }}/>
          <button onClick={addTag} className="btn" style={{ flexShrink: 0 }}>Add</button>
        </div>
      </div>

      <div style={{ marginBottom: 16 }}>
        <label style={labelStyle}>References</label>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 3, marginBottom: 6 }}>
          {refs.map(r => (
            <div key={r} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ flex: 1, fontFamily: 'var(--mono)', fontSize: 11,
                             color: 'var(--accent)', overflow: 'hidden',
                             textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r}</span>
              <span onClick={() => setRefs(p => p.filter(x => x !== r))}
                    style={{ cursor: 'pointer', color: 'var(--text3)', fontSize: 13 }}>×</span>
            </div>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <input style={{ ...inputStyle, flex: 1, fontFamily: 'var(--mono)', fontSize: 11 }}
                 placeholder="https://…"
                 value={refInput} onChange={e => setRefInput(e.target.value)}
                 onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addRef(); } }}/>
          <button onClick={addRef} className="btn" style={{ flexShrink: 0 }}>Add</button>
        </div>
      </div>

      {err && (
        <div style={{ marginBottom: 12, padding: '7px 10px', fontSize: 12,
                      background: 'var(--red-d)', border: '1px solid var(--red)',
                      borderRadius: 'var(--radius-sm)', color: 'var(--red)' }}>{err}</div>
      )}

      <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
        <button className="btn" onClick={onCancel} disabled={saving}>Cancel</button>
        <button onClick={save} disabled={saving} style={{
          padding: '5px 20px', borderRadius: 'var(--radius-sm)',
          border: '1px solid var(--accent)', background: 'var(--accent-d)',
          color: 'var(--accent)', fontSize: 12, cursor: saving ? 'wait' : 'pointer',
        }}>{saving ? 'Saving…' : isEdit ? 'Save Changes' : 'Create'}</button>
      </div>
    </div>
  );
}
