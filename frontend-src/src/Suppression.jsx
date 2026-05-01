import { useState, useEffect } from 'react';

export function SuppressionPanel({ role }) {
  const [rules,    setRules]    = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editing,  setEditing]  = useState(null);
  const [delId,    setDelId]    = useState(null);

  function load() {
    setLoading(true);
    fetch('/suppression').then(r => r.json())
      .then(d => { setRules(Array.isArray(d) ? d : []); setLoading(false); })
      .catch(() => setLoading(false));
  }
  useEffect(() => { load(); }, []);

  async function doDelete(id) {
    await fetch(`/suppression/${id}`, { method: 'DELETE' });
    setDelId(null); load();
  }

  async function toggleEnabled(rule) {
    await fetch(`/suppression/${rule.id}`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: !rule.enabled }),
    });
    load();
  }

  const fmtDate = ts => ts
    ? new Date(ts * 1000).toLocaleDateString(undefined,
        { month: 'short', day: 'numeric', year: 'numeric' })
    : null;

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Header row */}
      <div style={{ padding: '10px 20px', borderBottom: '1px solid var(--border)',
                    display: 'flex', alignItems: 'center', flexShrink: 0 }}>
        <span style={{ fontSize: 11, color: 'var(--text3)', fontFamily: 'var(--mono)' }}>
          {rules.length} rule{rules.length !== 1 ? 's' : ''}
        </span>
        {role === 'admin' && (
          <button onClick={() => { setEditing(null); setShowForm(true); }} style={{
            marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6,
            padding: '5px 14px', borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--red)', background: 'var(--red-d)',
            color: 'var(--red)', fontSize: 12, cursor: 'pointer',
          }}>+ Add Rule</button>
        )}
      </div>

      <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
        <div style={{ marginBottom: 16, padding: '10px 14px', fontSize: 12,
                      color: 'var(--text2)', lineHeight: 1.7,
                      background: 'var(--red-d)', borderRadius: 'var(--radius-md)',
                      border: '1px solid rgba(240,84,84,.2)' }}>
          <b style={{ color: 'var(--red)' }}>Suppression Rules</b> silence matching
          alerts before they are stored or streamed. Rules match on any combination
          of <b style={{ color: 'var(--text1)' }}>SID</b>,{' '}
          <b style={{ color: 'var(--text1)' }}>source IP</b>, or{' '}
          <b style={{ color: 'var(--text1)' }}>category</b> — all specified
          conditions must match (AND logic).
        </div>

        {showForm && (
          <SuppressionForm
            existing={editing}
            onSaved={() => { setShowForm(false); setEditing(null); load(); }}
            onCancel={() => { setShowForm(false); setEditing(null); }}
          />
        )}

        {loading && (
          <div style={{ color: 'var(--text3)', fontSize: 12,
                        fontFamily: 'var(--mono)', padding: '20px 0' }}>Loading…</div>
        )}

        {!loading && rules.length === 0 && !showForm && (
          <div className="empty" style={{ height: 160 }}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
              <circle cx="12" cy="12" r="10"/>
              <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
            </svg>
            <div>No suppression rules</div>
            <div style={{ fontSize: 11 }}>Add rules to silence known-noisy signatures</div>
          </div>
        )}

        {!loading && rules.map(rule => {
          const expired = rule.expires_at && Date.now() / 1000 > rule.expires_at;
          return (
            <div key={rule.id} style={{
              background: 'var(--bg1)', border: '1px solid var(--border)',
              borderRadius: 'var(--radius-lg)', padding: '14px 16px', marginBottom: 10,
              opacity: (!rule.enabled || expired) ? 0.55 : 1,
              borderLeft: `3px solid ${
                expired ? 'var(--text3)' :
                rule.enabled ? 'var(--red)' : 'var(--border2)'}`,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
                <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text1)' }}>
                  {rule.name}
                </span>
                {expired && (
                  <span style={{
                    fontSize: 9, fontFamily: 'var(--mono)', padding: '2px 7px',
                    borderRadius: 20, background: 'var(--bg3)', color: 'var(--text3)',
                    border: '1px solid var(--border)', letterSpacing: '.06em',
                  }}>EXPIRED</span>
                )}
                {!expired && (
                  <span style={{
                    fontSize: 9, fontFamily: 'var(--mono)', padding: '2px 7px',
                    borderRadius: 20, letterSpacing: '.06em',
                    background: rule.enabled ? 'var(--red-d)' : 'var(--bg3)',
                    color: rule.enabled ? 'var(--red)' : 'var(--text3)',
                    border: `1px solid ${rule.enabled ? 'rgba(240,84,84,.3)' : 'var(--border)'}`,
                  }}>{rule.enabled ? 'ACTIVE' : 'DISABLED'}</span>
                )}
                <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
                  {role === 'admin' && (
                    <div onClick={() => toggleEnabled(rule)} style={{
                      width: 32, height: 18, borderRadius: 9, cursor: 'pointer',
                      background: rule.enabled && !expired ? 'var(--red)' : 'var(--bg3)',
                      position: 'relative', transition: 'background .2s',
                      border: '1px solid var(--border2)',
                    }}>
                      <div style={{
                        position: 'absolute', top: 2,
                        left: rule.enabled ? 14 : 2,
                        width: 12, height: 12, borderRadius: '50%',
                        background: 'white', transition: 'left .2s',
                      }}/>
                    </div>
                  )}
                </div>
              </div>

              {/* Match conditions */}
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 10 }}>
                {rule.sig_id && (
                  <div style={{
                    display: 'flex', alignItems: 'center', gap: 5,
                    padding: '3px 10px', borderRadius: 'var(--radius-sm)',
                    background: 'var(--bg2)', border: '1px solid var(--border)',
                    fontSize: 11, fontFamily: 'var(--mono)',
                  }}>
                    <span style={{ color: 'var(--text3)' }}>SID</span>
                    <span style={{ color: 'var(--accent)' }}>{rule.sig_id}</span>
                  </div>
                )}
                {rule.src_ip && (
                  <div style={{
                    display: 'flex', alignItems: 'center', gap: 5,
                    padding: '3px 10px', borderRadius: 'var(--radius-sm)',
                    background: 'var(--bg2)', border: '1px solid var(--border)',
                    fontSize: 11, fontFamily: 'var(--mono)',
                  }}>
                    <span style={{ color: 'var(--text3)' }}>IP</span>
                    <span style={{ color: 'var(--teal)' }}>{rule.src_ip}</span>
                  </div>
                )}
                {rule.category && (
                  <div style={{
                    display: 'flex', alignItems: 'center', gap: 5,
                    padding: '3px 10px', borderRadius: 'var(--radius-sm)',
                    background: 'var(--bg2)', border: '1px solid var(--border)',
                    fontSize: 11, fontFamily: 'var(--mono)',
                  }}>
                    <span style={{ color: 'var(--text3)' }}>CAT</span>
                    <span style={{ color: 'var(--yellow)' }}>{rule.category}</span>
                  </div>
                )}
              </div>

              {rule.reason && (
                <div style={{ fontSize: 11, color: 'var(--text2)', fontStyle: 'italic',
                              marginBottom: 10, lineHeight: 1.5 }}>
                  "{rule.reason}"
                </div>
              )}

              <div style={{ display: 'flex', alignItems: 'center', gap: 16,
                            fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--text3)' }}>
                <span>by {rule.created_by || 'system'}</span>
                <span>created {fmtDate(rule.created_at)}</span>
                {rule.expires_at && (
                  <span style={{ color: expired ? 'var(--red)' : 'var(--text3)' }}>
                    expires {fmtDate(rule.expires_at)}
                  </span>
                )}
                {role === 'admin' && (
                  <div style={{ marginLeft: 'auto', display: 'flex', gap: 7 }}>
                    <button className="btn" style={{ fontSize: 11 }}
                            onClick={() => { setEditing(rule); setShowForm(true); }}>Edit</button>
                    <button className="btn-danger" style={{ fontSize: 11 }}
                            onClick={() => setDelId(rule.id)}>Delete</button>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {delId !== null && (
        <div className="modal-bg" onClick={() => setDelId(null)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div style={{ fontSize: 15, fontWeight: 500, marginBottom: 10 }}>
              Delete suppression rule?
            </div>
            <div style={{ fontSize: 12, color: 'var(--text2)', marginBottom: 24 }}>
              Matching alerts will start appearing again immediately.
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

// ── SuppressionForm ───────────────────────────────────────────────────────────
function SuppressionForm({ existing, onSaved, onCancel }) {
  const [name,     setName]     = useState(existing?.name     || '');
  const [sigId,    setSigId]    = useState(existing?.sig_id   ? String(existing.sig_id) : '');
  const [srcIp,    setSrcIp]    = useState(existing?.src_ip   || '');
  const [category, setCategory] = useState(existing?.category || '');
  const [reason,   setReason]   = useState(existing?.reason   || '');
  const [expires,  setExpires]  = useState(
    existing?.expires_at
      ? new Date(existing.expires_at * 1000).toISOString().split('T')[0]
      : ''
  );
  const [saving, setSaving] = useState(false);
  const [err,    setErr]    = useState('');

  async function save() {
    if (!name.trim()) { setErr('Name is required'); return; }
    if (!sigId && !srcIp.trim() && !category.trim()) {
      setErr('At least one of SID, Source IP, or Category is required'); return;
    }
    setSaving(true); setErr('');
    const body = {
      name:       name.trim(),
      sig_id:     sigId ? parseInt(sigId) : null,
      src_ip:     srcIp.trim()    || null,
      category:   category.trim() || null,
      reason:     reason.trim()   || null,
      expires_at: expires ? new Date(expires).getTime() / 1000 : null,
    };
    const method   = existing?.id ? 'PUT'  : 'POST';
    const endpoint = existing?.id ? `/suppression/${existing.id}` : '/suppression';
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
        {existing?.id ? 'Edit Rule' : 'New Suppression Rule'}
      </div>

      <div style={{ marginBottom: 12 }}>
        <label style={labelStyle}>Rule Name</label>
        <input style={inputStyle} placeholder="e.g. Ignore ICMP from monitoring host"
               value={name} onChange={e => setName(e.target.value)}/>
      </div>

      <div style={{ marginBottom: 8, fontSize: 10, color: 'var(--text3)',
                    fontFamily: 'var(--mono)', letterSpacing: '.06em',
                    textTransform: 'uppercase', paddingBottom: 6,
                    borderBottom: '1px solid var(--border)' }}>
        Match Conditions (AND logic — all filled fields must match)
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10,
                    margin: '12px 0' }}>
        <div>
          <label style={labelStyle}>SID</label>
          <input style={{ ...inputStyle, fontFamily: 'var(--mono)' }}
                 type="number" placeholder="e.g. 2100498"
                 value={sigId} onChange={e => setSigId(e.target.value)}/>
        </div>
        <div>
          <label style={labelStyle}>Source IP</label>
          <input style={{ ...inputStyle, fontFamily: 'var(--mono)' }}
                 placeholder="e.g. 192.168.1.10"
                 value={srcIp} onChange={e => setSrcIp(e.target.value)}/>
        </div>
        <div>
          <label style={labelStyle}>Category</label>
          <input style={inputStyle} placeholder="e.g. not-suspicious"
                 value={category} onChange={e => setCategory(e.target.value)}/>
        </div>
      </div>

      <div style={{ marginBottom: 12 }}>
        <label style={labelStyle}>Reason (optional)</label>
        <input style={inputStyle}
               placeholder="Why is this being suppressed?"
               value={reason} onChange={e => setReason(e.target.value)}/>
      </div>

      <div style={{ marginBottom: 16 }}>
        <label style={labelStyle}>Expires On (optional — leave blank for permanent)</label>
        <input style={inputStyle} type="date"
               value={expires} onChange={e => setExpires(e.target.value)}/>
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
          border: '1px solid var(--red)', background: 'var(--red-d)',
          color: 'var(--red)', fontSize: 12, cursor: saving ? 'wait' : 'pointer',
        }}>{saving ? 'Saving…' : existing?.id ? 'Save Changes' : 'Create Rule'}</button>
      </div>
    </div>
  );
}
