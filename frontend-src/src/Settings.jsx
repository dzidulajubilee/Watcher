import { useState, useEffect, useRef } from 'react';
import { ThreatIntelPanel } from './ThreatIntel.jsx';
import { SuppressionPanel } from './Suppression.jsx';

const SEV_OPTIONS   = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_COLORS_WH = {
  critical: 'var(--red)', high: 'var(--orange)',
  medium:   'var(--yellow)', low: 'var(--green)', info: 'var(--accent)',
};

// ── UserForm ──────────────────────────────────────────────────────────────────
function UserForm({ initial, onSave, onCancel }) {
  const editing = !!initial?.id;
  const [username, setUsername] = useState(initial?.username || '');
  const [password, setPassword] = useState('');
  const [role,     setRole]     = useState(initial?.role || 'analyst');
  const [enabled,  setEnabled]  = useState(initial?.enabled !== false);
  const [saving,   setSaving]   = useState(false);
  const [err,      setErr]      = useState('');

  const ROLE_INFO = {
    admin:   'Full access — all views, clear data, manage users & webhooks',
    analyst: 'Read-only — all views, no destructive actions',
    viewer:  'Stream only — alert list, no detail panel or controls',
  };

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

  return (
    <div className="modal-bg" onClick={onCancel}>
      <div className="modal" style={{ width:440, maxWidth:'95vw' }}
           onClick={e => e.stopPropagation()}>
        <div style={{ fontSize:15, fontWeight:500, marginBottom:20 }}>
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
          <select className="form-input" value={role} onChange={e => setRole(e.target.value)}>
            <option value="admin">Admin</option>
            <option value="analyst">Analyst</option>
            <option value="viewer">Viewer</option>
          </select>
          <span style={{ fontSize:11, color:'var(--text3)', marginTop:3 }}>{ROLE_INFO[role]}</span>
        </div>

        {editing && (
          <div className="form-row">
            <label className="form-label">Status</label>
            <label style={{ display:'flex', alignItems:'center', gap:8, cursor:'pointer', width:'fit-content' }}>
              <div className="toggle">
                <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)}/>
                <div className="toggle-track"/>
                <div className="toggle-thumb"/>
              </div>
              <span style={{ fontSize:12, color:'var(--text2)' }}>{enabled ? 'Active' : 'Disabled'}</span>
            </label>
          </div>
        )}

        {err && <div className="wh-error">{err}</div>}

        <div style={{ display:'flex', gap:10, justifyContent:'flex-end', marginTop:20 }}>
          <button className="btn" onClick={onCancel} disabled={saving} style={{ minWidth:80 }}>Cancel</button>
          <button className="btn on" onClick={save} disabled={saving} style={{ minWidth:80 }}>
            {saving ? 'Saving…' : editing ? 'Save' : 'Create'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── WebhookForm ───────────────────────────────────────────────────────────────
function WebhookForm({ initial, onSave, onCancel }) {
  const blank = { name:'', type:'generic', url:'', enabled:true,
                  severities:['critical','high','medium','low','info'] };
  const [form,   setForm]   = useState(initial || blank);
  const [saving, setSaving] = useState(false);
  const [error,  setError]  = useState('');

  function toggleSev(s) {
    setForm(f => ({
      ...f,
      severities: f.severities.includes(s)
        ? f.severities.filter(x => x !== s)
        : [...f.severities, s],
    }));
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
        method, headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      });
      const data = await r.json();
      if (!r.ok) { setError(data.error || 'Save failed.'); return; }
      onSave(data);
    } catch { setError('Network error.'); }
    finally { setSaving(false); }
  }

  const inputStyle = {
    width:'100%', padding:'8px 10px',
    background:'var(--bg2)', border:'1px solid var(--border2)',
    borderRadius:'var(--radius-sm)', color:'var(--text1)',
    fontSize:12, fontFamily:'var(--sans)', outline:'none',
  };
  const labelStyle = {
    display:'block', fontSize:10, fontWeight:600,
    letterSpacing:'.09em', textTransform:'uppercase',
    color:'var(--text3)', marginBottom:5,
  };

  return (
    <div style={{ background:'var(--bg2)', border:'1px solid var(--border2)',
                  borderRadius:'var(--radius-lg)', padding:20, marginBottom:16 }}>
      <div style={{ fontSize:13, fontWeight:500, marginBottom:16 }}>
        {form.id ? 'Edit Webhook' : 'New Webhook'}
      </div>

      <div style={{ marginBottom:14 }}>
        <label style={labelStyle}>Name</label>
        <input style={inputStyle} placeholder="e.g. Security Alerts"
               value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}/>
      </div>

      <div style={{ marginBottom:14 }}>
        <label style={labelStyle}>Type</label>
        <select style={{ ...inputStyle, cursor:'pointer' }}
                value={form.type} onChange={e => setForm(f => ({ ...f, type: e.target.value }))}>
          <option value="slack">Slack</option>
          <option value="discord">Discord</option>
          <option value="generic">Generic / Other (Teams, Mattermost, custom…)</option>
        </select>
      </div>

      <div style={{ marginBottom:14 }}>
        <label style={labelStyle}>Webhook URL</label>
        <input style={{ ...inputStyle, fontFamily:'var(--mono)', fontSize:11 }}
               placeholder={
                 form.type === 'slack'   ? 'https://hooks.slack.com/services/…' :
                 form.type === 'discord' ? 'https://discord.com/api/webhooks/…' :
                                          'https://your-endpoint.com/webhook'}
               value={form.url} onChange={e => setForm(f => ({ ...f, url: e.target.value }))}/>
      </div>

      <div style={{ marginBottom:14 }}>
        <label style={labelStyle}>Trigger on Severities</label>
        <div style={{ display:'flex', gap:8, flexWrap:'wrap' }}>
          {SEV_OPTIONS.map(s => {
            const on = form.severities.includes(s);
            return (
              <div key={s} onClick={() => toggleSev(s)} style={{
                display:'flex', alignItems:'center', gap:5, padding:'4px 10px',
                borderRadius:20, border:`1px solid ${on ? SEV_COLORS_WH[s] : 'var(--border)'}`,
                background: on ? `${SEV_COLORS_WH[s]}18` : 'transparent',
                color: on ? SEV_COLORS_WH[s] : 'var(--text3)',
                fontSize:11, fontFamily:'var(--mono)', cursor:'pointer',
                userSelect:'none', transition:'all .15s', textTransform:'uppercase',
              }}>
                <div style={{ width:6, height:6, borderRadius:'50%',
                              background: on ? SEV_COLORS_WH[s] : 'var(--text3)' }}/>
                {s}
              </div>
            );
          })}
        </div>
      </div>

      <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:16 }}>
        <div onClick={() => setForm(f => ({ ...f, enabled: !f.enabled }))} style={{
          width:34, height:18, borderRadius:9,
          background: form.enabled ? 'var(--green)' : 'var(--bg3)',
          position:'relative', cursor:'pointer', transition:'background .2s',
          border:'1px solid var(--border2)',
        }}>
          <div style={{
            position:'absolute', top:2, left: form.enabled ? 17 : 2,
            width:12, height:12, borderRadius:'50%',
            background:'white', transition:'left .2s',
          }}/>
        </div>
        <span style={{ fontSize:12, color:'var(--text2)' }}>
          {form.enabled ? 'Enabled' : 'Disabled'}
        </span>
      </div>

      {error && (
        <div style={{ marginBottom:12, padding:'7px 10px', borderRadius:5,
                      background:'var(--red-d)', border:'1px solid var(--red)',
                      color:'var(--red)', fontSize:12 }}>{error}</div>
      )}

      <div style={{ display:'flex', gap:8, justifyContent:'flex-end' }}>
        <button className="btn" onClick={onCancel} disabled={saving}>Cancel</button>
        <button onClick={handleSave} disabled={saving} style={{
          padding:'4px 14px', borderRadius:'var(--radius-sm)',
          border:'1px solid var(--accent)', background:'var(--accent-d)',
          color:'var(--accent)', fontSize:11, fontFamily:'var(--sans)',
          cursor: saving ? 'wait' : 'pointer',
        }}>{saving ? 'Saving…' : form.id ? 'Save Changes' : 'Create Webhook'}</button>
      </div>
    </div>
  );
}

// ── WebhookCard ───────────────────────────────────────────────────────────────
function WebhookCard({ wh, onEdit, onDelete }) {
  const [testing,    setTesting]    = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [delConfirm, setDelConfirm] = useState(false);

  async function handleTest() {
    setTesting(true); setTestResult(null);
    try {
      const r = await fetch(`/webhooks/${wh.id}/test`, { method:'POST' });
      const d = await r.json();
      setTestResult(d.ok ? 'ok' : (d.error || 'failed'));
    } catch { setTestResult('Network error'); }
    finally { setTesting(false); }
  }

  const firedAt = wh.last_fired
    ? new Date(wh.last_fired * 1000).toLocaleString('en-GB', { hour12:false })
    : 'Never';

  return (
    <div style={{ background:'var(--bg1)', border:'1px solid var(--border)',
                  borderRadius:'var(--radius-lg)', padding:'14px 16px', marginBottom:10,
                  borderLeft:`3px solid ${wh.enabled ? 'var(--green)' : 'var(--border2)'}` }}>
      <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:10 }}>
        <div style={{ padding:'2px 8px', borderRadius:4, background:'var(--bg3)',
                      border:'1px solid var(--border)', fontSize:10, fontFamily:'var(--mono)',
                      color:'var(--text2)', textTransform:'uppercase' }}>{wh.type}</div>
        <span style={{ fontSize:13, fontWeight:500, color:'var(--text1)' }}>{wh.name}</span>
        <div style={{ marginLeft:'auto', padding:'2px 8px', borderRadius:10, fontSize:10,
                      background: wh.enabled ? 'var(--green-d)' : 'var(--bg3)',
                      color: wh.enabled ? 'var(--green)' : 'var(--text3)',
                      border:`1px solid ${wh.enabled ? 'var(--green)' : 'var(--border)'}`,
                      fontFamily:'var(--mono)' }}>{wh.enabled ? 'ENABLED' : 'DISABLED'}</div>
      </div>

      <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text3)',
                    background:'var(--bg2)', padding:'5px 8px', borderRadius:4,
                    marginBottom:10, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
        {wh.url}
      </div>

      <div style={{ display:'flex', gap:5, flexWrap:'wrap', marginBottom:10 }}>
        {SEV_OPTIONS.map(s => {
          const on = (wh.severities || []).includes(s);
          return (
            <span key={s} style={{
              padding:'1px 7px', borderRadius:10, fontSize:10,
              fontFamily:'var(--mono)', textTransform:'uppercase',
              background: on ? `${SEV_COLORS_WH[s]}18` : 'transparent',
              color: on ? SEV_COLORS_WH[s] : 'var(--text3)',
              border:`1px solid ${on ? SEV_COLORS_WH[s] : 'var(--border)'}`,
              opacity: on ? 1 : 0.4,
            }}>{s}</span>
          );
        })}
      </div>

      <div style={{ display:'flex', alignItems:'center', gap:16, fontSize:10,
                    fontFamily:'var(--mono)', color:'var(--text3)', marginBottom:12 }}>
        <span>Fired: <b style={{ color:'var(--text2)' }}>{wh.fire_count || 0}</b></span>
        <span>Last: <b style={{ color:'var(--text2)' }}>{firedAt}</b></span>
        {wh.last_error && (
          <span style={{ color:'var(--red)', marginLeft:'auto' }}>⚠ {wh.last_error.slice(0,60)}</span>
        )}
      </div>

      {testResult && (
        <div style={{ marginBottom:10, padding:'6px 10px', borderRadius:5, fontSize:11,
                      background: testResult==='ok' ? 'var(--green-d)' : 'var(--red-d)',
                      border:`1px solid ${testResult==='ok' ? 'var(--green)' : 'var(--red)'}`,
                      color: testResult==='ok' ? 'var(--green)' : 'var(--red)' }}>
          {testResult === 'ok' ? '✓ Test delivered successfully' : `✗ ${testResult}`}
        </div>
      )}

      <div style={{ display:'flex', gap:7 }}>
        <button className="btn" onClick={handleTest} disabled={testing} style={{ fontSize:11 }}>
          {testing ? 'Sending…' : 'Test'}
        </button>
        <button className="btn" onClick={() => onEdit(wh)} style={{ fontSize:11 }}>Edit</button>
        {!delConfirm ? (
          <button className="btn" onClick={() => setDelConfirm(true)}
                  style={{ fontSize:11, marginLeft:'auto' }}>Delete</button>
        ) : (
          <div style={{ display:'flex', gap:6, marginLeft:'auto', alignItems:'center' }}>
            <span style={{ fontSize:11, color:'var(--text3)' }}>Confirm?</span>
            <button className="btn" onClick={() => setDelConfirm(false)} style={{ fontSize:11 }}>Cancel</button>
            <button onClick={() => onDelete(wh.id)} style={{
              padding:'4px 10px', borderRadius:'var(--radius-sm)',
              border:'1px solid var(--red)', background:'var(--red-d)',
              color:'var(--red)', fontSize:11, fontFamily:'var(--sans)', cursor:'pointer',
            }}>Delete</button>
          </div>
        )}
      </div>
    </div>
  );
}

// ── WebhooksView ──────────────────────────────────────────────────────────────
function WebhooksView({ webhooks, onRefresh, triggerNew }) {
  const [showForm, setShowForm] = useState(false);
  const [editing,  setEditing]  = useState(null);
  const mounted = useRef(false);

  useEffect(() => {
    if (!mounted.current) { mounted.current = true; return; }
    if (triggerNew !== undefined) { setEditing(null); setShowForm(true); }
  }, [triggerNew]);

  async function handleDelete(id) {
    await fetch(`/webhooks/${id}`, { method:'DELETE' }).catch(() => {});
    onRefresh();
  }

  function handleSaved() { setShowForm(false); setEditing(null); onRefresh(); }

  return (
    <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }}>
      <div style={{ flex:1, overflowY:'auto', padding:20 }}>
        <div style={{ background:'var(--accent-d)', border:'1px solid rgba(79,156,249,.2)',
                      borderRadius:'var(--radius-md)', padding:'10px 14px',
                      fontSize:12, color:'var(--text2)', marginBottom:20, lineHeight:1.7 }}>
          <b style={{ color:'var(--accent)' }}>Webhooks</b> send a POST request to your URL whenever
          a matching alert fires. Choose <b style={{ color:'var(--text1)' }}>Slack</b> or{' '}
          <b style={{ color:'var(--text1)' }}>Discord</b> for formatted messages, or{' '}
          <b style={{ color:'var(--text1)' }}>Generic</b> for a plain JSON payload compatible
          with Teams, Mattermost, or any custom endpoint.
        </div>

        {showForm && (
          <WebhookForm
            initial={editing}
            onSave={handleSaved}
            onCancel={() => { setShowForm(false); setEditing(null); }}
          />
        )}

        {webhooks.length === 0 && !showForm && (
          <div className="empty" style={{ height:200 }}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
              <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
              <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
            </svg>
            <div>No webhooks configured</div>
            <div style={{ fontSize:11 }}>Click "+ Add Webhook" above to get started</div>
          </div>
        )}

        {webhooks.map(wh => (
          <WebhookCard
            key={wh.id} wh={wh}
            onEdit={w => { setEditing(w); setShowForm(true); }}
            onDelete={handleDelete}
          />
        ))}
      </div>
    </div>
  );
}

// ── SettingsView ──────────────────────────────────────────────────────────────
export function SettingsView({ currentUser, webhooks, onRefreshWebhooks, role }) {
  const [tab,      setTab]      = useState('users');
  const [triggerNew, setTriggerNew] = useState(false);
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
    await fetch(`/users/${uid}`, { method:'DELETE' });
    setUsers(prev => prev.filter(u => u.id !== uid));
    setDelId(null);
  }

  const ROLE_COLOR = { admin:'var(--accent)', analyst:'var(--green)', viewer:'var(--text3)' };
  const fmtDate = ts => ts
    ? new Date(ts * 1000).toLocaleDateString(undefined, { month:'short', day:'numeric', year:'numeric' })
    : 'Never';

  return (
    <div style={{ display:'flex', flexDirection:'column', overflow:'hidden', flex:1 }}>
      <div className="pane-head">
        <span className="pane-title">Settings</span>
        <div style={{ display:'flex', gap:1, background:'var(--bg2)',
                      border:'1px solid var(--border)', borderRadius:'var(--radius-sm)',
                      padding:2, marginLeft:10 }}>
          {[{ id:'users', label:'Users' }, { id:'webhooks', label:'Webhooks' }, { id:'threat-intel', label:'Threat Intel' }, { id:'suppression', label:'Suppression' }].map(t => (
            <button key={t.id} onClick={() => setTab(t.id)} style={{
              padding:'2px 12px', borderRadius:'var(--radius-sm)', border:'none',
              background: tab===t.id ? 'var(--accent)' : 'transparent',
              color:      tab===t.id ? 'white' : 'var(--text3)',
              fontSize:11, fontFamily:'var(--mono)', cursor:'pointer', transition:'all .15s',
            }}>{t.label}</button>
          ))}
        </div>
        <div className="pane-actions">
          {tab === 'users' && (
            <button className="btn-add" onClick={() => { setEditing(null); setShowForm(true); }}>
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="6" y1="1" x2="6" y2="11"/><line x1="1" y1="6" x2="11" y2="6"/>
              </svg>
              Add user
            </button>
          )}
          {tab === 'webhooks' && (
            <button className="btn-add" onClick={() => setTriggerNew(t => !t)}>
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="6" y1="1" x2="6" y2="11"/><line x1="1" y1="6" x2="11" y2="6"/>
              </svg>
              Add webhook
            </button>
          )}
        </div>
      </div>

      <div className="wh-panel">
        {tab === 'webhooks' && (
          <WebhooksView webhooks={webhooks} onRefresh={onRefreshWebhooks} triggerNew={triggerNew}/>
        )}

        {tab === 'threat-intel' && (
          <ThreatIntelPanel role={role}/>
        )}
        {tab === 'suppression' && (
          <SuppressionPanel role={role}/>
        )}
        {tab === 'users' && (<>
          <div className="wh-section">
            <div className="wh-section-title">User Accounts</div>
            {loading && <div style={{ color:'var(--text3)', fontSize:12, fontFamily:'var(--mono)', padding:'20px 0' }}>Loading…</div>}
            {!loading && users.map(u => (
              <div key={u.id} className="wh-card" style={{ opacity: u.enabled ? 1 : 0.55 }}>
                <div className="wh-card-header">
                  <div style={{
                    width:30, height:30, borderRadius:'50%',
                    background:`${ROLE_COLOR[u.role]}22`, border:`1px solid ${ROLE_COLOR[u.role]}44`,
                    display:'flex', alignItems:'center', justifyContent:'center',
                    fontFamily:'var(--mono)', fontSize:12, fontWeight:600,
                    color:ROLE_COLOR[u.role], flexShrink:0,
                  }}>{u.username[0].toUpperCase()}</div>
                  <div>
                    <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                      <span className="wh-name">{u.username}</span>
                      {u.username === currentUser && (
                        <span style={{ fontSize:9, fontFamily:'var(--mono)', color:'var(--accent)', letterSpacing:'.06em' }}>YOU</span>
                      )}
                      {!u.enabled && (
                        <span style={{ fontSize:9, fontFamily:'var(--mono)', color:'var(--text3)', letterSpacing:'.06em' }}>DISABLED</span>
                      )}
                    </div>
                    <div style={{ fontSize:10, fontFamily:'var(--mono)', color:ROLE_COLOR[u.role],
                                  letterSpacing:'.06em', textTransform:'uppercase', marginTop:2 }}>{u.role}</div>
                  </div>
                  <div style={{ marginLeft:'auto', fontSize:10, fontFamily:'var(--mono)',
                                color:'var(--text3)', textAlign:'right' }}>
                    <div>Created {fmtDate(u.created_at)}</div>
                    <div>Last login {fmtDate(u.last_login)}</div>
                  </div>
                </div>
                <div className="wh-footer">
                  <button className="btn-test" onClick={() => { setEditing(u); setShowForm(true); }}>Edit</button>
                  {u.username !== currentUser && (
                    <button className="btn-danger" onClick={() => setDelId(u.id)}>Delete</button>
                  )}
                </div>
              </div>
            ))}
          </div>

          <div className="wh-section">
            <div className="wh-section-title">Role Permissions</div>
            <div style={{ display:'grid', gridTemplateColumns:'1fr 60px 70px 60px', gap:'0 12px', fontSize:11 }}>
              {['Permission','Admin','Analyst','Viewer'].map((h, i) => (
                <div key={i} style={{ color:'var(--text3)', fontWeight:600, textTransform:'uppercase',
                                      letterSpacing:'.08em', fontSize:9, paddingBottom:6,
                                      borderBottom:'1px solid var(--border)',
                                      textAlign: i > 0 ? 'center' : 'left' }}>{h}</div>
              ))}
              {[
                ['View alerts / flows / DNS / charts', true, true, true],
                ['Alert detail panel',                 true, true, false],
                ['Search & severity filter',           true, true, false],
                ['Pause / Resume stream',              true, true, false],
                ['Clear alerts / flows',               true, false, false],
                ['Webhook notifications',              true, false, false],
                ['User management',                    true, false, false],
              ].map(([label, a, b, c]) => [
                <div key={label} style={{ color:'var(--text2)', padding:'5px 0', borderBottom:'1px solid var(--border)' }}>{label}</div>,
                ...[a,b,c].map((ok, i) => (
                  <div key={i} style={{ textAlign:'center', padding:'5px 0', borderBottom:'1px solid var(--border)',
                                        color: ok ? 'var(--green)' : 'var(--red)', fontSize:13 }}>
                    {ok ? '✓' : '✗'}
                  </div>
                ))
              ])}
            </div>
          </div>
        </>)}
      </div>

      {showForm && (
        <UserForm initial={editing} onSave={onSaved}
                  onCancel={() => { setShowForm(false); setEditing(null); }}/>
      )}

      {delId !== null && (
        <div className="modal-bg" onClick={() => setDelId(null)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div style={{ fontSize:15, fontWeight:500, marginBottom:10 }}>Delete user?</div>
            <div style={{ fontSize:12, color:'var(--text2)', marginBottom:24, lineHeight:1.7 }}>
              This user will be permanently removed and immediately logged out.
            </div>
            <div style={{ display:'flex', gap:10, justifyContent:'flex-end' }}>
              <button className="btn" onClick={() => setDelId(null)} style={{ minWidth:80 }}>Cancel</button>
              <button className="btn-danger" onClick={() => deleteUser(delId)}
                      style={{ padding:'4px 14px', borderRadius:'var(--radius-sm)' }}>Delete</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
