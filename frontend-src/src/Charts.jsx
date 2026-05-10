import { useState, useEffect } from 'react';

const CHART_SEV_COLORS = {
  critical: '#f05454', high: '#f5944a',
  medium:   '#f5c842', low:  '#4caf82', info: '#4f9cf9',
};

const CAT_PALETTE = [
  '#4f9cf9','#f5944a','#9f7aea','#2dd4bf','#f5c842',
  '#f05454','#4caf82','#e879f9','#60a5fa','#a3e635',
  '#fb923c','#94a3b8',
];

function ChartEmpty({ message = 'No data for this period' }) {
  return (
    <div style={{ display:'flex', flexDirection:'column', alignItems:'center',
                  justifyContent:'center', height:'100%', gap:10,
                  color:'var(--text3)', fontSize:12 }}>
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

function TopTalkersChart({ data }) {
  if (!data || data.length === 0) return <ChartEmpty/>;
  const max = data[0].count;
  return (
    <div style={{ padding:'4px 0', overflow:'hidden' }}>
      {data.map((row, i) => {
        const pct = max > 0 ? (row.count / max) * 100 : 0;
        return (
          <div key={row.ip} style={{
            display:'grid', gridTemplateColumns:'130px 1fr 52px',
            alignItems:'center', gap:10, padding:'5px 0',
            borderBottom: i < data.length - 1 ? '1px solid var(--border)' : 'none',
          }}>
            <div style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--text2)',
                          overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap',
                          textAlign:'right' }}>{row.ip}</div>
            <div style={{ position:'relative', height:18, background:'var(--bg2)',
                          borderRadius:3, overflow:'hidden' }}>
              <div style={{
                position:'absolute', inset:'0 auto 0 0', width:`${pct}%`,
                background:'linear-gradient(90deg, var(--accent), var(--accent) 60%, rgba(79,156,249,.5))',
                borderRadius:3, transition:'width .4s ease',
              }}/>
              <div style={{ position:'absolute', inset:0, display:'flex',
                            alignItems:'center', paddingLeft:8,
                            fontFamily:'var(--mono)', fontSize:10, color:'white',
                            mixBlendMode:'screen' }}>{pct.toFixed(0)}%</div>
            </div>
            <div style={{ fontFamily:'var(--mono)', fontSize:11,
                          color:'var(--text1)', textAlign:'right' }}>
              {row.count.toLocaleString()}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function TrendChart({ data }) {
  if (!data || data.length === 0) return <ChartEmpty/>;

  const W = 560, H = 140, PAD = { t:16, r:16, b:32, l:44 };
  const iW = W - PAD.l - PAD.r;
  const iH = H - PAD.t - PAD.b;
  const maxVal = Math.max(1, ...data.map(d => d.count));
  const yMax   = Math.ceil(maxVal / 5) * 5 || 5;
  const yTicks = [0, Math.round(yMax*.25), Math.round(yMax*.5), Math.round(yMax*.75), yMax];

  const xPos = i => PAD.l + (i / (data.length - 1)) * iW;
  const yPos = v => PAD.t + iH - (v / yMax) * iH;
  const pts  = data.map((d, i) => `${xPos(i).toFixed(1)},${yPos(d.count).toFixed(1)}`);

  const linePath = `M ${pts.join(' L ')}`;
  const areaPath = `M ${xPos(0).toFixed(1)},${(PAD.t+iH).toFixed(1)} ` +
                   `L ${pts.join(' L ')} ` +
                   `L ${xPos(data.length-1).toFixed(1)},${(PAD.t+iH).toFixed(1)} Z`;

  const labelStep = Math.ceil(data.length / 8);
  const labelIndices = new Set();
  for (let i = 0; i < data.length; i++) { if (i % labelStep === 0) labelIndices.add(i); }
  const lastRegular = Math.floor((data.length - 1) / labelStep) * labelStep;
  if (data.length - 1 - lastRegular >= Math.ceil(labelStep / 2)) labelIndices.add(data.length - 1);

  return (
    <svg viewBox={`0 0 ${W} ${H}`} style={{ width:'100%', height:'auto', overflow:'visible' }}>
      <defs>
        <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%"   stopColor="var(--accent)" stopOpacity=".35"/>
          <stop offset="100%" stopColor="var(--accent)" stopOpacity=".02"/>
        </linearGradient>
      </defs>
      {yTicks.map(v => (
        <g key={v}>
          <line x1={PAD.l} y1={yPos(v)} x2={PAD.l+iW} y2={yPos(v)}
                stroke="var(--border)" strokeWidth="1"/>
          <text x={PAD.l-6} y={yPos(v)} textAnchor="end" dominantBaseline="middle"
                fontSize="9" fill="var(--text3)" fontFamily="var(--mono)">{v}</text>
        </g>
      ))}
      <path d={areaPath} fill="url(#areaGrad)"/>
      <path d={linePath} fill="none" stroke="var(--accent)"
            strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round"/>
      {data.map((d, i) => d.count > 0 && (
        <circle key={i} cx={xPos(i)} cy={yPos(d.count)} r="2.5"
                fill="var(--accent)" opacity=".8"/>
      ))}
      {data.map((d, i) => {
        if (!labelIndices.has(i)) return null;
        return (
          <text key={i} x={xPos(i)} y={H - 6} textAnchor="middle"
                fontSize="9" fill="var(--text3)" fontFamily="var(--mono)">{d.ts}</text>
        );
      })}
      <line x1={PAD.l} y1={PAD.t} x2={PAD.l} y2={PAD.t+iH} stroke="var(--border2)" strokeWidth="1"/>
      <line x1={PAD.l} y1={PAD.t+iH} x2={PAD.l+iW} y2={PAD.t+iH} stroke="var(--border2)" strokeWidth="1"/>
    </svg>
  );
}

function DonutChart({ data }) {
  if (!data || data.length === 0) return <ChartEmpty/>;
  const total = data.reduce((s, d) => s + d.count, 0);
  if (total === 0) return <ChartEmpty/>;

  const R = 70, r = 42, CX = 90, CY = 90;
  let angle = -Math.PI / 2;

  const slices = data.map((d, i) => {
    const sweep = (d.count / total) * 2 * Math.PI;
    const x1 = CX + R * Math.cos(angle), y1 = CY + R * Math.sin(angle);
    angle += sweep;
    const x2 = CX + R * Math.cos(angle), y2 = CY + R * Math.sin(angle);
    const xi1 = CX + r * Math.cos(angle), yi1 = CY + r * Math.sin(angle);
    angle -= sweep;
    const xi2 = CX + r * Math.cos(angle), yi2 = CY + r * Math.sin(angle);
    angle += sweep;
    const large = sweep > Math.PI ? 1 : 0;
    const path = `M ${x1.toFixed(2)} ${y1.toFixed(2)}
                  A ${R} ${R} 0 ${large} 1 ${x2.toFixed(2)} ${y2.toFixed(2)}
                  L ${xi1.toFixed(2)} ${yi1.toFixed(2)}
                  A ${r} ${r} 0 ${large} 0 ${xi2.toFixed(2)} ${yi2.toFixed(2)} Z`;
    return { ...d, path, color: CAT_PALETTE[i % CAT_PALETTE.length] };
  });

  return (
    <div style={{ display:'flex', alignItems:'center', gap:20, flexWrap:'wrap' }}>
      <svg viewBox="0 0 180 180" style={{ width:160, height:160, flexShrink:0 }}>
        {slices.map((s, i) => (
          <path key={i} d={s.path} fill={s.color} opacity=".85"
                style={{ transition:'opacity .15s' }}
                onMouseEnter={e => e.target.setAttribute('opacity','1')}
                onMouseLeave={e => e.target.setAttribute('opacity','.85')}/>
        ))}
        <text x={CX} y={CY-6} textAnchor="middle" fontSize="18" fontWeight="600"
              fill="var(--text1)" fontFamily="var(--mono)">{total.toLocaleString()}</text>
        <text x={CX} y={CY+10} textAnchor="middle" fontSize="8"
              fill="var(--text3)" fontFamily="var(--mono)" letterSpacing=".08em">ALERTS</text>
      </svg>
      <div style={{ flex:1, minWidth:120, display:'flex', flexDirection:'column', gap:6 }}>
        {slices.map((s, i) => (
          <div key={i} style={{ display:'flex', alignItems:'center', gap:7, fontSize:11 }}>
            <div style={{ width:8, height:8, borderRadius:2, background:s.color, flexShrink:0 }}/>
            <div style={{ flex:1, color:'var(--text2)', overflow:'hidden',
                          textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{s.category}</div>
            <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text3)' }}>
              {((s.count/total)*100).toFixed(1)}%
            </div>
            <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text1)',
                          minWidth:30, textAlign:'right' }}>{s.count}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function SeverityBars({ data }) {
  if (!data || data.length === 0) return <ChartEmpty/>;
  const total = data.reduce((s, d) => s + d.count, 0);
  if (total === 0) return <ChartEmpty/>;
  const order  = ['critical','high','medium','low','info'];
  const sorted = [...data].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));

  return (
    <div style={{ display:'flex', flexDirection:'column', gap:8, padding:'4px 0' }}>
      {sorted.map(row => {
        const pct   = (row.count / total) * 100;
        const color = CHART_SEV_COLORS[row.severity] || 'var(--accent)';
        return (
          <div key={row.severity} style={{ display:'grid', gridTemplateColumns:'70px 1fr 48px',
                                           alignItems:'center', gap:10 }}>
            <div style={{ fontFamily:'var(--mono)', fontSize:10, color,
                          textTransform:'uppercase', letterSpacing:'.05em', textAlign:'right' }}>
              {row.severity}
            </div>
            <div style={{ height:20, background:'var(--bg2)', borderRadius:3,
                          overflow:'hidden', position:'relative' }}>
              <div style={{ position:'absolute', inset:'0 auto 0 0', width:`${pct}%`,
                            background:color, opacity:.75, borderRadius:3, transition:'width .4s ease' }}/>
              <div style={{ position:'absolute', inset:0, display:'flex', alignItems:'center',
                            paddingLeft:8, fontFamily:'var(--mono)', fontSize:10, color:'white',
                            mixBlendMode:'screen' }}>{pct.toFixed(1)}%</div>
            </div>
            <div style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--text1)', textAlign:'right' }}>
              {row.count.toLocaleString()}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── BarTrendChart ─────────────────────────────────────────────────────────────
function BarTrendChart({ data }) {
  if (!data || data.length === 0) return <ChartEmpty/>;
  const W = 560, H = 140, PAD = { t:16, r:16, b:32, l:44 };
  const iW = W - PAD.l - PAD.r;
  const iH = H - PAD.t - PAD.b;
  const maxVal = Math.max(1, ...data.map(d => d.count));
  const yMax   = Math.ceil(maxVal / 5) * 5 || 5;
  const yTicks = [0, Math.round(yMax * .5), yMax];
  const barW   = Math.max(2, iW / data.length - 2);
  const gap    = iW / data.length;
  const labelStep = Math.ceil(data.length / 8);

  return (
    <svg viewBox={`0 0 ${W} ${H}`} style={{ width:'100%', height:'auto', overflow:'visible' }}>
      {yTicks.map(v => {
        const y = PAD.t + iH - (v / yMax) * iH;
        return (
          <g key={v}>
            <line x1={PAD.l} y1={y} x2={PAD.l + iW} y2={y}
                  stroke="var(--border)" strokeWidth="1" strokeDasharray={v===0?'0':'3 3'}/>
            <text x={PAD.l - 6} y={y} textAnchor="end" dominantBaseline="middle"
                  fontSize="9" fill="var(--text3)" fontFamily="var(--mono)">{v}</text>
          </g>
        );
      })}
      {data.map((d, i) => {
        const x   = PAD.l + i * gap + gap / 2 - barW / 2;
        const bh  = Math.max(1, (d.count / yMax) * iH);
        const y   = PAD.t + iH - bh;
        return (
          <g key={i}>
            <rect x={x} y={y} width={barW} height={bh} rx="1"
                  fill="var(--accent)" opacity={d.count > 0 ? '.8' : '.2'}
                  style={{ transition:'opacity .15s' }}
                  onMouseEnter={e => e.target.setAttribute('opacity','1')}
                  onMouseLeave={e => e.target.setAttribute('opacity', d.count > 0 ? '.8' : '.2')}/>
            {i % labelStep === 0 && (
              <text x={x + barW / 2} y={H - 6} textAnchor="middle"
                    fontSize="9" fill="var(--text3)" fontFamily="var(--mono)">{d.ts}</text>
            )}
          </g>
        );
      })}
      <line x1={PAD.l} y1={PAD.t} x2={PAD.l} y2={PAD.t + iH} stroke="var(--border2)" strokeWidth="1"/>
      <line x1={PAD.l} y1={PAD.t + iH} x2={PAD.l + iW} y2={PAD.t + iH} stroke="var(--border2)" strokeWidth="1"/>
    </svg>
  );
}

// ── PieTrendChart ─────────────────────────────────────────────────────────────
function PieTrendChart({ data }) {
  if (!data || data.length === 0) return <ChartEmpty/>;
  // Group into up to 8 meaningful time buckets — merge zeros into "Quiet"
  const nonZero = data.filter(d => d.count > 0);
  if (nonZero.length === 0) return <ChartEmpty message="No alerts in this period"/>;

  const total   = nonZero.reduce((s, d) => s + d.count, 0);
  const topN    = [...nonZero].sort((a, b) => b.count - a.count).slice(0, 8);
  const topSum  = topN.reduce((s, d) => s + d.count, 0);
  const rest    = total - topSum;
  const sliceData = rest > 0 ? [...topN, { ts:'Other', count: rest }] : topN;

  const R = 68, r = 0, CX = 88, CY = 88;   // solid pie (r=0)
  let angle = -Math.PI / 2;
  const [hovered, setHovered] = useState(null);

  const slices = sliceData.map((d, i) => {
    const sweep = (d.count / total) * 2 * Math.PI;
    const x1 = CX + R * Math.cos(angle), y1 = CY + R * Math.sin(angle);
    angle += sweep;
    const x2 = CX + R * Math.cos(angle), y2 = CY + R * Math.sin(angle);
    const large = sweep > Math.PI ? 1 : 0;
    const path = `M ${CX} ${CY} L ${x1.toFixed(2)} ${y1.toFixed(2)}
                  A ${R} ${R} 0 ${large} 1 ${x2.toFixed(2)} ${y2.toFixed(2)} Z`;
    return { ...d, path, color: CAT_PALETTE[i % CAT_PALETTE.length] };
  });

  return (
    <div style={{ display:'flex', alignItems:'center', gap:24, flexWrap:'wrap' }}>
      <svg viewBox="0 0 176 176" style={{ width:156, height:156, flexShrink:0 }}>
        {slices.map((s, i) => (
          <path key={i} d={s.path} fill={s.color}
                opacity={hovered === null || hovered === i ? '.9' : '.35'}
                style={{ transition:'opacity .15s', cursor:'default' }}
                onMouseEnter={() => setHovered(i)}
                onMouseLeave={() => setHovered(null)}/>
        ))}
        {hovered !== null && (
          <>
            <text x={CX} y={CY - 7} textAnchor="middle" fontSize="14" fontWeight="700"
                  fill="var(--text1)" fontFamily="var(--mono)">
              {slices[hovered].count}
            </text>
            <text x={CX} y={CY + 8} textAnchor="middle" fontSize="8"
                  fill="var(--text3)" fontFamily="var(--mono)">
              {((slices[hovered].count / total) * 100).toFixed(1)}%
            </text>
          </>
        )}
        {hovered === null && (
          <>
            <text x={CX} y={CY - 7} textAnchor="middle" fontSize="14" fontWeight="700"
                  fill="var(--text1)" fontFamily="var(--mono)">{total}</text>
            <text x={CX} y={CY + 8} textAnchor="middle" fontSize="8"
                  fill="var(--text3)" fontFamily="var(--mono)" letterSpacing=".06em">TOTAL</text>
          </>
        )}
      </svg>
      <div style={{ flex:1, minWidth:120, display:'flex', flexDirection:'column', gap:5 }}>
        {slices.map((s, i) => (
          <div key={i} style={{ display:'flex', alignItems:'center', gap:7, fontSize:11,
                                opacity: hovered === null || hovered === i ? 1 : .4,
                                transition:'opacity .15s', cursor:'default' }}
               onMouseEnter={() => setHovered(i)}
               onMouseLeave={() => setHovered(null)}>
            <div style={{ width:8, height:8, borderRadius:2, background:s.color, flexShrink:0 }}/>
            <div style={{ flex:1, color:'var(--text2)', overflow:'hidden',
                          textOverflow:'ellipsis', whiteSpace:'nowrap',
                          fontFamily:'var(--mono)', fontSize:10 }}>{s.ts}</div>
            <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text3)' }}>
              {((s.count / total) * 100).toFixed(1)}%
            </div>
            <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text1)',
                          minWidth:30, textAlign:'right' }}>{s.count}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── ChartTypeMenu ─────────────────────────────────────────────────────────────
const CHART_ICONS = {
  Trend: (
    <svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.8">
      <polyline points="1,12 5,7 9,9 15,3"/>
    </svg>
  ),
  Bar: (
    <svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.8">
      <rect x="1" y="9"  width="3" height="6" rx=".5"/>
      <rect x="6" y="5"  width="3" height="10" rx=".5"/>
      <rect x="11" y="2" width="3" height="13" rx=".5"/>
    </svg>
  ),
  Pie: (
    <svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.8">
      <circle cx="8" cy="8" r="6"/>
      <line x1="8" y1="8" x2="8" y2="2"/>
      <line x1="8" y1="8" x2="13.2" y2="11"/>
      <line x1="8" y1="8" x2="2" y2="11"/>
    </svg>
  ),
};

function ChartTypeMenu({ value, onChange }) {
  const [open, setOpen] = useState(false);
  const types = ['Trend', 'Bar'];

  return (
    <div style={{ position:'relative' }}>
      {/* Trigger button */}
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          display:'flex', alignItems:'center', gap:5,
          padding:'3px 10px 3px 8px',
          background:'var(--bg2)', border:'1px solid var(--border2)',
          borderRadius:'var(--radius-md)', cursor:'pointer',
          color:'var(--text2)', fontSize:11, fontFamily:'var(--mono)',
          transition:'border-color .15s',
        }}
        onMouseEnter={e => e.currentTarget.style.borderColor='var(--accent)'}
        onMouseLeave={e => e.currentTarget.style.borderColor='var(--border2)'}
      >
        <span style={{ color:'var(--accent)', display:'flex', alignItems:'center' }}>
          {CHART_ICONS[value]}
        </span>
        {value}
        {/* chevron */}
        <svg width="10" height="10" viewBox="0 0 10 10" fill="none"
             stroke="currentColor" strokeWidth="1.8"
             style={{ transform: open ? 'rotate(180deg)' : 'none', transition:'transform .15s' }}>
          <polyline points="2,3 5,7 8,3"/>
        </svg>
      </button>

      {/* Dropdown */}
      {open && (
        <>
          {/* Backdrop — mousedown+preventDefault ensures item clicks always register first */}
          <div style={{ position:'fixed', inset:0, zIndex:99 }}
               onMouseDown={e => { e.preventDefault(); setOpen(false); }}/>
          <div style={{
            position:'absolute', top:'calc(100% + 4px)', right:0, zIndex:100,
            background:'var(--bg2)', border:'1px solid var(--border2)',
            borderRadius:'var(--radius-md)', overflow:'hidden',
            boxShadow:'0 8px 24px rgba(0,0,0,.35)',
            minWidth:120,
          }}>
            {types.map(type => (
              <button key={type}
                onClick={() => { onChange(type); setOpen(false); }}
                style={{
                  display:'flex', alignItems:'center', gap:9, width:'100%',
                  padding:'8px 14px', border:'none', cursor:'pointer',
                  background: value === type ? 'rgba(79,156,249,.12)' : 'transparent',
                  color: value === type ? 'var(--accent)' : 'var(--text2)',
                  fontSize:12, fontFamily:'var(--mono)', textAlign:'left',
                  transition:'background .1s',
                }}
                onMouseEnter={e => { if (value !== type) e.currentTarget.style.background='var(--bg3)'; }}
                onMouseLeave={e => { if (value !== type) e.currentTarget.style.background='transparent'; }}
              >
                <span style={{ opacity: value === type ? 1 : .6, display:'flex', alignItems:'center' }}>
                  {CHART_ICONS[type]}
                </span>
                {type}
                {value === type && (
                  <span style={{ marginLeft:'auto', fontSize:10, color:'var(--accent)' }}>✓</span>
                )}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

// ── Card ─────────────────────────────────────────────────────────────────────
function Card({ title, subtitle, children, extra, isLoading = false }) {
  return (
    <div style={{ background:'var(--bg1)', border:'1px solid var(--border)',
                  borderRadius:'var(--radius-lg)', overflow:'hidden' }}>
      <div style={{ display:'flex', alignItems:'center', gap:8, padding:'12px 16px',
                    borderBottom:'1px solid var(--border)', background:'var(--bg1)' }}>
        <div>
          <div style={{ fontSize:12, fontWeight:500, color:'var(--text1)' }}>{title}</div>
          {subtitle && <div style={{ fontSize:10, color:'var(--text3)', marginTop:1,
                                     fontFamily:'var(--mono)' }}>{subtitle}</div>}
        </div>
        {extra && <div style={{ marginLeft:'auto' }}>{extra}</div>}
      </div>
      <div style={{ padding:'14px 16px', minHeight:120 }}>
        {isLoading
          ? <div style={{ display:'flex', alignItems:'center', justifyContent:'center',
                          height:120, color:'var(--text3)', fontSize:12,
                          fontFamily:'var(--mono)' }}>Loading…</div>
          : children}
      </div>
    </div>
  );
}

// ── SeverityPie ───────────────────────────────────────────────────────────────
function SeverityPie({ data }) {
  if (!data || data.length === 0) return <ChartEmpty/>;
  const total = data.reduce((s, d) => s + d.count, 0);
  if (total === 0) return <ChartEmpty/>;

  const order  = ['critical','high','medium','low','info'];
  const sorted = [...data].sort((a,b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  const [hovered, setHovered] = useState(null);

  const R = 90, CX = 110, CY = 110;
  let angle = -Math.PI / 2;
  const slices = sorted.map((d, i) => {
    const sweep = (d.count / total) * 2 * Math.PI;
    const x1 = CX + R * Math.cos(angle), y1 = CY + R * Math.sin(angle);
    angle += sweep;
    const x2 = CX + R * Math.cos(angle), y2 = CY + R * Math.sin(angle);
    const large = sweep > Math.PI ? 1 : 0;
    const path = `M ${CX} ${CY} L ${x1.toFixed(2)} ${y1.toFixed(2)} A ${R} ${R} 0 ${large} 1 ${x2.toFixed(2)} ${y2.toFixed(2)} Z`;
    return { ...d, path, color: CHART_SEV_COLORS[d.severity] || 'var(--accent)' };
  });

  return (
    <div style={{ display:'flex', alignItems:'center', gap:20, flexWrap:'wrap' }}>
      <svg viewBox="0 0 220 220" style={{ width:200, height:200, flexShrink:0 }}>
        {slices.map((s, i) => (
          <path key={i} d={s.path} fill={s.color}
                opacity={hovered === null || hovered === i ? '.9' : '.3'}
                style={{ transition:'opacity .15s', cursor:'default' }}
                onMouseEnter={() => setHovered(i)}
                onMouseLeave={() => setHovered(null)}/>
        ))}
        {hovered !== null ? (<>
          <text x={CX} y={CY-8} textAnchor="middle" fontSize="15" fontWeight="700"
                fill="var(--text1)" fontFamily="var(--mono)">{slices[hovered].count}</text>
          <text x={CX} y={CY+8} textAnchor="middle" fontSize="9"
                fill={slices[hovered].color} fontFamily="var(--mono)" fontWeight="600"
                textTransform="uppercase">{slices[hovered].severity}</text>
        </>) : (<>
          <text x={CX} y={CY-8} textAnchor="middle" fontSize="15" fontWeight="700"
                fill="var(--text1)" fontFamily="var(--mono)">{total}</text>
          <text x={CX} y={CY+8} textAnchor="middle" fontSize="9"
                fill="var(--text3)" fontFamily="var(--mono)" letterSpacing=".06em">TOTAL</text>
        </>)}
      </svg>
      <div style={{ flex:1, minWidth:100, display:'flex', flexDirection:'column', gap:6 }}>
        {slices.map((s, i) => (
          <div key={i} style={{ display:'flex', alignItems:'center', gap:7, fontSize:11,
                                opacity: hovered === null || hovered === i ? 1 : .35,
                                transition:'opacity .15s', cursor:'default' }}
               onMouseEnter={() => setHovered(i)}
               onMouseLeave={() => setHovered(null)}>
            <div style={{ width:8, height:8, borderRadius:2, background:s.color, flexShrink:0 }}/>
            <div style={{ flex:1, color:s.color, fontFamily:'var(--mono)', fontSize:10,
                          textTransform:'uppercase', letterSpacing:'.05em' }}>{s.severity}</div>
            <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text3)' }}>
              {((s.count / total)*100).toFixed(1)}%
            </div>
            <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text1)',
                          minWidth:28, textAlign:'right' }}>{s.count}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── SeverityCard (Bars / Pie toggle) ─────────────────────────────────────────
function SeverityCard({ data, subtitle }) {
  const [view, setView] = useState('bars');
  const btnStyle = (active) => ({
    padding:'2px 10px', fontSize:11, fontFamily:'var(--mono)',
    borderRadius:'var(--radius-md)', border:'none', cursor:'pointer',
    background: active ? 'var(--accent)'  : 'var(--bg2)',
    color:      active ? 'white'          : 'var(--text3)',
    transition: 'all .15s',
  });
  return (
    <Card title="Alerts by Severity" subtitle={subtitle}
          extra={
            <div style={{ display:'flex', gap:4 }}>
              <button style={btnStyle(view==='bars')} onClick={() => setView('bars')}>Bars</button>
              <button style={btnStyle(view==='pie')}  onClick={() => setView('pie')}>Pie</button>
            </div>
          }>
      {view === 'bars' ? <SeverityBars data={data}/> : <SeverityPie data={data}/>}
    </Card>
  );
}

// ── ChartsView ────────────────────────────────────────────────────────────────
export function ChartsView() {
  const [data,      setData]      = useState(null);
  const [loading,   setLoading]   = useState(true);
  const [trend,     setTrend]     = useState(24);
  const [chartType, setChartType] = useState('Trend'); // 'Trend' | 'Bar' | 'Pie'

  function load(trendHours) {
    setLoading(true);
    const days = Math.max(1, trendHours / 24);
    fetch(`/charts?trend=${trendHours}&days=${days}`)
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }

  useEffect(() => { load(24); }, []);

  function switchTrend(h) { setTrend(h); load(h); }

  const TREND_OPTIONS = [
    { label:'24h', val:24 }, { label:'7d',  val:168 },
    { label:'30d', val:720 }, { label:'60d', val:1440 }, { label:'90d', val:2160 },
  ];

  const opt = TREND_OPTIONS.find(o => o.val === trend);
  const window_label = opt ? `Last ${opt.label}` : `Last ${trend}h`;

  const TrendToggle = () => (
    <div style={{ display:'flex', gap:1, background:'var(--bg2)',
                  border:'1px solid var(--border)', borderRadius:'var(--radius-sm)', padding:2 }}>
      {TREND_OPTIONS.map(({ label, val }) => (
        <button key={val} onClick={() => switchTrend(val)} style={{
          padding:'2px 10px', borderRadius:'var(--radius-sm)', border:'none',
          background: trend===val ? 'var(--accent)' : 'transparent',
          color:      trend===val ? 'white' : 'var(--text3)',
          fontSize:11, fontFamily:'var(--mono)', cursor:'pointer', transition:'all .15s',
        }}>{label}</button>
      ))}
    </div>
  );

  return (
    <main className="main" style={{ overflow:'auto' }}>
      <div style={{ padding:'20px 24px', display:'flex', flexDirection:'column', gap:20 }}>
        <Card isLoading={loading} title="Alert Trend" subtitle={window_label}
              extra={<div style={{ display:'flex', alignItems:'center', gap:8 }}>
                <ChartTypeMenu value={chartType} onChange={setChartType}/>
                <TrendToggle/>
              </div>}>
          {chartType === 'Trend' && <TrendChart    data={data?.trend}/>}
          {chartType === 'Bar'   && <BarTrendChart  data={data?.trend}/>}
        </Card>
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:20 }}>
          <Card isLoading={loading} title="Top Talkers" subtitle={`Top 10 source IPs · ${window_label}`}>
            <TopTalkersChart data={data?.top_talkers}/>
          </Card>
          <SeverityCard data={data?.by_severity} subtitle={window_label}/>
        </div>
        <Card isLoading={loading} title="Alerts by Category" subtitle={window_label}>
          <DonutChart data={data?.by_category}/>
        </Card>
      </div>
    </main>
  );
}
