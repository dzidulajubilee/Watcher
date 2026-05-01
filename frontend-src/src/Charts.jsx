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

// ── ChartsView ────────────────────────────────────────────────────────────────
export function ChartsView() {
  const [data,    setData]    = useState(null);
  const [loading, setLoading] = useState(true);
  const [trend,   setTrend]   = useState(24);

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

  const Card = ({ title, subtitle, children, extra }) => (
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
        {loading
          ? <div style={{ display:'flex', alignItems:'center', justifyContent:'center',
                          height:120, color:'var(--text3)', fontSize:12,
                          fontFamily:'var(--mono)' }}>Loading…</div>
          : children}
      </div>
    </div>
  );

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
        <Card title="Alert Trend" subtitle={window_label} extra={<TrendToggle/>}>
          <TrendChart data={data?.trend}/>
        </Card>
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:20 }}>
          <Card title="Top Talkers" subtitle={`Top 10 source IPs · ${window_label}`}>
            <TopTalkersChart data={data?.top_talkers}/>
          </Card>
          <Card title="Alerts by Severity" subtitle={window_label}>
            <SeverityBars data={data?.by_severity}/>
          </Card>
        </div>
        <Card title="Alerts by Category" subtitle={window_label}>
          <DonutChart data={data?.by_category}/>
        </Card>
      </div>
    </main>
  );
}
