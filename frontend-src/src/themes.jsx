import { useState, useEffect, useRef } from 'react';

export const THEMES = [
  { id: 'night',     label: 'Night',          accent: '#4f9cf9', dot: '#0f1117' },
  { id: 'light',     label: 'Light',          accent: '#2563eb', dot: '#f0f2f5' },
  { id: 'midnight',  label: 'Midnight Blue',  accent: '#58a6ff', dot: '#161b27' },
  { id: 'solarized', label: 'Solarized Dark', accent: '#268bd2', dot: '#002b36' },
  { id: 'dracula',   label: 'Dracula',        accent: '#bd93f9', dot: '#21222c' },
  { id: 'nord',      label: 'Nord',           accent: '#88c0d0', dot: '#3b4252' },
];

export function ThemePicker({ theme, onChange }) {
  const [open, setOpen] = useState(false);
  const ref             = useRef(null);
  const current         = THEMES.find(t => t.id === theme) || THEMES[0];

  useEffect(() => {
    function handleClick(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  return (
    <div style={{ position: 'relative' }} ref={ref}>
      <div className="theme-btn" onClick={() => setOpen(o => !o)}>
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
              <div style={{
                width: 10, height: 10, borderRadius: '50%', flexShrink: 0,
                background: t.dot, border: `2px solid ${t.accent}`,
                boxShadow: `0 0 0 1px ${t.accent}55`,
              }}/>
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
