import { NavLink } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import apiClient from '../api/client';
import './Sidebar.css';

/* ── SVG icons ───────────────────────────────────────────── */
const Icons = {
  Dashboard: () => (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/>
      <rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>
    </svg>
  ),
  Alerts: () => (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
      <line x1="12" y1="9" x2="12" y2="13"/>
      <line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>
  ),
  Traffic: () => (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
    </svg>
  ),
  Rules: () => (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
      <polyline points="14 2 14 8 20 8"/>
      <line x1="16" y1="13" x2="8" y2="13"/>
      <line x1="16" y1="17" x2="8" y2="17"/>
      <polyline points="10 9 9 9 8 9"/>
    </svg>
  ),
  Models: () => (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <path d="M8.56 2.75c4.37 6.03 6.02 9.42 8.03 17.72m2.54-15.38c-3.72 4.35-8.94 5.66-16.88 5.85m19.5 1.9c-3.5-.93-6.63-.82-8.94 0-2.58.92-5.01 2.86-7.44 6.32"/>
    </svg>
  ),
  Analytics: () => (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <line x1="18" y1="20" x2="18" y2="10"/>
      <line x1="12" y1="20" x2="12" y2="4"/>
      <line x1="6"  y1="20" x2="6"  y2="14"/>
    </svg>
  ),
  Admin: () => (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  ),
  Capture: () => (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="5 3 19 12 5 21 5 3"/>
    </svg>
  ),
  // ── NEW: Threat Detection icon (crosshair/target) ─────────
  ThreatDetection: () => (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="9"/>
      <circle cx="12" cy="12" r="4"/>
      <line x1="12" y1="2"  x2="12" y2="6"/>
      <line x1="12" y1="18" x2="12" y2="22"/>
      <line x1="2"  y1="12" x2="6"  y2="12"/>
      <line x1="18" y1="12" x2="22" y2="12"/>
    </svg>
  ),
};

/* ── nav sections ────────────────────────────────────────── */
const SECTIONS = [
  {
    label: 'DETECTION',
    items: [
      { to: '/',                  icon: 'Dashboard',        label: 'Overview',          end: true },
      { to: '/alerts',            icon: 'Alerts',           label: 'Alert Queue'       },
      { to: '/traffic',           icon: 'Traffic',          label: 'Live Traffic'                 },
      { to: '/threat-detection',  icon: 'ThreatDetection',  label: 'Threat Detection'             },
      { to: '/capture',           icon: 'Capture',          label: 'Capture',           pill: 'PCAP' },
    ],
  },
  {
    label: 'CONFIGURATION',
    items: [
      { to: '/rules',  icon: 'Rules',   label: 'Detection Rules' },
      { to: '/models', icon: 'Models',  label: 'ML Models'       },
    ],
  },
  {
    label: 'REPORTING',
    items: [
      { to: '/analytics', icon: 'Analytics', label: 'Analytics & Reports' },
    ],
  },
  {
    label: 'SYSTEM',
    items: [
      { to: '/admin', icon: 'Admin', label: 'Administration' },
    ],
  },
];

/* ── engine status mini panel ────────────────────────────── */
function EngineStatus({ statusData }) {
  const engines = statusData?.detection_engines ?? {};
  const weights = statusData?.ensemble?.weights ?? {};
  const alertThreshold = statusData?.ensemble?.alert_threshold ?? 0.50;

  const rows = [
    { key: 'signature', label: 'Signature Engine' },
    { key: 'random_forest', label: 'Random Forest' },
    { key: 'isolation_forest', label: 'Isolation Forest' },
    { key: 'lstm', label: 'LSTM' },
  ].map(engine => ({
    ...engine,
    data: engines[engine.key] || null,
    weight: weights[engine.key] ?? 0,
  }));

  return (
    <div className="sidebar-engines">
      <div className="sidebar-section-label">ENSEMBLE</div>
      {rows.map(e => (
        <div key={e.key} className="sidebar-engine-row">
          <span className={`dot dot-${e.data?.status === 'active' ? 'ok' : 'muted'}`} />
          <span className="sidebar-engine-name">{e.label}</span>
          <span className="sidebar-engine-weight">{e.weight.toFixed(2)}</span>
        </div>
      ))}
      <div className="sidebar-threshold">
        <span className="text-muted">Alert threshold</span>
        <span className="text-accent">≥ {alertThreshold.toFixed(2)}</span>
      </div>
    </div>
  );
}

const fetchStatus = () => apiClient.get('/api/v1/status').then(r => r.data);

/* ── main component ──────────────────────────────────────── */
export default function Sidebar({ open }) {
  const { data: statusData } = useQuery({ queryKey: ['status'], queryFn: fetchStatus, staleTime: 20_000 });

  return (
    <aside className={`sidebar ${open ? 'sidebar--open' : 'sidebar--closed'}`}>
      <nav className="sidebar-nav">
        {SECTIONS.map(section => (
          <div key={section.label} className="sidebar-section">
            <div className="sidebar-section-label">{section.label}</div>
            {section.items.map(item => {
              const Icon = Icons[item.icon];
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) =>
                    `sidebar-link ${isActive ? 'sidebar-link--active' : ''}`
                  }
                >
                  <span className="sidebar-link-icon"><Icon /></span>
                  <span className="sidebar-link-label">{item.label}</span>
                  {item.badge && (
                    <span className="sidebar-link-badge">{item.badge}</span>
                  )}
                  {item.pill && (
                    <span className="sidebar-link-pill">{item.pill}</span>
                  )}
                </NavLink>
              );
            })}
          </div>
        ))}
      </nav>

      {/* engine status at bottom */}
      <EngineStatus />

      {/* version footer */}
      <div className="sidebar-footer">
        <span className="text-muted">AI-NIDS</span>
        <span className="text-dim">v0.1.0 · Sprint 1</span>
      </div>
    </aside>
  );
}