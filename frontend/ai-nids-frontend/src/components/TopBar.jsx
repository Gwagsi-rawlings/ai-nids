import { useState, useEffect } from 'react';
import './TopBar.css';

/* ── tiny live clock ─────────────────────────────────────── */
function Clock() {
  const [time, setTime] = useState(new Date());
  useEffect(() => {
    const id = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  return (
    <span className="topbar-clock">
      {time.toISOString().replace('T', ' ').slice(0, 19)} UTC
    </span>
  );
}

/* ── alert count badge ───────────────────────────────────── */
function AlertBell({ count = 3 }) {
  return (
    <button className="topbar-icon-btn" title="Active alerts">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
        <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
      </svg>
      {count > 0 && (
        <span className="topbar-badge">{count > 99 ? '99+' : count}</span>
      )}
    </button>
  );
}

/* ── system health indicator ─────────────────────────────── */
function HealthPill({ status = 'ok' }) {
  const labels = { ok: 'SYSTEMS NOMINAL', warn: 'DEGRADED', crit: 'CRITICAL' };
  return (
    <div className={`topbar-health topbar-health--${status}`}>
      <span className={`dot dot-${status === 'ok' ? 'ok' : 'critical'} dot-pulse`} />
      {labels[status] || 'UNKNOWN'}
    </div>
  );
}

/* ── main component ──────────────────────────────────────── */
export default function TopBar({ onMenuToggle, sidebarOpen }) {
  return (
    <header className="topbar">
      {/* left: hamburger + wordmark */}
      <div className="topbar-left">
        <button
          className="topbar-hamburger"
          onClick={onMenuToggle}
          title={sidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'}
        >
          <span /><span /><span />
        </button>

        <div className="topbar-wordmark">
          <span className="topbar-wordmark-ai">N</span>
          <span className="topbar-wordmark-sep">—</span>
          <span className="topbar-wordmark-nids">CyberShield™</span>
        </div>

        <div className="topbar-divider" />
        <HealthPill status="ok" />
      </div>

      {/* centre: live clock */}
      <div className="topbar-centre">
        <Clock />
      </div>

      {/* right: actions + user */}
      <div className="topbar-right">
        {/* PCAP upload shortcut */}
        <button className="btn btn-ghost topbar-action" title="Upload PCAP for analysis">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none"
            stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="17 8 12 3 7 8"/>
            <line x1="12" y1="3" x2="12" y2="15"/>
          </svg>
          UPLOAD PCAP
        </button>

        <AlertBell count={3} />

        {/* settings */}
        <button className="topbar-icon-btn" title="Settings">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none"
            stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="3"/>
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
          </svg>
        </button>

        {/* user pill */}
        <div className="topbar-user">
          <div className="topbar-avatar">R</div>
          <div className="topbar-user-info">
            <span className="topbar-username">rawlings</span>
            <span className="topbar-role">SYSTEM_ADMIN</span>
          </div>
        </div>
      </div>
    </header>
  );
}
