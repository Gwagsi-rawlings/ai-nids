import AlertQueue from './AlertQueue';
import TrafficMonitor from './TrafficMonitor';
import ThreatDetection from './ThreatDetection';
import RulesManagement from './RulesManagement';
import Capture from './Capture';
import MLModels from './MLModels';
import Analytics from './Analytics';
import Admin from './Admin';
/* ─────────────────────────────────────────────────────────
   Placeholder pages — each will be fully implemented in
   subsequent sprints. They share a single file for brevity.
───────────────────────────────────────────────────────── */

function PlaceholderPage({ title, subtitle, sprint, icon }) {
  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1 className="page-title">{title}</h1>
          <p className="page-subtitle">{subtitle}</p>
        </div>
      </div>
      <div style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        height: 320,
        gap: 16,
        opacity: 0.4,
      }}>
        <div style={{ fontSize: 48 }}>{icon}</div>
        <div style={{
          fontFamily: 'var(--font-display)',
          fontSize: 14,
          fontWeight: 600,
          color: 'var(--text-secondary)',
          textTransform: 'uppercase',
          letterSpacing: '0.1em',
        }}>
          Scheduled: {sprint}
        </div>
        <div style={{
          fontSize: 11,
          color: 'var(--text-muted)',
          textAlign: 'center',
          maxWidth: 320,
          lineHeight: 1.7,
        }}>
          This view will be fully implemented in the listed sprint.
          See the execution plan (Mar 13 – May 31, 2026) for details.
        </div>
      </div>
    </div>
  );
}

export function AlertQueuePage() {
  return <AlertQueue />;
}

export function TrafficPage() {
  return <TrafficMonitor />;
}

export function ThreatDetectionPage() {
  return <ThreatDetection />;
}

export function RulesPage() {
  return <RulesManagement />;
}

export function MLModelsPage() {
  return <MLModels/>;
}

export function AnalyticsPage() {
  return <Analytics/>;
}

export function AdminPage() {
  return <Admin/>;
}

export function CapturePage() {
  return <Capture/>;
}
