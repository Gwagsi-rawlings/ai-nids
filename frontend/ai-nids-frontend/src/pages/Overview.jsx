import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import './Overview.css';
import apiClient from '../api/client';
import { fetchCaptureStatus, startCapture, stopCapture } from '../api/capture';

/* ── API functions ───────────────────────────────────────── */
const fetchRecentAlerts = () =>
  apiClient.get('/api/v1/alerts?page_size=5').then(r => r.data);

const fetchStatus = () =>
  apiClient.get('/api/v1/status').then(r => r.data);

const fetchModels = () =>
  apiClient.get('/api/v1/models').then(r => r.data);

const fetchCaptureStats = () =>
  apiClient.get('/api/v1/capture/stats').then(r => r.data);

/* ── weight map for API model_name → ensemble weight ────── */
const WEIGHT_MAP = {
  random_forest:    0.35,
  isolation_forest: 0.10,
  lstm:             0.15,
  signature_engine: 0.40,
};

/* ── normalise API model record → EngineCard shape ─────── */
function normaliseModel(m) {
  const key    = m.model_name ?? m.name ?? '';
  const weight = WEIGHT_MAP[key] ?? 0;
  const metric =
    m.f1_score       != null ? m.f1_score.toFixed(4)       :
    m.false_pos_rate  != null ? m.false_pos_rate.toFixed(4)  :
    m.accuracy        != null ? m.accuracy.toFixed(4)        : '—';
  const metricLabel =
    m.f1_score       != null ? 'F1 score' :
    m.false_pos_rate  != null ? 'FPR'      :
    m.accuracy        != null ? 'accuracy' : 'scheduled';
  return {
    name:        key,
    weight,
    status:      m.is_active ? 'active' : 'pending',
    metric,
    metricLabel,
  };
}

/* ── sub-components ──────────────────────────────────────── */
function StatCard({ value, label, delta, deltaDir, accent }) {
  return (
    <div className="stat-card" style={accent ? { '--card-accent': accent } : {}}>
      <div className="stat-card-accent-bar" />
      <div className="stat-block">
        <span className="stat-value">{value}</span>
        <span className="stat-label">{label}</span>
        {delta && (
          <span className={`stat-delta ${deltaDir}`}>{delta}</span>
        )}
      </div>
    </div>
  );
}

function SeverityBadge({ level }) {
  return <span className={`badge badge-${level}`}>{level.toUpperCase()}</span>;
}

function EngineCard({ engine }) {
  const isActive = engine.status === 'active';
  return (
    <div className={`engine-card ${isActive ? 'engine-card--active' : 'engine-card--pending'}`}>
      <div className="engine-card-header">
        <span className={`dot ${isActive ? 'dot-ok dot-pulse' : 'dot-muted'}`} />
        <span className="engine-name">{engine.name}</span>
        <span className="engine-weight">w={engine.weight.toFixed(2)}</span>
      </div>
      <div className="engine-card-metric">
        <span className="engine-metric-value">{engine.metric}</span>
        <span className="engine-metric-label">{engine.metricLabel}</span>
      </div>
      <div className="engine-bar-wrap">
        <div
          className="engine-bar"
          style={{ width: `${engine.weight / 0.40 * 100}%` }}
        />
      </div>
    </div>
  );
}

/* ── live pps ticker ─────────────────────────────────────── */

/* ── main component ──────────────────────────────────────── */
export default function Overview() {
  const queryClient = useQueryClient();
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [captureIface, setCaptureIface] = useState('eth0');

  const { data: alertsData } = useQuery({
    queryKey: ['alerts', 'recent'],
    queryFn: fetchRecentAlerts,
    refetchInterval: 15_000,
  });

  const { data: statusData } = useQuery({
    queryKey: ['status'],
    queryFn: fetchStatus,
    refetchInterval: 30_000,
  });

  const { data: modelsData } = useQuery({
    queryKey: ['models'],
    queryFn: fetchModels,
    staleTime: 60_000,
  });

  const { data: captureStats } = useQuery({
    queryKey: ['capture', 'stats'],
    queryFn: fetchCaptureStats,
    staleTime: 10_000,
    refetchInterval: 15_000,
  });

  const { data: captureStatusData } = useQuery({
    queryKey: ['capture', 'liveStatus'],
    queryFn: fetchCaptureStatus,
    refetchInterval: 5_000,
  });

  const isRunning = captureStatusData?.running ?? false;

  const startMutation = useMutation({
    mutationFn: () => startCapture(captureIface),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['capture', 'liveStatus'] }),
  });

  const stopMutation = useMutation({
    mutationFn: stopCapture,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['capture', 'liveStatus'] }),
  });

  const isCaptureLoading = startMutation.isPending || stopMutation.isPending;

  const handleCaptureToggle = () => {
    if (isRunning) stopMutation.mutate();
    else startMutation.mutate();
  };

  // ── FIX: handle all possible API response shapes ──────────
  const alerts      = alertsData?.alerts ?? alertsData?.items ?? alertsData ?? [];
  const activeCount = alertsData?.total  ?? alerts.filter(a =>
    (a.status ?? 'NEW').toUpperCase() === 'NEW').length;

  const engineList = statusData?.detection_engines
    ? Object.entries(statusData.detection_engines).map(([key, engine]) => ({
        name: {
          signature: 'Signature Engine',
          random_forest: 'Random Forest',
          isolation_forest: 'Isolation Forest',
          lstm: 'LSTM',
        }[key] ?? key,
        weight: statusData?.ensemble?.weights?.[key] ?? WEIGHT_MAP[key] ?? 0,
        status: engine.status === 'active' ? 'active' : 'pending',
        metric: key === 'signature'
          ? `${engine.rules_loaded ?? 0} rules`
          : engine.status === 'active'
            ? 'ready'
            : 'not trained',
        metricLabel: key === 'signature' ? 'loaded' : 'status',
      }))
    : Array.isArray(modelsData) && modelsData.length
      ? modelsData.map(normaliseModel)
      : [];

  const pipeline = statusData?.pipeline_stages
    ? Object.entries(statusData.pipeline_stages).map(([key, val]) => ({
        stage: key.replace(/_/g, ' '),
        status: (val === 'active' || val === 'ready' || val.startsWith('active')) ? 'ok' : 'pending',
        note: val,
      }))
    : null;

  return (
    <div className="page">

      {/* settings modal */}
      {settingsOpen && (
        <div className="settings-overlay" onClick={() => setSettingsOpen(false)}>
          <div className="settings-modal" onClick={e => e.stopPropagation()}>
            <div className="settings-modal-header">
              <span className="card-title">Capture Settings</span>
              <button className="btn btn-ghost" style={{ padding: '2px 8px', fontSize: 14 }} onClick={() => setSettingsOpen(false)}>✕</button>
            </div>
            <div className="settings-modal-body">
              <div className="settings-field">
                <label className="settings-label">Network Interface</label>
                <input
                  className="settings-input"
                  value={captureIface}
                  onChange={e => setCaptureIface(e.target.value)}
                  placeholder="eth0"
                  disabled={isRunning}
                />
                <span className="settings-hint">Interface used for live packet capture. Requires NET_ADMIN capability.</span>
              </div>
              <div className="settings-field">
                <label className="settings-label">Capture Mode</label>
                <div className="settings-info-row">
                  <span className={`dot ${isRunning ? 'dot-ok dot-pulse' : 'dot-muted'}`} />
                  <span style={{ color: isRunning ? 'var(--ok)' : 'var(--text-secondary)', fontSize: 12 }}>
                    {isRunning ? `Live — capturing on ${captureStatusData?.interface ?? captureIface}` : 'Idle — PCAP replay or standby'}
                  </span>
                </div>
              </div>
            </div>
            <div className="settings-modal-footer">
              <button className="btn btn-ghost" onClick={() => setSettingsOpen(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={() => setSettingsOpen(false)} disabled={isRunning}>Apply</button>
            </div>
          </div>
        </div>
      )}

      {/* page header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">System Overview</h1>
          <p className="page-subtitle">
            Real-time detection dashboard · CICIDS2017 ensemble · threshold ≥ 0.50
          </p>
        </div>
        <div className="page-actions">
          <div className={`capture-status${isRunning ? ' capture-status--live' : ''}`}>
            <span className={`dot ${isRunning ? 'dot-ok dot-pulse' : 'dot-muted'}`} />
            <span>{isRunning ? 'LIVE MODE' : 'PCAP MODE'}</span>
          </div>
          <button
            className="btn btn-ghost"
            onClick={() => setSettingsOpen(true)}
            title="Capture Settings"
            style={{ padding: '6px 10px' }}
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="3"/>
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
            </svg>
          </button>
          <button
            className={`btn ${isRunning ? 'btn-danger' : 'btn-primary'}`}
            onClick={handleCaptureToggle}
            disabled={isCaptureLoading}
          >
            {isRunning ? (
              <svg width="11" height="11" viewBox="0 0 24 24" fill="currentColor">
                <rect x="6" y="6" width="12" height="12" rx="1"/>
              </svg>
            ) : (
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none"
                stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <polygon points="5 3 19 12 5 21 5 3"/>
              </svg>
            )}
            {isCaptureLoading ? '…' : isRunning ? 'STOP CAPTURE' : 'START LIVE CAPTURE'}
          </button>
        </div>
      </div>

      {/* KPI strip */}
      <div className="grid-4" style={{ marginBottom: 20 }}>
        <StatCard value={activeCount}        label="Active Alerts"    delta="▲ 1 last hour"  deltaDir="up"   accent="var(--critical)" />
        <StatCard value="91.3%"              label="Detection Rate"   delta="↑ 0.4% vs base" deltaDir="down" accent="var(--ok)"       />
        <StatCard value="0.0114"             label="Ensemble FPR"     delta="↓ 84% vs sig."  deltaDir="down" accent="var(--accent)"   />
        <StatCard value={captureStats ? `${Math.round(captureStats.bytes_per_sec).toLocaleString()} Bps` : '—'} label="Throughput" delta={captureStats ? `${Math.round(captureStats.packets_per_sec).toLocaleString()} pkt/s` : 'Loading…'} deltaDir="" accent="var(--low)" />
      </div>

      {/* main grid: alerts + engines */}
      <div className="overview-main">

        {/* recent alerts table */}
        <div className="card overview-alerts">
          <div className="card-header">
            <span className="card-title">Recent Alerts</span>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span className="badge badge-critical" style={{ animation: 'pulse 2s ease-in-out infinite' }}>
                {activeCount} OPEN
              </span>
              <a href="/alerts" className="btn btn-ghost" style={{ fontSize: 10, padding: '3px 10px' }}>
                VIEW ALL →
              </a>
            </div>
          </div>

          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>TIME</th>
                <th>SEVERITY</th>
                <th>TYPE</th>
                <th>SOURCE IP</th>
                <th>ENGINE</th>
                <th>CONF</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {!Array.isArray(alerts) || alerts.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', padding: 20, color: 'var(--text-muted)' }}>
                    No alerts — system is monitoring
                  </td>
                </tr>
              ) : (
                alerts.map((a, i) => (
                  <tr key={a.alert_id ?? a.id ?? i} className="animate-fade-up">
                    <td className="text-accent" style={{ fontWeight: 600 }}>
                      {String(a.alert_id ?? a.id ?? '—').slice(0, 8)}
                    </td>
                    <td className="text-muted">
                      {(a.detected_at ?? a.timestamp)?.split('T')[1]?.slice(0, 8)}
                    </td>
                    <td>
                      <SeverityBadge level={(a.severity ?? 'low').toLowerCase()} />
                    </td>
                    <td style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
                      {a.attack_type ?? a.type ?? '—'}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{a.src_ip}</td>
                    <td>
                      <span className="engine-tag">{a.detected_by ?? a.detection_method ?? '—'}</span>
                    </td>
                    <td>
                      <div className="conf-bar-wrap">
                        <div className="conf-bar" style={{ width: `${(a.confidence ?? a.confidence_score ?? 0) * 100}%` }} />
                        <span className="conf-label">{(a.confidence ?? a.confidence_score ?? 0).toFixed(2)}</span>
                      </div>
                    </td>
                    <td>
                      <button className="btn btn-ghost" style={{ padding: '3px 8px', fontSize: 10 }}>
                        ACK
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* right column */}
        <div className="overview-right">

          {/* ensemble engines */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Detection Ensemble</span>
              <span className="badge badge-ok">{engineList.length} ENGINES</span>
            </div>
            <div className="engine-grid">
              {engineList.map((e, i) => (
                <EngineCard key={`${e.name}-${i}`} engine={e} />
              ))}
            </div>
            <div className="ensemble-formula">
              <span className="text-muted" style={{ fontSize: 10 }}>Score =</span>
              <span>0.40·sig + 0.35·rf + 0.15·lstm + 0.10·if</span>
            </div>
          </div>

          {/* pipeline health */}
          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-header">
              <span className="card-title">Pipeline Health</span>
            </div>
            <div className="pipeline-rows">
              {(pipeline ?? [
                { stage: 'Packet Capture',      status: 'ok',      note: 'PCAP mode'      },
                { stage: 'Flow Aggregator',      status: 'ok',      note: '5-tuple key'    },
                { stage: 'Feature Extractor',    status: 'ok',      note: '41 features'    },
                { stage: 'Signature Engine',     status: 'ok',      note: '65 rules'       },
                { stage: 'ML Inference',         status: 'ok',      note: 'RF + IF'        },
                { stage: 'Ensemble Correlator',  status: 'ok',      note: 'threshold 0.50' },
                { stage: 'Alert Generator',      status: 'ok',      note: 'PostgreSQL'     },
                { stage: 'LSTM (Sequential)',    status: 'pending', note: 'Week 6'         },
              ]).map((row, i) => (
                <div key={`${row.stage}-${i}`} className="pipeline-row">
                  <span className={`dot dot-${row.status === 'ok' ? 'ok' : 'muted'}`} />
                  <span className="pipeline-stage">{row.stage}</span>
                  <span className="pipeline-note">{row.note}</span>
                </div>
              ))}
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}