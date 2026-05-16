import { useState, useEffect, useCallback, useRef } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import AlertDrawer from '../components/AlertDrawer';
import apiClient from '../api/client';
import './AlertQueue.css';

/* ── API functions ──────────────────────────────────────── */
const fetchAlerts = (filters) => {
  const params = {};
  if (filters.severity !== 'all') params.severity = filters.severity.toUpperCase();
  if (filters.status   !== 'all') params.status   = filters.status.toUpperCase();
  if (filters.engine)             params.engine   = filters.engine;
  if (filters.q)                  params.q        = filters.q;
  params.limit = 200;
  return apiClient.get('/api/v1/alerts', { params }).then(r => r.data);
};

const acknowledgeAlert = (id) =>
  apiClient.patch(`/api/v1/alerts/${id}/acknowledge`).then(r => r.data);

const markFalsePositive = (id) =>
  apiClient.patch(`/api/v1/alerts/${id}/false-positive`).then(r => r.data);

const addNote = ({ id, note }) =>
  apiClient.post(`/api/v1/alerts/${id}/notes`, { text: note }).then(r => r.data);

/* ── shape normaliser (API → component schema) ──────────── */
function normaliseAlert(a) {
  return {
    id:         a.alert_id ?? a.id,
    ts:         a.detected_at ?? a.timestamp ?? new Date().toISOString(),
    severity:   (a.severity ?? 'LOW').toLowerCase(),
    type:       a.attack_type ?? a.type ?? 'Unknown',
    src_ip:     a.src_ip ?? '—',
    dst_ip:     a.dst_ip ?? '—',
    dst_port:   a.dst_port ?? null,
    protocol:   a.protocol ?? '—',
    engine:     a.detected_by ?? a.engine ?? '—',
    confidence: a.confidence ?? a.confidence_score ?? 0,
    status:     (a.status ?? 'NEW').toLowerCase().replace('new', 'open'),
    rule_id:    a.rule_id ?? null,
    flow_id:    a.flow_id ?? null,
    notes:      a.notes ?? [],
  };
}

/* ── static fallback engines list ───────────────────────── */
const ENGINES = ['Signature', 'RF', 'IF', 'LSTM', 'Ensemble'];

/* ─────────────────────────────────────────────────────────────
   SUB-COMPONENTS
───────────────────────────────────────────────────────────── */

function SevBadge({ level }) {
  return <span className={`badge badge-${level}`}>{level.toUpperCase()}</span>;
}

function ConfBar({ value }) {
  const pct = Math.round(value * 100);
  const color = value >= 0.9 ? 'var(--critical)'
              : value >= 0.8 ? 'var(--high)'
              : value >= 0.7 ? 'var(--medium)'
              : 'var(--low)';
  return (
    <div className="aq-conf">
      <div className="aq-conf-track">
        <div className="aq-conf-fill" style={{ width:`${pct}%`, background: color }} />
      </div>
      <span className="aq-conf-val">{value.toFixed(3)}</span>
    </div>
  );
}

function LiveDot() {
  return <span className="aq-live-dot" />;
}

function FilterBar({ filters, onChange, totalOpen, totalAll, autoRefresh, onToggleAuto }) {
  return (
    <div className="aq-filterbar">
      <div className="aq-sev-toggles">
        {['all','critical','high','medium','low'].map(s => (
          <button
            key={s}
            className={`aq-sev-btn aq-sev-btn--${s} ${filters.severity === s ? 'active' : ''}`}
            onClick={() => onChange({ ...filters, severity: s })}
          >
            {s === 'all' ? `ALL  (${totalAll})` : s.toUpperCase()}
          </button>
        ))}
      </div>

      <div className="aq-filterbar-right">
        <div className="aq-status-toggle">
          {['all','open','acknowledged','false_positive'].map(st => (
            <button
              key={st}
              className={`aq-status-btn ${filters.status === st ? 'active' : ''}`}
              onClick={() => onChange({ ...filters, status: st })}
            >
              {st === 'all' ? 'ALL STATUSES' : st.replace('_',' ').toUpperCase()}
            </button>
          ))}
        </div>

        <div className="aq-search">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none"
            stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <input
            type="text"
            placeholder="Filter by IP, type, ID…"
            value={filters.q}
            onChange={e => onChange({ ...filters, q: e.target.value })}
          />
        </div>

        <select
          className="aq-select"
          value={filters.engine}
          onChange={e => onChange({ ...filters, engine: e.target.value })}
        >
          <option value="">ALL ENGINES</option>
          {ENGINES.map(e => <option key={e} value={e}>{e}</option>)}
        </select>

        <button
          className={`aq-auto-btn ${autoRefresh ? 'aq-auto-btn--on' : ''}`}
          onClick={onToggleAuto}
          title={autoRefresh ? 'Pause live updates' : 'Resume live updates'}
        >
          {autoRefresh ? <LiveDot /> : null}
          {autoRefresh ? 'LIVE' : 'PAUSED'}
        </button>
      </div>
    </div>
  );
}

function StatStrip({ alerts }) {
  const counts = { critical:0, high:0, medium:0, low:0 };
  alerts.forEach(a => { if (counts[a.severity] !== undefined) counts[a.severity]++; });
  const open  = alerts.filter(a => a.status === 'open').length;
  const acked = alerts.filter(a => a.status === 'acknowledged').length;
  const fp    = alerts.filter(a => a.status === 'false_positive').length;

  return (
    <div className="aq-statstrip">
      <div className="aq-stat aq-stat--critical">
        <span className="aq-stat-val">{counts.critical}</span>
        <span className="aq-stat-lbl">CRITICAL</span>
      </div>
      <div className="aq-stat aq-stat--high">
        <span className="aq-stat-val">{counts.high}</span>
        <span className="aq-stat-lbl">HIGH</span>
      </div>
      <div className="aq-stat aq-stat--medium">
        <span className="aq-stat-val">{counts.medium}</span>
        <span className="aq-stat-lbl">MEDIUM</span>
      </div>
      <div className="aq-stat aq-stat--low">
        <span className="aq-stat-val">{counts.low}</span>
        <span className="aq-stat-lbl">LOW</span>
      </div>
      <div className="aq-stat-divider" />
      <div className="aq-stat">
        <span className="aq-stat-val">{open}</span>
        <span className="aq-stat-lbl">OPEN</span>
      </div>
      <div className="aq-stat">
        <span className="aq-stat-val" style={{ color:'var(--ok)' }}>{acked}</span>
        <span className="aq-stat-lbl">ACKED</span>
      </div>
      <div className="aq-stat">
        <span className="aq-stat-val" style={{ color:'var(--text-muted)' }}>{fp}</span>
        <span className="aq-stat-lbl">FALSE+</span>
      </div>
    </div>
  );
}

function AlertRow({ alert, selected, onSelect, onAck, onFP, index }) {
  const age = useRelativeTime(alert.ts);
  const isNew = Date.now() - new Date(alert.ts).getTime() < 8000;

  return (
    <tr
      className={`aq-row aq-row--${alert.severity} ${selected ? 'aq-row--selected' : ''} ${isNew ? 'aq-row--new' : ''} ${alert.status !== 'open' ? 'aq-row--closed' : ''}`}
      style={{ animationDelay: `${index * 30}ms` }}
      onClick={() => onSelect(alert)}
    >
      <td className="aq-cell-sev">
        <span className={`aq-sev-strip aq-sev-strip--${alert.severity}`} />
      </td>
      <td className="aq-cell-id">
        <span className="aq-alert-id">{alert.id}</span>
        {isNew && <span className="aq-new-pip" />}
      </td>
      <td className="aq-cell-ts">
        <span className="aq-ts-rel">{age}</span>
        <span className="aq-ts-abs">{fmtTs(alert.ts)}</span>
      </td>
      <td><SevBadge level={alert.severity} /></td>
      <td><span className="aq-type">{alert.type}</span></td>
      <td className="aq-cell-src">
        <span className="aq-ip">{alert.src_ip}</span>
        <span className="aq-proto">{alert.protocol}</span>
      </td>
      <td className="aq-cell-dst">
        <span className="aq-ip">{alert.dst_ip}</span>
        <span className="aq-port">:{alert.dst_port}</span>
      </td>
      <td><span className="aq-engine-tag">{alert.engine}</span></td>
      <td className="aq-cell-conf">
        <ConfBar value={alert.confidence} />
      </td>
      <td><StatusChip status={alert.status} /></td>
      <td className="aq-cell-actions" onClick={e => e.stopPropagation()}>
        {alert.status === 'open' && (
          <>
            <button
              className="aq-action-btn aq-action-btn--ack"
              onClick={() => onAck(alert.id)}
              title="Acknowledge"
            >ACK</button>
            <button
              className="aq-action-btn aq-action-btn--fp"
              onClick={() => onFP(alert.id)}
              title="Mark as false positive"
            >FP</button>
          </>
        )}
        <button className="aq-action-btn aq-action-btn--view" title="View details">→</button>
      </td>
    </tr>
  );
}

function StatusChip({ status }) {
  const map = {
    open:           { label: 'OPEN',      cls: 'aq-status--open'  },
    acknowledged:   { label: 'ACKED',     cls: 'aq-status--acked' },
    false_positive: { label: 'FALSE+',    cls: 'aq-status--fp'    },
    escalated:      { label: 'ESCALATED', cls: 'aq-status--esc'   },
  };
  const { label, cls } = map[status] ?? { label: status, cls: '' };
  return <span className={`aq-status ${cls}`}>{label}</span>;
}

function EmptyState({ filtered }) {
  return (
    <tr>
      <td colSpan={11} style={{ textAlign:'center', padding:'60px 20px' }}>
        <div style={{ color:'var(--text-dim)', fontSize: 13 }}>
          {filtered
            ? '— No alerts match the current filters —'
            : '— No alerts yet. System is monitoring. —'}
        </div>
      </td>
    </tr>
  );
}

/* ─────────────────────────────────────────────────────────────
   HOOKS
───────────────────────────────────────────────────────────── */

function useRelativeTime(isoTs) {
  const [label, setLabel] = useState('');
  useEffect(() => {
    function compute() {
      const diff = (Date.now() - new Date(isoTs).getTime()) / 1000;
      if (diff < 10)   return 'just now';
      if (diff < 60)   return `${Math.floor(diff)}s ago`;
      if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
      return `${Math.floor(diff/3600)}h ago`;
    }
    setLabel(compute());
    const id = setInterval(() => setLabel(compute()), 10000);
    return () => clearInterval(id);
  }, [isoTs]);
  return label;
}

/* ─────────────────────────────────────────────────────────────
   HELPERS
───────────────────────────────────────────────────────────── */
function fmtTs(iso) {
  return iso.replace('T',' ').slice(0,19);
}

function applyFilters(alerts, f) {
  return alerts.filter(a => {
    if (f.severity && f.severity !== 'all' && a.severity !== f.severity) return false;
    if (f.status   && f.status   !== 'all' && a.status   !== f.status)   return false;
    if (f.engine   && a.engine !== f.engine)                              return false;
    if (f.q) {
      const q = f.q.toLowerCase();
      const hay = `${a.id} ${a.type} ${a.src_ip} ${a.dst_ip} ${a.engine}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

/* ─────────────────────────────────────────────────────────────
   MAIN COMPONENT
───────────────────────────────────────────────────────────── */
export default function AlertQueue() {
  const queryClient = useQueryClient();
  const [filters, setFilters]         = useState({ severity:'all', status:'all', engine:'', q:'' });
  const [selected, setSelected]       = useState(null);
  const [drawerOpen, setDrawerOpen]   = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [sort, setSort]               = useState({ col:'ts', dir:'desc' });

  /* ── live data fetch ──────────────────────────────────── */
  const { data: rawData, isLoading } = useQuery({
    queryKey: ['alerts', filters],
    queryFn:  () => fetchAlerts(filters),
    refetchInterval: autoRefresh ? 15_000 : false,
    staleTime: 10_000,
  });

  const rawAlerts = rawData?.alerts ?? rawData ?? [];
  const alerts = rawAlerts.map(normaliseAlert);

  /* ── loading state ────────────────────────────────────── */
  if (isLoading && alerts.length === 0) {
    return (
      <div className="page" style={{ padding: 40, color: 'var(--text-muted)' }}>
        Loading alerts…
      </div>
    );
  }

  /* ── mutations ────────────────────────────────────────── */
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['alerts'] });

  const ackMutation = useMutation({
    mutationFn: acknowledgeAlert,
    onSuccess: invalidate,
  });

  const fpMutation = useMutation({
    mutationFn: markFalsePositive,
    onSuccess: invalidate,
  });

  const noteMutation = useMutation({
    mutationFn: addNote,
    onSuccess: invalidate,
  });

  /* ── sort ─────────────────────────────────────────────── */
  const sorted = [...alerts].sort((a, b) => {
    let av = a[sort.col], bv = b[sort.col];
    if (sort.col === 'ts')         { av = new Date(av); bv = new Date(bv); }
    if (sort.col === 'confidence') { av = +av; bv = +bv; }
    if (av < bv) return sort.dir === 'asc' ? -1 : 1;
    if (av > bv) return sort.dir === 'asc' ?  1 : -1;
    return 0;
  });

  const visible    = applyFilters(sorted, filters);
  const isFiltered = filters.severity !== 'all' || filters.status !== 'all' || filters.engine || filters.q;

  function toggleSort(col) {
    setSort(s => ({ col, dir: s.col === col && s.dir === 'asc' ? 'desc' : 'asc' }));
  }

  function handleSelect(alert) {
    setSelected(alert);
    setDrawerOpen(true);
  }

  function handleAck(id)           { ackMutation.mutate(id);            }
  function handleFP(id)            { fpMutation.mutate(id);             }
  function handleAddNote(id, note) { noteMutation.mutate({ id, note }); }

  function SortTh({ col, label, className }) {
    const active = sort.col === col;
    return (
      <th
        className={`aq-th aq-th--sortable ${active ? 'aq-th--active' : ''} ${className ?? ''}`}
        onClick={() => toggleSort(col)}
      >
        {label}
        <span className="aq-sort-icon">
          {active ? (sort.dir === 'asc' ? ' ↑' : ' ↓') : ' ⇅'}
        </span>
      </th>
    );
  }

  return (
    <div className="page aq-page">
      {/* header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Alert Queue</h1>
          <p className="page-subtitle">
            Real-time threat alerts · ensemble threshold ≥ 0.50 · FR9, FR7, FR8
          </p>
        </div>
        <div className="page-actions">
          <span className="aq-total-count">{alerts.length} total · {visible.length} shown</span>
          {/* ── FIX 2: RESET now refreshes from API instead of calling missing setAlerts ── */}
          <button className="btn btn-ghost" onClick={() => queryClient.invalidateQueries({ queryKey: ['alerts'] })}>
            REFRESH
          </button>
          <button className="btn btn-danger" disabled={!alerts.some(a => a.status === 'open')}>
            ACK ALL OPEN
          </button>
        </div>
      </div>

      {/* stat strip */}
      <StatStrip alerts={alerts} />

      {/* filter bar */}
      <FilterBar
        filters={filters}
        onChange={setFilters}
        totalOpen={alerts.filter(a => a.status==='open').length}
        totalAll={alerts.length}
        autoRefresh={autoRefresh}
        onToggleAuto={() => setAutoRefresh(v => !v)}
      />

      {/* table */}
      <div className="aq-table-wrap">
        <table className="aq-table">
          <thead>
            <tr className="aq-thead-row">
              <th className="aq-th aq-th--sev-col" />
              <SortTh col="id"         label="ALERT ID"   />
              <SortTh col="ts"         label="TIME"       />
              <SortTh col="severity"   label="SEVERITY"   />
              <SortTh col="type"       label="TYPE"       />
              <th className="aq-th">SOURCE</th>
              <th className="aq-th">DESTINATION</th>
              <th className="aq-th">ENGINE</th>
              <SortTh col="confidence" label="CONFIDENCE" className="aq-th--conf" />
              <th className="aq-th">STATUS</th>
              <th className="aq-th aq-th--actions">ACTIONS</th>
            </tr>
          </thead>
          <tbody>
            {visible.length === 0
              ? <EmptyState filtered={isFiltered} />
              : visible.map((a, i) => (
                  <AlertRow
                    key={a.id}
                    alert={a}
                    index={i}
                    selected={selected?.id === a.id}
                    onSelect={handleSelect}
                    onAck={handleAck}
                    onFP={handleFP}
                  />
                ))
            }
          </tbody>
        </table>
      </div>

      {/* detail drawer */}
      <AlertDrawer
        alert={selected}
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        onAck={handleAck}
        onFP={handleFP}
        onAddNote={handleAddNote}
      />
    </div>
  );
}