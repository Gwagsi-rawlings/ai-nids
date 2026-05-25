import { useState, useEffect } from 'react';
import './AlertDrawer.css';

/* ── helpers ─────────────────────────────────────────────── */
function fmtTs(iso) {
  if (!iso) return '—';
  return iso.replace('T', ' ').slice(0, 19) + ' UTC';
}

function ConfMeter({ value }) {
  const pct = Math.round(value * 100);
  const color = value >= 0.9 ? 'var(--critical)'
              : value >= 0.8 ? 'var(--high)'
              : value >= 0.7 ? 'var(--medium)'
              : 'var(--low)';
  return (
    <div className="drawer-conf-meter">
      <div className="drawer-conf-track">
        <div
          className="drawer-conf-fill"
          style={{ width: `${pct}%`, background: color }}
        />
        <div
          className="drawer-conf-threshold"
          style={{ left: '50%' }}
          title="Alert threshold (0.50)"
        />
      </div>
      <div className="drawer-conf-labels">
        <span className="drawer-conf-val" style={{ color }}>
          {value.toFixed(4)}
        </span>
        <span className="drawer-conf-pct">{pct}%</span>
      </div>
    </div>
  );
}

function EnsembleBreakdown({ alert }) {
  const engines = [
    { name: 'Signature', weight: 0.40, conf: alert.sig_confidence },
    { name: 'RF',        weight: 0.35, conf: alert.rf_confidence },
    { name: 'LSTM',      weight: 0.15, conf: alert.lstm_confidence },
    { name: 'IF',        weight: 0.10, conf: alert.if_confidence },
    { name: 'Ensemble',  weight: 1.00, conf: alert.confidence },
  ];

  return (
    <div className="drawer-ensemble">
      {engines.map(e => (
        <div key={e.name} className={`drawer-eng-row ${e.conf !== null ? 'drawer-eng-row--active' : 'drawer-eng-row--pending'}`}>
          <span className={`dot ${e.conf !== null ? 'dot-ok' : 'dot-muted'}`} />
          <span className="drawer-eng-name">{e.name}</span>
          <span className="drawer-eng-weight">w={e.weight.toFixed(2)}</span>
          <div className="drawer-eng-bar-wrap">
            <div
              className="drawer-eng-bar"
              style={{
                width: e.conf !== null ? `${Math.min(1, Math.max(0, e.conf)) * 100}%` : '0%',
                background: e.conf !== null ? 'var(--accent)' : 'var(--border-bright)',
              }}
            />
          </div>
          <span className="drawer-eng-conf">
            {e.conf !== null ? e.conf.toFixed(3) : '—'}
          </span>
        </div>
      ))}
      <div className="drawer-formula">
        <span className="text-muted">Weighted score =</span>
        <span className="text-accent">0.40·sig + 0.35·rf + 0.15·lstm + 0.10·if</span>
      </div>
    </div>
  );
}

function DataRow({ label, value, mono, accent, copy }) {
  const [copied, setCopied] = useState(false);
  function handleCopy() {
    navigator.clipboard?.writeText(String(value));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }
  return (
    <div className="drawer-row">
      <span className="drawer-row-label">{label}</span>
      <span className={`drawer-row-value ${mono ? 'mono' : ''} ${accent ? 'text-accent' : ''}`}>
        {value ?? '—'}
        {copy && value && (
          <button className="drawer-copy-btn" onClick={handleCopy} title="Copy">
            {copied ? '✓' : '⎘'}
          </button>
        )}
      </span>
    </div>
  );
}

function NotesList({ notes }) {
  if (!notes || notes.length === 0) {
    return (
      <div className="drawer-notes-empty">No investigation notes yet.</div>
    );
  }
  return (
    <div className="drawer-notes-list">
      {notes.map((n, i) => (
        <div key={i} className="drawer-note">
          <span className="drawer-note-ts">{fmtTs(n.ts)}</span>
          <span className="drawer-note-text">{n.text}</span>
        </div>
      ))}
    </div>
  );
}

/* ── main component ──────────────────────────────────────── */
export default function AlertDrawer({ alert, open, onClose, onAck, onFP, onAddNote }) {
  const [tab, setTab]       = useState('details');
  const [note, setNote]     = useState('');
  const [closing, setClosing] = useState(false);

  /* reset tab when alert changes */
  useEffect(() => {
    if (alert) setTab('details');
  }, [alert?.id]);

  /* close animation */
  function handleClose() {
    setClosing(true);
    setTimeout(() => {
      setClosing(false);
      onClose();
    }, 200);
  }

  /* close on Escape */
  useEffect(() => {
    function onKey(e) { if (e.key === 'Escape') handleClose(); }
    if (open) document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open]);

  function submitNote() {
    const trimmed = note.trim();
    if (!trimmed || !alert) return;
    onAddNote(alert.id, trimmed);
    setNote('');
  }

  if (!alert) return null;

  const isOpen = alert.status === 'open';

  return (
    <>
      {/* backdrop */}
      <div
        className={`drawer-backdrop ${open && !closing ? 'drawer-backdrop--visible' : ''}`}
        onClick={handleClose}
      />

      {/* drawer panel */}
      <aside className={`drawer ${open && !closing ? 'drawer--open' : ''}`}>

        {/* drawer header */}
        <div className="drawer-header">
          <div className="drawer-header-left">
            <span className={`drawer-sev-dot drawer-sev-dot--${alert.severity}`} />
            <div>
              <div className="drawer-alert-id">{alert.id}</div>
              <div className="drawer-alert-type">{alert.type}</div>
            </div>
          </div>
          <button className="drawer-close" onClick={handleClose} title="Close (Esc)">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
              stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
              <line x1="18" y1="6" x2="6" y2="18"/>
              <line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        </div>

        {/* severity + actions bar */}
        <div className="drawer-action-bar">
          <span className={`badge badge-${alert.severity}`}>{alert.severity.toUpperCase()}</span>
          <span className={`aq-status aq-status--${alert.status === 'open' ? 'open' : alert.status === 'acknowledged' ? 'acked' : 'fp'}`}>
            {alert.status === 'open' ? 'OPEN'
              : alert.status === 'acknowledged' ? 'ACKNOWLEDGED'
              : 'FALSE POSITIVE'}
          </span>
          <div style={{ flex: 1 }} />
          {isOpen && (
            <>
              <button
                className="btn btn-ghost"
                style={{ fontSize: 10, padding: '4px 12px' }}
                onClick={() => { onFP(alert.id); }}
              >
                MARK FALSE+
              </button>
              <button
                className="btn btn-primary"
                style={{ fontSize: 10, padding: '4px 14px' }}
                onClick={() => { onAck(alert.id); }}
              >
                ✓ ACKNOWLEDGE
              </button>
            </>
          )}
        </div>

        {/* tabs */}
        <div className="drawer-tabs">
          {['details', 'ensemble', 'notes'].map(t => (
            <button
              key={t}
              className={`drawer-tab ${tab === t ? 'drawer-tab--active' : ''}`}
              onClick={() => setTab(t)}
            >
              {t.toUpperCase()}
              {t === 'notes' && alert.notes?.length > 0 && (
                <span className="drawer-tab-badge">{alert.notes.length}</span>
              )}
            </button>
          ))}
        </div>

        {/* tab content */}
        <div className="drawer-body">

          {/* ── DETAILS tab ────────────────────────────────── */}
          {tab === 'details' && (
            <div className="drawer-section animate-fade-up">

              {/* confidence meter */}
              <div className="drawer-block">
                <div className="drawer-block-title">ENSEMBLE CONFIDENCE</div>
                <ConfMeter value={alert.confidence} />
                <div className="drawer-conf-hint">
                  Threshold: 0.50 · Alert generated at {alert.confidence.toFixed(4)}
                </div>
              </div>

              {/* network info */}
              <div className="drawer-block">
                <div className="drawer-block-title">NETWORK</div>
                <DataRow label="Source IP"      value={alert.src_ip}   mono copy />
                <DataRow label="Destination IP" value={alert.dst_ip}   mono copy />
                <DataRow label="Dest Port"      value={alert.dst_port} mono />
                <DataRow label="Protocol"       value={alert.protocol} />
                <DataRow label="Flow ID"        value={alert.flow_id?.slice(0,20) + '…'} mono />
              </div>

              {/* detection info */}
              <div className="drawer-block">
                <div className="drawer-block-title">DETECTION</div>
                <DataRow label="Attack Type"   value={alert.type}              />
                <DataRow label="Engine"        value={alert.engine}    accent  />
                <DataRow label="Rule ID"       value={alert.rule_id ?? 'ML detection (no rule)'} mono />
                <DataRow label="Detected At"   value={fmtTs(alert.ts)}         />
                <DataRow label="Alert Status"  value={alert.status.replace('_',' ').toUpperCase()} />
              </div>

              {/* recommended actions */}
              <div className="drawer-block">
                <div className="drawer-block-title">RECOMMENDED ACTIONS</div>
                <div className="drawer-actions-list">
                  {getRecommendations(alert.type).map((r, i) => (
                    <div key={i} className="drawer-rec">
                      <span className="drawer-rec-num">{String(i+1).padStart(2,'0')}</span>
                      <span className="drawer-rec-text">{r}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ── ENSEMBLE tab ───────────────────────────────── */}
          {tab === 'ensemble' && (
            <div className="drawer-section animate-fade-up">
              <div className="drawer-block">
                <div className="drawer-block-title">DETECTION ENGINE BREAKDOWN</div>
          <EnsembleBreakdown alert={alert} />

              <div className="drawer-block">
                <div className="drawer-block-title">SCORE COMPONENTS</div>
                <DataRow label="Signature weight" value="0.40" mono />
                <DataRow label="Random Forest"    value="0.35" mono />
                <DataRow label="LSTM"             value="0.15 (Week 6)" mono />
                <DataRow label="Isolation Forest" value="0.10" mono />
                <DataRow label="Alert threshold"  value="≥ 0.50" accent />
                <DataRow label="Final score"      value={alert.confidence.toFixed(4)} accent />
              </div>

              <div className="drawer-block">
                <div className="drawer-block-title">NFR20 COMPLIANCE</div>
                <div className="drawer-nfr-row">
                  <span className="dot dot-ok" />
                  <span>NFR20.1 — RF weighted F1: 0.9867</span>
                </div>
                <div className="drawer-nfr-row">
                  <span className="dot dot-ok" />
                  <span>NFR20.2 — Ensemble FPR: 0.0114</span>
                </div>
                <div className="drawer-nfr-row">
                  <span className="dot dot-ok" />
                  <span>NFR20.3 — Precision ≥ 0.90 ✓</span>
                </div>
                <div className="drawer-nfr-row">
                  <span className="dot dot-muted" />
                  <span style={{ color:'var(--text-muted)' }}>NFR20.5 — Ensemble gain pending LSTM (Wk 6)</span>
                </div>
              </div>
            </div>
          )}

          {/* ── NOTES tab ──────────────────────────────────── */}
          {tab === 'notes' && (
            <div className="drawer-section animate-fade-up">
              <div className="drawer-block">
                <div className="drawer-block-title">INVESTIGATION NOTES</div>
                <NotesList notes={alert.notes} />
              </div>

              <div className="drawer-note-input-wrap">
                <textarea
                  className="drawer-note-input"
                  placeholder="Add investigation note… (analyst observations, findings, next steps)"
                  value={note}
                  onChange={e => setNote(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) submitNote();
                  }}
                  rows={4}
                />
                <div className="drawer-note-actions">
                  <span className="drawer-note-hint">Ctrl+Enter to submit</span>
                  <button
                    className="btn btn-primary"
                    style={{ fontSize: 10, padding: '5px 14px' }}
                    onClick={submitNote}
                    disabled={!note.trim()}
                  >
                    ADD NOTE
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* footer */}
        <div className="drawer-footer">
          <span className="text-muted" style={{ fontSize: 10 }}>
            Flow ID: {alert.flow_id?.slice(0, 24)}…
          </span>
          <button className="btn btn-ghost" style={{ fontSize: 10, padding: '3px 10px' }}>
            EXPORT JSON
          </button>
        </div>
      </aside>
    </>
  );
}

/* ── recommendations map ─────────────────────────────────── */
function getRecommendations(type) {
  const map = {
    DoS:        ['Block source IP at perimeter firewall', 'Enable rate-limiting on target service', 'Check upstream bandwidth consumption', 'Notify network administrator'],
    DDoS:       ['Engage DDoS mitigation service (Cloudflare/AWS Shield)', 'Apply traffic scrubbing upstream', 'Enable geo-blocking for source regions', 'Monitor target host availability'],
    PortScan:   ['Block source IP for 24 hours', 'Review exposed service ports', 'Check for subsequent exploitation attempts from same IP', 'Log source in threat intelligence feed'],
    BruteForce: ['Lock out source IP immediately', 'Check target account for successful login', 'Enable MFA on target service', 'Review authentication logs for successful auths'],
    WebAttack:  ['Block source IP at WAF', 'Review application logs for successful injection', 'Check database query logs', 'Patch vulnerable application endpoint'],
    Botnet:     ['Isolate affected host from network', 'Capture traffic for forensic analysis', 'Check C2 domain in threat intelligence', 'Scan host for malware indicators'],
    Infiltration:['Immediately isolate affected hosts', 'Preserve forensic evidence (memory dump)', 'Initiate incident response procedure', 'Notify security leadership'],
    Anomaly:    ['Investigate source IP in threat intel feeds', 'Review baseline deviation details', 'Correlate with other alerts from same source', 'Monitor for escalation to known attack pattern'],
  };
  return map[type] ?? ['Investigate alert details', 'Correlate with recent alerts', 'Review logs for additional context'];
}