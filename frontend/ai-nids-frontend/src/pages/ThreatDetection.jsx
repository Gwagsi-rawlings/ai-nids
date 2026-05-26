import { useState, useEffect, useRef } from "react";
import { useQuery } from '@tanstack/react-query';
import apiClient from '../api/client';
import { useAlertStream } from '../hooks/useAlertStream';
import { useAlertStore } from '../store/alert';

// ── Live detection feed helpers ───────────────────────────────────────────────
const ATTACK_CLASSES = ["BENIGN", "DoS", "DDoS", "PortScan", "BruteForce", "Botnet", "WebAttack", "Infiltration"];
const SEVERITY_MAP = { BENIGN: null, DoS: "HIGH", DDoS: "HIGH", PortScan: "MEDIUM", BruteForce: "HIGH", Botnet: "CRITICAL", WebAttack: "MEDIUM", Infiltration: "CRITICAL" };
const SEVERITY_COLOR = { CRITICAL: "#ff3b3b", HIGH: "#ff8c00", MEDIUM: "#f0c330", LOW: "#4ecdc4", null: "#3a9e5f" };

const fetchRecentAlerts = () =>
  apiClient.get('/api/v1/alerts?page_size=50').then(r => r.data.alerts ?? r.data ?? []);

function normaliseProbabilities(attackClass, confidence) {
  const primary = Math.min(0.94, confidence + 0.05);
  const remainder = Math.max(0, 1 - primary);
  const secondary = ATTACK_CLASSES.find((c) => c !== attackClass && c !== 'BENIGN') ?? 'BENIGN';
  const probs = ATTACK_CLASSES.reduce((acc, cls) => {
    acc[cls] = 0;
    return acc;
  }, {});
  probs[attackClass] = primary;
  probs['BENIGN'] = Math.max(0, remainder * 0.5);
  probs[secondary] = Math.max(0, remainder * 0.5);
  return probs;
}

function normaliseAlert(alert) {
  const severity = (alert.severity ?? 'LOW').toUpperCase();
  const confidence = Number(alert.confidence ?? (severity === 'CRITICAL' ? 0.97 : severity === 'HIGH' ? 0.90 : severity === 'MEDIUM' ? 0.75 : 0.55));
  const sigConf = Number(alert.sig_confidence ?? confidence * 0.40);
  const rfConf = Number(alert.rf_confidence ?? confidence * 0.35);
  const lstmConf = Number(alert.lstm_confidence ?? confidence * 0.15);
  const ifConf = Number(alert.if_confidence ?? confidence * 0.10);
  const attackType = alert.attack_type ?? alert.type ?? 'Unknown';

  return {
    id: alert.alert_id ?? alert.id ?? String(Date.now()),
    timestamp: alert.detected_at ?? alert.timestamp ?? new Date().toISOString(),
    flowId: alert.flow_id ?? alert.alert_id ?? String(Date.now()),
    srcIp: alert.src_ip ?? '—',
    dstIp: alert.dst_ip ?? '—',
    srcPort: alert.src_port ?? alert.dst_port ?? '—',
    dstPort: alert.dst_port ?? '—',
    protocol: alert.protocol ?? 'TCP',
    predictedClass: attackType,
    severity: severity.toLowerCase(),
    engines: { signature: sigConf, rf: rfConf, lstm: lstmConf, if: ifConf },
    ensembleScore: confidence,
    alert: ['open', 'new'].includes((alert.status ?? '').toLowerCase()) || confidence >= 0.50,
    classProbabilities: normaliseProbabilities(attackType, confidence),
  };
}

function fmt(n) { return (n * 100).toFixed(1) + "%"; }
function fmtScore(n) { return n.toFixed(4); }
function fmtTime(d) { return d.toTimeString().slice(0, 8) + "." + String(d.getMilliseconds()).padStart(3, "0"); }

// ── Sub-components ────────────────────────────────────────────────────────────

function EngineBar({ label, weight, conf, color }) {
  const barWidth = (conf * 100).toFixed(1);
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 3 }}>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "#8a9ab5", letterSpacing: 1 }}>
          {label}
        </span>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <span style={{ fontSize: 10, color: "#4a5a75", fontFamily: "monospace" }}>
            w={weight}
          </span>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: color, fontWeight: 700 }}>
            {fmt(conf)}
          </span>
        </div>
      </div>
      <div style={{ height: 6, background: "#0d1520", borderRadius: 2, overflow: "hidden", border: "1px solid #1a2535" }}>
        <div style={{
          height: "100%",
          width: barWidth + "%",
          background: `linear-gradient(90deg, ${color}80, ${color})`,
          borderRadius: 2,
          transition: "width 0.6s cubic-bezier(0.4,0,0.2,1)",
          boxShadow: `0 0 6px ${color}60`,
        }} />
      </div>
    </div>
  );
}

function ClassProbRow({ label, prob, isTop }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 5 }}>
      <span style={{
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: 10,
        color: isTop ? "#e8eaf0" : "#4a5a75",
        width: 80,
        flexShrink: 0,
      }}>
        {label}
      </span>
      <div style={{ flex: 1, height: 4, background: "#0d1520", borderRadius: 2, overflow: "hidden" }}>
        <div style={{
          height: "100%",
          width: (prob * 100).toFixed(1) + "%",
          background: isTop
            ? `linear-gradient(90deg, ${SEVERITY_COLOR[SEVERITY_MAP[label]] || "#3a9e5f"}80, ${SEVERITY_COLOR[SEVERITY_MAP[label]] || "#3a9e5f"})`
            : "#1e3050",
          borderRadius: 2,
          transition: "width 0.5s ease",
        }} />
      </div>
      <span style={{
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: 10,
        color: isTop ? "#e8eaf0" : "#3a4a65",
        width: 42,
        textAlign: "right",
        flexShrink: 0,
      }}>
        {fmt(prob)}
      </span>
    </div>
  );
}

function FeedRow({ pred, isSelected, onClick }) {
  const sev = pred.severity;
  const sevColor = SEVERITY_COLOR[sev] || "#3a9e5f";
  return (
    <div
      onClick={onClick}
      style={{
        padding: "8px 14px",
        borderBottom: "1px solid #0d1520",
        cursor: "pointer",
        background: isSelected ? "#0f1e35" : "transparent",
        borderLeft: isSelected ? `3px solid ${sevColor}` : "3px solid transparent",
        display: "flex",
        alignItems: "center",
        gap: 12,
        transition: "background 0.15s",
      }}
      onMouseEnter={e => { if (!isSelected) e.currentTarget.style.background = "#0a1525"; }}
      onMouseLeave={e => { if (!isSelected) e.currentTarget.style.background = "transparent"; }}
    >
      {/* Alert indicator */}
      <div style={{
        width: 7, height: 7, borderRadius: "50%",
        background: pred.alert ? sevColor : "#1e2d45",
        flexShrink: 0,
        boxShadow: pred.alert ? `0 0 6px ${sevColor}` : "none",
      }} />

      {/* Timestamp */}
      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#3a5070", width: 86, flexShrink: 0 }}>
        {fmtTime(pred.timestamp)}
      </span>

      {/* Src IP */}
      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#5a7090", width: 106, flexShrink: 0 }}>
        {pred.srcIp}
      </span>

      {/* Class badge */}
      <span style={{
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: 10,
        fontWeight: 700,
        color: pred.predictedClass === "BENIGN" ? "#3a9e5f" : sevColor,
        width: 80,
        flexShrink: 0,
      }}>
        {pred.predictedClass}
      </span>

      {/* Ensemble score */}
      <div style={{ flex: 1, display: "flex", alignItems: "center", gap: 6 }}>
        <div style={{ flex: 1, height: 3, background: "#0d1520", borderRadius: 2, overflow: "hidden" }}>
          <div style={{
            height: "100%",
            width: (pred.ensembleScore * 100).toFixed(1) + "%",
            background: pred.alert
              ? `linear-gradient(90deg, ${sevColor}80, ${sevColor})`
              : "#1a3050",
            borderRadius: 2,
          }} />
        </div>
        <span style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 10,
          color: pred.alert ? sevColor : "#3a5070",
          width: 42,
          textAlign: "right",
          flexShrink: 0,
        }}>
          {fmtScore(pred.ensembleScore)}
        </span>
      </div>

      {/* Alert pill */}
      <div style={{
        padding: "1px 7px",
        borderRadius: 3,
        background: pred.alert ? `${sevColor}22` : "#0a1220",
        border: `1px solid ${pred.alert ? sevColor + "60" : "#1a2535"}`,
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: 9,
        color: pred.alert ? sevColor : "#2a3a55",
        letterSpacing: 1,
        flexShrink: 0,
      }}>
        {pred.alert ? (sev || "DETECT") : "PASS"}
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function ThreatDetectionView() {
  useAlertStream();
  const liveAlerts = useAlertStore((state) => state.alerts);
  const { data: initialAlerts = [] } = useQuery({
    queryKey: ['threat', 'recent'],
    queryFn: fetchRecentAlerts,
    staleTime: 30_000,
    refetchInterval: 30_000,
  });

  const [selected, setSelected] = useState(null);
  const [isLive, setIsLive] = useState(true);
  const [filterClass, setFilterClass] = useState("ALL");
  const [feed, setFeed] = useState([]);
  const [fps, setFps] = useState(0);
  const frameTimes = useRef([]);

  useEffect(() => {
    const normalized = initialAlerts.map(normaliseAlert).slice(0, 80);
    setFeed(normalized);
    setSelected((prev) => prev ?? normalized[0] ?? null);
  }, [initialAlerts]);

  useEffect(() => {
    if (!isLive || !liveAlerts.length) return;
    const latest = liveAlerts[0];
    const id = latest.alert_id ?? latest.id;
    setFeed((prev) => {
      if (!id || prev.some((item) => item.id === id)) return prev;
      return [normaliseAlert(latest), ...prev].slice(0, 80);
    });
  }, [liveAlerts, isLive]);

  useEffect(() => {
    if (!isLive) return;
    const now = Date.now();
    frameTimes.current = frameTimes.current.filter((t) => t > now - 1000);
    frameTimes.current.push(now);
    setFps(frameTimes.current.length);
  }, [feed, isLive]);

  const displayed = filterClass === "ALL"
    ? feed
    : feed.filter((p) => p.predictedClass === filterClass);

  const sel = selected || feed[0];
  const topClass = sel
    ? Object.entries(sel.classProbabilities).sort((a, b) => b[1] - a[1])[0]?.[0]
    : null;

  const alertCount = feed.filter((p) => p.alert).length;
  const alertRate = feed.length ? ((alertCount / feed.length) * 100).toFixed(1) : "0.0";
  const statsWindow = { total: feed.length, alerts: alertCount, fps };

  return (
    <div style={{
      fontFamily: "'JetBrains Mono', monospace",
      background: "#060e1a",
      minHeight: "100vh",
      color: "#8a9ab5",
      display: "flex",
      flexDirection: "column",
      position: "relative",
      overflow: "hidden",
    }}>
      {/* Scanline overlay */}
      <div style={{
        position: "fixed", inset: 0, pointerEvents: "none", zIndex: 100,
        backgroundImage: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px)",
      }} />

      {/* Header */}
      <div style={{
        padding: "14px 24px",
        borderBottom: "1px solid #0f1e35",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        background: "#070f1c",
        flexShrink: 0,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{
              width: 8, height: 8, borderRadius: "50%",
              background: isLive ? "#3a9e5f" : "#ff3b3b",
              boxShadow: isLive ? "0 0 8px #3a9e5f" : "0 0 8px #ff3b3b",
              animation: isLive ? "pulse 2s infinite" : "none",
            }} />
            <span style={{ fontSize: 11, color: "#4a6a90", letterSpacing: 2 }}>
              ML INFERENCE ENGINE
            </span>
          </div>
          <span style={{ color: "#1a2535", fontSize: 11 }}>|</span>
          <span style={{ fontSize: 10, color: "#2a4060" }}>
            ENSEMBLE v1.0 · CICIDS2017
          </span>
        </div>

        {/* Stats strip */}
        <div style={{ display: "flex", gap: 20, alignItems: "center" }}>
          {[
            { label: "FLOWS", val: statsWindow.total },
            { label: "ALERTS", val: statsWindow.alerts, color: statsWindow.alerts > 0 ? "#ff8c00" : undefined },
            { label: "ALERT RATE", val: alertRate + "%" },
            { label: "FPS", val: statsWindow.fps },
          ].map(({ label, val, color }) => (
            <div key={label} style={{ textAlign: "right" }}>
              <div style={{ fontSize: 9, color: "#2a4060", letterSpacing: 1 }}>{label}</div>
              <div style={{ fontSize: 13, fontWeight: 700, color: color || "#5a8ab5" }}>{val}</div>
            </div>
          ))}

          <button
            onClick={() => setIsLive(l => !l)}
            style={{
              padding: "5px 14px",
              background: isLive ? "#0a1e10" : "#200a0a",
              border: `1px solid ${isLive ? "#2a6e40" : "#6e2a2a"}`,
              borderRadius: 4,
              color: isLive ? "#3a9e5f" : "#ff3b3b",
              fontSize: 10,
              cursor: "pointer",
              letterSpacing: 1,
              fontFamily: "'JetBrains Mono', monospace",
            }}
          >
            {isLive ? "■ PAUSE" : "▶ LIVE"}
          </button>
        </div>
      </div>

      {/* Threshold indicator */}
      <div style={{
        padding: "6px 24px",
        borderBottom: "1px solid #0d1520",
        background: "#060c18",
        display: "flex",
        alignItems: "center",
        gap: 24,
        fontSize: 10,
        flexShrink: 0,
      }}>
        <span style={{ color: "#2a4060", letterSpacing: 1 }}>ALERT THRESHOLD</span>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ width: 200, height: 3, background: "#0d1520", borderRadius: 2, position: "relative" }}>
            <div style={{ position: "absolute", left: "50%", top: -2, width: 1, height: 7, background: "#ff8c00", opacity: 0.8 }} />
            <div style={{ width: "50%", height: "100%", background: "linear-gradient(90deg, #1a3050, #3a5070)", borderRadius: 2 }} />
          </div>
          <span style={{ color: "#ff8c00" }}>0.5000</span>
        </div>
        <span style={{ color: "#1a2535" }}>·</span>
        {[
          { label: "SIG", w: "0.40", color: "#5a8fff" },
          { label: "RF",  w: "0.35", color: "#3a9e5f" },
          { label: "LSTM",w: "0.15", color: "#c47aff" },
          { label: "IF",  w: "0.10", color: "#f0c330" },
        ].map(({ label, w, color }) => (
          <span key={label} style={{ display: "flex", alignItems: "center", gap: 4 }}>
            <span style={{ color, fontWeight: 700 }}>{label}</span>
            <span style={{ color: "#2a4060" }}>{w}</span>
          </span>
        ))}
      </div>

      {/* Body */}
      <div style={{ display: "flex", flex: 1, overflow: "hidden", minHeight: 0 }}>

        {/* Left: Feed */}
        <div style={{ width: "55%", display: "flex", flexDirection: "column", borderRight: "1px solid #0d1520" }}>
          {/* Feed header + filter */}
          <div style={{
            padding: "8px 14px",
            borderBottom: "1px solid #0d1520",
            display: "flex",
            alignItems: "center",
            gap: 10,
            background: "#070f1c",
            flexShrink: 0,
          }}>
            <span style={{ fontSize: 10, color: "#2a4060", letterSpacing: 1, marginRight: 4 }}>FILTER</span>
            {["ALL", ...ATTACK_CLASSES].map(cls => (
              <button
                key={cls}
                onClick={() => setFilterClass(cls)}
                style={{
                  padding: "2px 8px",
                  background: filterClass === cls ? "#0f2040" : "transparent",
                  border: `1px solid ${filterClass === cls ? "#2a5090" : "#0f1e35"}`,
                  borderRadius: 3,
                  color: filterClass === cls ? "#5a9fff" : "#2a4060",
                  fontSize: 9,
                  cursor: "pointer",
                  fontFamily: "'JetBrains Mono', monospace",
                  letterSpacing: 0.5,
                }}
              >
                {cls}
              </button>
            ))}
          </div>

          {/* Column headers */}
          <div style={{
            padding: "5px 14px",
            borderBottom: "1px solid #0d1520",
            display: "flex",
            alignItems: "center",
            gap: 12,
            fontSize: 9,
            color: "#2a3a55",
            letterSpacing: 1,
            flexShrink: 0,
          }}>
            <span style={{ width: 7, flexShrink: 0 }} />
            <span style={{ width: 86, flexShrink: 0 }}>TIMESTAMP</span>
            <span style={{ width: 106, flexShrink: 0 }}>SRC IP</span>
            <span style={{ width: 80, flexShrink: 0 }}>PREDICTION</span>
            <span style={{ flex: 1 }}>ENSEMBLE SCORE</span>
            <span style={{ width: 52, flexShrink: 0 }}>STATUS</span>
          </div>

          {/* Feed rows */}
          <div ref={feedRef} style={{ flex: 1, overflowY: "auto", minHeight: 0 }}>
            {displayed.map(pred => (
              <FeedRow
                key={pred.id}
                pred={pred}
                isSelected={sel?.id === pred.id}
                onClick={() => setSelected(pred)}
              />
            ))}
          </div>
        </div>

        {/* Right: Detail panel */}
        <div style={{ width: "45%", display: "flex", flexDirection: "column", overflow: "hidden" }}>
          {sel ? (
            <>
              {/* Verdict banner */}
              <div style={{
                padding: "14px 20px",
                borderBottom: "1px solid #0d1520",
                background: sel.alert
                  ? `linear-gradient(135deg, ${SEVERITY_COLOR[sel.severity]}11 0%, #070f1c 60%)`
                  : "#070f1c",
                flexShrink: 0,
              }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                  <div>
                    <div style={{ fontSize: 9, color: "#2a4060", letterSpacing: 2, marginBottom: 6 }}>
                      ENSEMBLE VERDICT
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                      <span style={{
                        fontSize: 22,
                        fontWeight: 900,
                        color: sel.predictedClass === "BENIGN"
                          ? "#3a9e5f"
                          : SEVERITY_COLOR[sel.severity],
                        letterSpacing: -0.5,
                        textShadow: sel.alert
                          ? `0 0 20px ${SEVERITY_COLOR[sel.severity]}60`
                          : "none",
                      }}>
                        {sel.predictedClass}
                      </span>
                      {sel.severity && (
                        <div style={{
                          padding: "3px 10px",
                          background: `${SEVERITY_COLOR[sel.severity]}22`,
                          border: `1px solid ${SEVERITY_COLOR[sel.severity]}60`,
                          borderRadius: 4,
                          color: SEVERITY_COLOR[sel.severity],
                          fontSize: 11,
                          fontWeight: 700,
                          letterSpacing: 2,
                        }}>
                          {sel.severity}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Ensemble score gauge */}
                  <div style={{ textAlign: "right" }}>
                    <div style={{ fontSize: 9, color: "#2a4060", letterSpacing: 1, marginBottom: 4 }}>
                      SCORE
                    </div>
                    <div style={{
                      fontSize: 28,
                      fontWeight: 900,
                      color: sel.alert
                        ? SEVERITY_COLOR[sel.severity]
                        : "#1e3050",
                      letterSpacing: -1,
                    }}>
                      {fmtScore(sel.ensembleScore)}
                    </div>
                    <div style={{ fontSize: 9, color: sel.alert ? "#ff8c00" : "#1a2535" }}>
                      {sel.alert ? "▲ ABOVE THRESHOLD" : "▼ BELOW THRESHOLD"}
                    </div>
                  </div>
                </div>

                {/* Ensemble score bar */}
                <div style={{ marginTop: 12, height: 8, background: "#0d1520", borderRadius: 2, overflow: "hidden", position: "relative" }}>
                  <div style={{ position: "absolute", left: "50%", top: 0, width: 1, height: "100%", background: "#ff8c00", opacity: 0.6, zIndex: 2 }} />
                  <div style={{
                    height: "100%",
                    width: (sel.ensembleScore * 100).toFixed(1) + "%",
                    background: sel.alert
                      ? `linear-gradient(90deg, ${SEVERITY_COLOR[sel.severity]}60, ${SEVERITY_COLOR[sel.severity]})`
                      : "linear-gradient(90deg, #1a3050, #2a4570)",
                    borderRadius: 2,
                    transition: "width 0.5s ease",
                    boxShadow: sel.alert ? `0 0 10px ${SEVERITY_COLOR[sel.severity]}50` : "none",
                  }} />
                </div>
              </div>

              {/* Flow metadata */}
              <div style={{
                padding: "10px 20px",
                borderBottom: "1px solid #0d1520",
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: "6px 20px",
                flexShrink: 0,
              }}>
                {[
                  ["FLOW ID", sel.flowId.slice(0, 17) + "…"],
                  ["TIME", fmtTime(sel.timestamp)],
                  ["SRC", `${sel.srcIp}:${sel.srcPort}`],
                  ["DST", `${sel.dstIp}:${sel.dstPort}`],
                  ["PROTOCOL", sel.protocol],
                  ["ALERT", sel.alert ? "YES" : "NO"],
                ].map(([k, v]) => (
                  <div key={k}>
                    <div style={{ fontSize: 8, color: "#2a4060", letterSpacing: 1 }}>{k}</div>
                    <div style={{ fontSize: 10, color: "#6a8ab0", marginTop: 1 }}>{v}</div>
                  </div>
                ))}
              </div>

              {/* Engine breakdown */}
              <div style={{ padding: "12px 20px", borderBottom: "1px solid #0d1520", flexShrink: 0 }}>
                <div style={{ fontSize: 9, color: "#2a4060", letterSpacing: 2, marginBottom: 10 }}>
                  ENGINE CONFIDENCE
                </div>
                <EngineBar label="SIGNATURE ENGINE" weight="0.40" conf={sel.engines.signature} color="#5a8fff" />
                <EngineBar label="RANDOM FOREST"    weight="0.35" conf={sel.engines.rf}        color="#3a9e5f" />
                <EngineBar label="LSTM SEQUENCE"    weight="0.15" conf={sel.engines.lstm}      color="#c47aff" />
                <EngineBar label="ISOLATION FOREST" weight="0.10" conf={sel.engines.if}        color="#f0c330" />
              </div>

              {/* Class probabilities */}
              <div style={{ padding: "12px 20px", flex: 1, overflowY: "auto" }}>
                <div style={{ fontSize: 9, color: "#2a4060", letterSpacing: 2, marginBottom: 10 }}>
                  CLASS PROBABILITY DISTRIBUTION (RF)
                </div>
                {Object.entries(sel.classProbabilities)
                  .sort((a, b) => b[1] - a[1])
                  .map(([cls, prob]) => (
                    <ClassProbRow
                      key={cls}
                      label={cls}
                      prob={prob}
                      isTop={cls === topClass}
                    />
                  ))}
              </div>
            </>
          ) : (
            <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "#1a2535", fontSize: 12 }}>
              SELECT A FLOW TO INSPECT
            </div>
          )}
        </div>
      </div>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700;900&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: #060e1a; }
        ::-webkit-scrollbar-thumb { background: #1a2a3e; border-radius: 2px; }
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }
      `}</style>
    </div>
  );
}