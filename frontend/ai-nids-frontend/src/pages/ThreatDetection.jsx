import { useState, useEffect, useRef } from "react";

// ── Simulated data ────────────────────────────────────────────────────────────
const ATTACK_CLASSES = ["BENIGN", "DoS", "DDoS", "PortScan", "BruteForce", "Botnet", "WebAttack", "Infiltration"];
const SEVERITY_MAP = { BENIGN: null, DoS: "HIGH", DDoS: "HIGH", PortScan: "MEDIUM", BruteForce: "HIGH", Botnet: "CRITICAL", WebAttack: "MEDIUM", Infiltration: "CRITICAL" };
const SEVERITY_COLOR = { CRITICAL: "#ff3b3b", HIGH: "#ff8c00", MEDIUM: "#f0c330", LOW: "#4ecdc4", null: "#3a9e5f" };

function randomFloat(min, max) { return Math.random() * (max - min) + min; }

function generatePrediction(forceAttack = null) {
  const attackClass = forceAttack || (Math.random() < 0.35
    ? ATTACK_CLASSES[Math.floor(Math.random() * (ATTACK_CLASSES.length - 1)) + 1]
    : "BENIGN");
  const isAttack = attackClass !== "BENIGN";

  const rfConf    = isAttack ? randomFloat(0.62, 0.99) : randomFloat(0.01, 0.18);
  const ifConf    = isAttack ? randomFloat(0.40, 0.88) : randomFloat(0.02, 0.12);
  const lstmConf  = isAttack ? randomFloat(0.55, 0.95) : randomFloat(0.01, 0.15);
  const sigConf   = isAttack && Math.random() > 0.4 ? randomFloat(0.70, 1.0) : 0;

  const ensembleScore = 0.40 * sigConf + 0.35 * rfConf + 0.15 * lstmConf + 0.10 * ifConf;

  const probs = ATTACK_CLASSES.map((c) => {
    if (c === attackClass) return randomFloat(0.55, 0.92);
    return randomFloat(0.0, 0.15);
  });
  const sum = probs.reduce((a, b) => a + b, 0);
  const normalised = probs.map((p) => p / sum);

  return {
    id: Date.now() + Math.random(),
    timestamp: new Date(),
    flowId: `${randomHex(8)}-${randomHex(4)}`,
    srcIp: `${rndInt(1,254)}.${rndInt(0,254)}.${rndInt(0,254)}.${rndInt(1,254)}`,
    dstIp: `10.0.${rndInt(0,5)}.${rndInt(1,100)}`,
    srcPort: rndInt(1024, 65535),
    dstPort: [80, 443, 22, 21, 3389, 8080, 25][Math.floor(Math.random() * 7)],
    protocol: ["TCP", "UDP", "ICMP"][Math.floor(Math.random() * 3)],
    predictedClass: attackClass,
    severity: SEVERITY_MAP[attackClass],
    engines: { signature: sigConf, rf: rfConf, lstm: lstmConf, if: ifConf },
    ensembleScore,
    alert: ensembleScore >= 0.50,
    classProbabilities: Object.fromEntries(ATTACK_CLASSES.map((c, i) => [c, normalised[i]])),
  };
}

function randomHex(n) { return [...Array(n)].map(() => Math.floor(Math.random() * 16).toString(16)).join(""); }
function rndInt(a, b) { return Math.floor(Math.random() * (b - a + 1)) + a; }
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
  const [predictions, setPredictions] = useState(() =>
    Array.from({ length: 18 }, () => generatePrediction())
  );
  const [selected, setSelected] = useState(null);
  const [isLive, setIsLive] = useState(true);
  const [statsWindow, setStatsWindow] = useState({ total: 18, alerts: 0, fps: 0 });
  const [filterClass, setFilterClass] = useState("ALL");
  const feedRef = useRef(null);
  const frameCount = useRef(0);
  const lastFpsTime = useRef(Date.now());

  // Init selected
  useEffect(() => {
    const first = predictions.find(p => p.alert) || predictions[0];
    setSelected(first);
    const alerts = predictions.filter(p => p.alert).length;
    setStatsWindow(s => ({ ...s, alerts }));
  }, []);

  // Live feed ticker
  useEffect(() => {
    if (!isLive) return;
    const interval = setInterval(() => {
      frameCount.current++;
      const now = Date.now();
      let fps = statsWindow.fps;
      if (now - lastFpsTime.current >= 1000) {
        fps = frameCount.current;
        frameCount.current = 0;
        lastFpsTime.current = now;
      }

      const newPred = generatePrediction();
      setPredictions(prev => {
        const updated = [newPred, ...prev].slice(0, 80);
        const alerts = updated.filter(p => p.alert).length;
        setStatsWindow({ total: updated.length, alerts, fps });
        return updated;
      });
    }, 1200);
    return () => clearInterval(interval);
  }, [isLive]);

  const displayed = filterClass === "ALL"
    ? predictions
    : predictions.filter(p => p.predictedClass === filterClass);

  const sel = selected || predictions[0];
  const topClass = sel
    ? Object.entries(sel.classProbabilities).sort((a, b) => b[1] - a[1])[0]?.[0]
    : null;

  const alertRate = statsWindow.total ? ((statsWindow.alerts / statsWindow.total) * 100).toFixed(1) : "0.0";

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