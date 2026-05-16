import { useState, useEffect, useRef, useCallback } from "react";

// ─── Colour tokens ────────────────────────────────────────────────────────────
const C = {
  bg:        "#0a0c0f",
  panel:     "#0f1318",
  border:    "#1c2230",
  borderHi:  "#2a3548",
  amber:     "#e8a030",
  amberDim:  "#8a5c18",
  green:     "#2dd4a0",
  greenDim:  "#155c44",
  red:       "#e84040",
  blue:      "#3a7bd5",
  purple:    "#8b5cf6",
  cyan:      "#22d3ee",
  yellow:    "#fbbf24",
  muted:     "#4a5568",
  text:      "#c8d6e8",
  textDim:   "#6a7d94",
};

const PROTOCOL_COLORS = {
  TCP:   C.blue,
  UDP:   C.green,
  HTTP:  C.amber,
  HTTPS: C.cyan,
  DNS:   C.purple,
  ICMP:  C.red,
  Other: C.muted,
};

const WINDOW_LABELS = { "1m": 60, "5m": 300, "1h": 3600 };

// ─── Simulation helpers ───────────────────────────────────────────────────────
function randomBetween(a, b) { return Math.floor(Math.random() * (b - a + 1)) + a; }
function jitter(base, pct = 0.15) {
  return Math.max(0, base + (Math.random() - 0.5) * 2 * base * pct);
}

function generateTick(prev) {
  const pps = Math.floor(jitter(prev?.pps ?? 8200, 0.12));
  const bps = Math.floor(jitter(prev?.bps ?? 42_000_000, 0.10));
  const active = Math.floor(jitter(prev?.active ?? 1240, 0.08));
  const total = pps;

  const protos = {
    TCP:   Math.floor(total * jitter(0.52, 0.05)),
    UDP:   Math.floor(total * jitter(0.18, 0.05)),
    HTTP:  Math.floor(total * jitter(0.12, 0.06)),
    HTTPS: Math.floor(total * jitter(0.09, 0.05)),
    DNS:   Math.floor(total * jitter(0.06, 0.05)),
    ICMP:  Math.floor(total * jitter(0.02, 0.10)),
  };
  protos.Other = Math.max(0, total - Object.values(protos).reduce((a,b) => a+b, 0));

  return { pps, bps, active, protos, ts: Date.now() };
}

function fmtBps(bps) {
  if (bps >= 1e9) return (bps / 1e9).toFixed(2) + " Gbps";
  if (bps >= 1e6) return (bps / 1e6).toFixed(1) + " Mbps";
  if (bps >= 1e3) return (bps / 1e3).toFixed(0) + " Kbps";
  return bps + " bps";
}

function fmtNum(n) {
  if (n >= 1e6) return (n/1e6).toFixed(1) + "M";
  if (n >= 1e3) return (n/1e3).toFixed(1) + "K";
  return String(n);
}

const SEED_IPS = [
  { ip: "203.178.145.12", country: "CN", pps: 420 },
  { ip: "185.220.101.47", country: "RU", pps: 315 },
  { ip: "192.168.1.254",  country: "LAN", pps: 280 },
  { ip: "94.102.49.193",  country: "NL", pps: 198 },
  { ip: "198.51.100.77",  country: "US", pps: 167 },
  { ip: "45.83.66.132",   country: "DE", pps: 134 },
  { ip: "10.0.0.1",       country: "LAN", pps: 98 },
  { ip: "172.16.45.201",  country: "LAN", pps: 76 },
];

function jitterIPs(ips) {
  return ips.map(row => ({
    ...row,
    pps: Math.max(1, Math.floor(jitter(row.pps, 0.12))),
  })).sort((a, b) => b.pps - a.pps);
}

// ─── Sparkline ────────────────────────────────────────────────────────────────
function Sparkline({ data, color, height = 40 }) {
  if (!data || data.length < 2) return null;
  const max = Math.max(...data, 1);
  const min = Math.min(...data);
  const range = max - min || 1;
  const w = 200, h = height;
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * w;
    const y = h - ((v - min) / range) * (h - 4) - 2;
    return `${x},${y}`;
  }).join(" ");

  return (
    <svg viewBox={`0 0 ${w} ${h}`} style={{ width: "100%", height: h }}>
      <defs>
        <linearGradient id={`sg-${color.replace("#","")}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.25" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <polyline
        points={pts}
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
      <polygon
        points={`0,${h} ${pts} ${w},${h}`}
        fill={`url(#sg-${color.replace("#","")})`}
      />
    </svg>
  );
}

// ─── Donut chart ──────────────────────────────────────────────────────────────
function DonutChart({ protos, total }) {
  const r = 54, cx = 64, cy = 64, stroke = 14;
  const circumference = 2 * Math.PI * r;
  let offset = 0;

  const slices = Object.entries(protos).map(([name, val]) => {
    const pct = total > 0 ? val / total : 0;
    const dash = pct * circumference;
    const gap  = circumference - dash;
    const slice = { name, val, pct, dash, gap, offset, color: PROTOCOL_COLORS[name] || C.muted };
    offset += dash;
    return slice;
  });

  return (
    <svg viewBox="0 0 128 128" style={{ width: 128, height: 128, flexShrink: 0 }}>
      {/* Background ring */}
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={C.border} strokeWidth={stroke} />
      {slices.map(s => (
        <circle
          key={s.name}
          cx={cx} cy={cy} r={r}
          fill="none"
          stroke={s.color}
          strokeWidth={stroke}
          strokeDasharray={`${s.dash} ${s.gap}`}
          strokeDashoffset={-s.offset}
          transform={`rotate(-90 ${cx} ${cy})`}
          style={{ transition: "stroke-dasharray 0.4s ease" }}
        />
      ))}
      {/* Centre label */}
      <text x={cx} y={cy - 6} textAnchor="middle" fill={C.text}
        style={{ font: `bold 14px 'Courier New', monospace` }}>
        {fmtNum(total)}
      </text>
      <text x={cx} y={cy + 10} textAnchor="middle" fill={C.textDim}
        style={{ font: `10px 'Courier New', monospace` }}>
        pkt/s
      </text>
    </svg>
  );
}

// ─── Stat card ────────────────────────────────────────────────────────────────
function StatCard({ label, value, sub, color, history, unit }) {
  return (
    <div style={{
      background: C.panel,
      border: `1px solid ${C.border}`,
      borderTop: `2px solid ${color}`,
      borderRadius: 4,
      padding: "16px 20px 10px",
      display: "flex",
      flexDirection: "column",
      gap: 4,
      minWidth: 0,
    }}>
      <span style={{ fontSize: 11, color: C.textDim, letterSpacing: "0.08em", textTransform: "uppercase", fontFamily: "monospace" }}>
        {label}
      </span>
      <span style={{ fontSize: 28, fontWeight: 700, color, fontFamily: "'Courier New', monospace", letterSpacing: "-0.02em", lineHeight: 1.1 }}>
        {value}
      </span>
      {sub && (
        <span style={{ fontSize: 12, color: C.textDim, fontFamily: "monospace" }}>{sub}</span>
      )}
      {history && <Sparkline data={history} color={color} height={36} />}
    </div>
  );
}

// ─── Protocol row ─────────────────────────────────────────────────────────────
function ProtoRow({ name, val, pct, color }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "52px 1fr 52px 52px", alignItems: "center", gap: 8, marginBottom: 8 }}>
      <span style={{ fontSize: 11, fontFamily: "monospace", color: C.text, fontWeight: 600 }}>{name}</span>
      <div style={{ background: C.border, borderRadius: 2, height: 5, overflow: "hidden" }}>
        <div style={{
          width: `${(pct * 100).toFixed(1)}%`,
          height: "100%",
          background: color,
          borderRadius: 2,
          transition: "width 0.5s ease",
        }} />
      </div>
      <span style={{ fontSize: 11, fontFamily: "monospace", color: C.textDim, textAlign: "right" }}>
        {(pct * 100).toFixed(1)}%
      </span>
      <span style={{ fontSize: 11, fontFamily: "monospace", color, textAlign: "right" }}>
        {fmtNum(val)}
      </span>
    </div>
  );
}

// ─── Country badge ────────────────────────────────────────────────────────────
function CountryBadge({ code }) {
  const isLAN = code === "LAN";
  return (
    <span style={{
      fontSize: 10,
      fontFamily: "monospace",
      padding: "1px 5px",
      borderRadius: 2,
      background: isLAN ? C.greenDim : C.border,
      color: isLAN ? C.green : C.textDim,
      letterSpacing: "0.05em",
    }}>
      {code}
    </span>
  );
}

// ─── Pulse dot ────────────────────────────────────────────────────────────────
function PulseDot({ active }) {
  return (
    <span style={{ position: "relative", display: "inline-flex", alignItems: "center", justifyContent: "center", width: 10, height: 10 }}>
      {active && (
        <span style={{
          position: "absolute",
          inset: 0,
          borderRadius: "50%",
          background: C.green,
          opacity: 0.3,
          animation: "ping 1.4s cubic-bezier(0,0,0.2,1) infinite",
        }} />
      )}
      <span style={{
        width: 6, height: 6,
        borderRadius: "50%",
        background: active ? C.green : C.muted,
        display: "inline-block",
      }} />
    </span>
  );
}

// ─── Section header ───────────────────────────────────────────────────────────
function SectionHeader({ title, children }) {
  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      marginBottom: 14,
      paddingBottom: 10,
      borderBottom: `1px solid ${C.border}`,
    }}>
      <span style={{
        fontSize: 11,
        fontFamily: "monospace",
        color: C.textDim,
        letterSpacing: "0.12em",
        textTransform: "uppercase",
        fontWeight: 600,
      }}>
        {title}
      </span>
      {children}
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────
export default function TrafficMonitor() {
  const [window_, setWindow_] = useState("1m");
  const [tick, setTick]       = useState(() => generateTick(null));
  const [ppsHistory, setPpsHistory]   = useState(() => Array(40).fill(8200));
  const [bpsHistory, setBpsHistory]   = useState(() => Array(40).fill(42_000_000));
  const [topIPs, setTopIPs]           = useState(() => jitterIPs(SEED_IPS));
  const [capturing, setCapturing]     = useState(true);
  const [elapsed, setElapsed]         = useState(0);
  const tickRef = useRef(tick);
  tickRef.current = tick;

  // Simulation tick every 1.2s
  useEffect(() => {
    if (!capturing) return;
    const id = setInterval(() => {
      const next = generateTick(tickRef.current);
      setTick(next);
      setPpsHistory(h => [...h.slice(-39), next.pps]);
      setBpsHistory(h => [...h.slice(-39), next.bps]);
      setTopIPs(ips => jitterIPs(ips));
      setElapsed(e => e + 1);
    }, 1200);
    return () => clearInterval(id);
  }, [capturing]);

  const total = tick.pps;
  const protoEntries = Object.entries(tick.protos);

  // Blinking cursor
  const [blink, setBlink] = useState(true);
  useEffect(() => {
    const id = setInterval(() => setBlink(b => !b), 600);
    return () => clearInterval(id);
  }, []);

  return (
    <div style={{
      minHeight: "100vh",
      background: C.bg,
      padding: "0 0 40px",
      fontFamily: "'Courier New', Courier, monospace",
      color: C.text,
    }}>
      <style>{`
        @keyframes ping {
          75%, 100% { transform: scale(2); opacity: 0; }
        }
        @keyframes fadeSlideIn {
          from { opacity: 0; transform: translateY(6px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: ${C.bg}; }
        ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 2px; }
        .ip-row:hover { background: ${C.border} !important; }
        .window-btn { cursor: pointer; transition: all 0.15s; }
        .window-btn:hover { border-color: ${C.amber} !important; color: ${C.amber} !important; }
        .capture-btn { cursor: pointer; transition: all 0.15s; }
        .capture-btn:hover { opacity: 0.8; }
      `}</style>

      {/* ── Header bar ── */}
      <div style={{
        background: C.panel,
        borderBottom: `1px solid ${C.border}`,
        padding: "12px 28px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        position: "sticky",
        top: 0,
        zIndex: 10,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <PulseDot active={capturing} />
          <span style={{ fontSize: 12, color: C.text, letterSpacing: "0.06em" }}>
            TRAFFIC MONITOR
          </span>
          <span style={{
            fontSize: 11,
            color: capturing ? C.green : C.muted,
            borderLeft: `1px solid ${C.border}`,
            paddingLeft: 14,
          }}>
            {capturing ? `LIVE${blink ? " ▮" : "  "}` : "PAUSED"}
          </span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          {/* Time window selector */}
          <div style={{ display: "flex", gap: 4 }}>
            {Object.keys(WINDOW_LABELS).map(w => (
              <button
                key={w}
                className="window-btn"
                onClick={() => setWindow_(w)}
                style={{
                  padding: "4px 10px",
                  fontSize: 11,
                  fontFamily: "monospace",
                  background: "transparent",
                  border: `1px solid ${window_ === w ? C.amber : C.border}`,
                  color: window_ === w ? C.amber : C.textDim,
                  borderRadius: 3,
                  outline: "none",
                }}
              >
                {w}
              </button>
            ))}
          </div>

          {/* Capture toggle */}
          <button
            className="capture-btn"
            onClick={() => setCapturing(c => !c)}
            style={{
              padding: "4px 14px",
              fontSize: 11,
              fontFamily: "monospace",
              background: capturing ? C.greenDim : C.border,
              border: `1px solid ${capturing ? C.green : C.border}`,
              color: capturing ? C.green : C.textDim,
              borderRadius: 3,
              outline: "none",
              letterSpacing: "0.05em",
            }}
          >
            {capturing ? "■ STOP" : "▶ CAPTURE"}
          </button>
        </div>
      </div>

      <div style={{ padding: "24px 28px", display: "flex", flexDirection: "column", gap: 24 }}>

        {/* ── Stat cards row ── */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
          gap: 16,
          animation: "fadeSlideIn 0.4s ease",
        }}>
          <StatCard
            label="Packets / sec"
            value={fmtNum(tick.pps)}
            sub={`peak ${fmtNum(Math.max(...ppsHistory))} pkt/s`}
            color={C.amber}
            history={ppsHistory}
          />
          <StatCard
            label="Throughput"
            value={fmtBps(tick.bps)}
            sub={`window: ${window_}`}
            color={C.green}
            history={bpsHistory.map(v => v / 1e6)}
          />
          <StatCard
            label="Active Flows"
            value={fmtNum(tick.active)}
            sub="bidirectional 5-tuple"
            color={C.cyan}
          />
          <StatCard
            label="Uptime"
            value={`${String(Math.floor(elapsed / 60)).padStart(2,"0")}:${String(elapsed % 60).padStart(2,"0")}`}
            sub="session elapsed"
            color={C.textDim}
          />
        </div>

        {/* ── Protocol breakdown + Top IPs ── */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: 16,
        }}>
          {/* Protocol panel */}
          <div style={{
            background: C.panel,
            border: `1px solid ${C.border}`,
            borderRadius: 4,
            padding: "20px 24px",
          }}>
            <SectionHeader title="Protocol Distribution">
              <span style={{ fontSize: 11, color: C.textDim }}>
                {fmtNum(total)} pkt/s total
              </span>
            </SectionHeader>

            <div style={{ display: "flex", gap: 24, alignItems: "flex-start" }}>
              <DonutChart protos={tick.protos} total={total} />

              <div style={{ flex: 1, minWidth: 0 }}>
                {protoEntries.map(([name, val]) => (
                  <ProtoRow
                    key={name}
                    name={name}
                    val={val}
                    pct={total > 0 ? val / total : 0}
                    color={PROTOCOL_COLORS[name] || C.muted}
                  />
                ))}
              </div>
            </div>

            {/* Legend chips */}
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 16, paddingTop: 12, borderTop: `1px solid ${C.border}` }}>
              {protoEntries.map(([name]) => (
                <span key={name} style={{
                  display: "flex", alignItems: "center", gap: 5,
                  fontSize: 10, color: C.textDim, fontFamily: "monospace",
                }}>
                  <span style={{ width: 8, height: 8, borderRadius: "50%", background: PROTOCOL_COLORS[name] || C.muted, display: "inline-block" }} />
                  {name}
                </span>
              ))}
            </div>
          </div>

          {/* Top IPs panel */}
          <div style={{
            background: C.panel,
            border: `1px solid ${C.border}`,
            borderRadius: 4,
            padding: "20px 24px",
            display: "flex",
            flexDirection: "column",
          }}>
            <SectionHeader title="Top Source IPs">
              <span style={{ fontSize: 11, color: C.textDim }}>by packet rate</span>
            </SectionHeader>

            {/* Table header */}
            <div style={{
              display: "grid",
              gridTemplateColumns: "1fr 60px 80px 60px",
              gap: 8,
              padding: "0 10px 8px",
              borderBottom: `1px solid ${C.border}`,
              marginBottom: 4,
            }}>
              {["IP ADDRESS", "ORIGIN", "PKT/S", "SHARE"].map(h => (
                <span key={h} style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.08em", textAlign: h === "PKT/S" || h === "SHARE" ? "right" : "left" }}>
                  {h}
                </span>
              ))}
            </div>

            {topIPs.map((row, i) => {
              const share = tick.pps > 0 ? (row.pps / tick.pps * 100).toFixed(1) : "0.0";
              const isHigh = row.pps > 300;
              return (
                <div
                  key={row.ip}
                  className="ip-row"
                  style={{
                    display: "grid",
                    gridTemplateColumns: "1fr 60px 80px 60px",
                    gap: 8,
                    padding: "7px 10px",
                    borderRadius: 3,
                    alignItems: "center",
                    background: "transparent",
                    transition: "background 0.15s",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
                    <span style={{
                      fontSize: 10,
                      color: C.textDim,
                      width: 14,
                      flexShrink: 0,
                    }}>{i + 1}</span>
                    <span style={{
                      fontSize: 12,
                      fontFamily: "monospace",
                      color: isHigh ? C.amber : C.text,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}>
                      {row.ip}
                    </span>
                    {isHigh && (
                      <span style={{
                        fontSize: 9,
                        color: C.red,
                        border: `1px solid ${C.red}`,
                        borderRadius: 2,
                        padding: "0 4px",
                        flexShrink: 0,
                        letterSpacing: "0.05em",
                      }}>
                        HIGH
                      </span>
                    )}
                  </div>

                  <CountryBadge code={row.country} />

                  <div style={{ textAlign: "right" }}>
                    <span style={{ fontSize: 12, fontFamily: "monospace", color: isHigh ? C.amber : C.text }}>
                      {fmtNum(row.pps)}
                    </span>
                  </div>

                  <div style={{ textAlign: "right" }}>
                    <span style={{ fontSize: 11, fontFamily: "monospace", color: C.textDim }}>
                      {share}%
                    </span>
                  </div>
                </div>
              );
            })}

            <div style={{ marginTop: "auto", paddingTop: 12, borderTop: `1px solid ${C.border}` }}>
              <span style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.06em" }}>
                SHOWING TOP {topIPs.length} OF ALL ACTIVE SOURCES
              </span>
            </div>
          </div>
        </div>

        {/* ── Sparkline history row ── */}
        <div style={{
          background: C.panel,
          border: `1px solid ${C.border}`,
          borderRadius: 4,
          padding: "20px 24px",
        }}>
          <SectionHeader title="Traffic History (last 40 ticks)">
            <div style={{ display: "flex", gap: 16 }}>
              <span style={{ fontSize: 11, color: C.amber, display: "flex", alignItems: "center", gap: 6 }}>
                <span style={{ width: 16, height: 2, background: C.amber, display: "inline-block" }} />
                PKT/S
              </span>
              <span style={{ fontSize: 11, color: C.green, display: "flex", alignItems: "center", gap: 6 }}>
                <span style={{ width: 16, height: 2, background: C.green, display: "inline-block" }} />
                MBPS
              </span>
            </div>
          </SectionHeader>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            <div>
              <div style={{ fontSize: 10, color: C.textDim, marginBottom: 6 }}>PACKETS PER SECOND</div>
              <Sparkline data={ppsHistory} color={C.amber} height={60} />
              <div style={{ display: "flex", justifyContent: "space-between", marginTop: 4 }}>
                <span style={{ fontSize: 10, color: C.textDim }}>min {fmtNum(Math.min(...ppsHistory))}</span>
                <span style={{ fontSize: 10, color: C.amber }}>{fmtNum(tick.pps)} now</span>
                <span style={{ fontSize: 10, color: C.textDim }}>max {fmtNum(Math.max(...ppsHistory))}</span>
              </div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: C.textDim, marginBottom: 6 }}>THROUGHPUT (MBPS)</div>
              <Sparkline data={bpsHistory.map(v => v / 1e6)} color={C.green} height={60} />
              <div style={{ display: "flex", justifyContent: "space-between", marginTop: 4 }}>
                <span style={{ fontSize: 10, color: C.textDim }}>min {(Math.min(...bpsHistory)/1e6).toFixed(1)}</span>
                <span style={{ fontSize: 10, color: C.green }}>{(tick.bps/1e6).toFixed(1)} now</span>
                <span style={{ fontSize: 10, color: C.textDim }}>max {(Math.max(...bpsHistory)/1e6).toFixed(1)}</span>
              </div>
            </div>
          </div>
        </div>

        {/* ── Status footer ── */}
        <div style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "10px 16px",
          background: C.panel,
          border: `1px solid ${C.border}`,
          borderRadius: 4,
          fontSize: 10,
          color: C.textDim,
          fontFamily: "monospace",
          letterSpacing: "0.06em",
        }}>
          <span>AI-NIDS :: TRAFFIC MONITOR :: SPRINT 1</span>
          <div style={{ display: "flex", gap: 24 }}>
            <span>INTERFACE: eth0 (PCAP MODE)</span>
            <span>SAMPLE: 1.2s</span>
            <span style={{ color: capturing ? C.green : C.muted }}>
              {capturing ? "● CAPTURING" : "○ STOPPED"}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}