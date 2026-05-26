import { useState, useEffect, useRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchTrafficStats } from '../api/capture';

/* ── Colour palette (matches existing terminal aesthetic) ── */
const C = {
  bg:       '#0a0c0f',
  panel:    '#0f1318',
  border:   '#1e2a35',
  bright:   '#2a3d52',
  text:     '#e2eaf4',
  textDim:  '#8aa0b8',
  muted:    '#4a6480',
  dim:      '#2d4156',
  amber:    '#f0c000',
  green:    '#00c07a',
  greenDim: 'rgba(0,192,122,0.12)',
  cyan:     '#00d4ff',
  red:      '#ff3b5c',
};

const PROTOCOL_COLORS = {
  TCP:   '#00d4ff',
  UDP:   '#f0c000',
  ICMP:  '#ff7a00',
  HTTP:  '#00c07a',
  HTTPS: '#3b8aff',
  DNS:   '#c07aff',
  Other: '#4a6480',
};

const HISTORY_LEN = 40;
const WINDOW_LABELS = { '1m': '1m', '5m': '5m', '15m': '15m' };

/* ── Helpers ── */
function fmtNum(n = 0) {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 1_000)     return (n / 1_000).toFixed(1) + 'K';
  return String(Math.round(n));
}
function fmtBps(n = 0) {
  if (n >= 1e9)  return (n / 1e9).toFixed(2) + ' Gbps';
  if (n >= 1e6)  return (n / 1e6).toFixed(2) + ' Mbps';
  if (n >= 1e3)  return (n / 1e3).toFixed(1) + ' Kbps';
  return n + ' bps';
}
function padHistory(arr, len) {
  const padded = [...arr];
  while (padded.length < len) padded.unshift(0);
  return padded.slice(-len);
}

/* ── PulseDot ── */
function PulseDot({ active }) {
  return (
    <span style={{ position: 'relative', display: 'inline-flex', width: 10, height: 10 }}>
      {active && (
        <span style={{
          position: 'absolute', inset: 0,
          borderRadius: '50%',
          background: C.green,
          opacity: 0.4,
          animation: 'ping 1.2s cubic-bezier(0,0,0.2,1) infinite',
        }} />
      )}
      <span style={{
        width: 10, height: 10,
        borderRadius: '50%',
        background: active ? C.green : C.muted,
        display: 'inline-block',
        flexShrink: 0,
        boxShadow: active ? `0 0 6px ${C.green}` : 'none',
        transition: 'all 0.3s',
      }} />
    </span>
  );
}

/* ── SectionHeader ── */
function SectionHeader({ title, children }) {
  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      marginBottom: 14,
      paddingBottom: 10,
      borderBottom: `1px solid ${C.border}`,
    }}>
      <span style={{
        fontSize: 10,
        fontWeight: 600,
        letterSpacing: '0.12em',
        textTransform: 'uppercase',
        color: C.textDim,
      }}>
        {title}
      </span>
      {children}
    </div>
  );
}

/* ── Sparkline SVG ── */
function Sparkline({ data, color, height = 60 }) {
  const W = 400;
  const max = Math.max(...data, 1);
  const pts = data.map((v, i) => {
    const x = (i / Math.max(data.length - 1, 1)) * W;
    const y = height - (v / max) * height * 0.9;
    return `${x},${y}`;
  }).join(' ');
  const area = `0,${height} ${pts} ${W},${height}`;
  const gradId = `sg${color.replace(/[^a-z0-9]/gi, '')}`;

  return (
    <svg viewBox={`0 0 ${W} ${height}`} style={{ width: '100%', height, display: 'block' }}>
      <defs>
        <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%"   stopColor={color} stopOpacity="0.25" />
          <stop offset="100%" stopColor={color} stopOpacity="0.02" />
        </linearGradient>
      </defs>
      <polygon points={area} fill={`url(#${gradId})`} />
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

/* ── Donut chart ── */
function DonutChart({ protos, total }) {
  const size = 90, r = 36, cx = 45, cy = 45;
  const circ = 2 * Math.PI * r;
  const entries = Object.entries(protos || {}).filter(([, v]) => v > 0);
  let offset = 0;
  const segments = entries.map(([name, val]) => {
    const frac  = total > 0 ? val / total : 0;
    const dash  = frac * circ;
    const gap   = circ - dash;
    const seg   = { name, val, dash, gap, offset, color: PROTOCOL_COLORS[name] || C.muted };
    offset += dash;
    return seg;
  });

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ flexShrink: 0 }}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={C.border} strokeWidth="10" />
      {segments.map(s => (
        <circle
          key={s.name}
          cx={cx} cy={cy} r={r}
          fill="none"
          stroke={s.color}
          strokeWidth="10"
          strokeDasharray={`${s.dash} ${s.gap}`}
          strokeDashoffset={-s.offset}
          style={{ transform: 'rotate(-90deg)', transformOrigin: `${cx}px ${cy}px` }}
        />
      ))}
      <text x={cx} y={cy - 4} textAnchor="middle" fill={C.text}
        fontSize="11" fontFamily="monospace" fontWeight="600">
        {fmtNum(total)}
      </text>
      <text x={cx} y={cy + 10} textAnchor="middle" fill={C.muted}
        fontSize="8" fontFamily="monospace">
        pkt/s
      </text>
    </svg>
  );
}

/* ── Protocol row ── */
function ProtoRow({ name, val, pct, color }) {
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
        <span style={{ fontSize: 11, fontFamily: 'monospace', color: C.text }}>{name}</span>
        <span style={{ fontSize: 11, fontFamily: 'monospace', color: C.textDim }}>
          {fmtNum(val)}{' '}
          <span style={{ color: C.muted }}>({(pct * 100).toFixed(1)}%)</span>
        </span>
      </div>
      <div style={{ height: 3, background: C.border, borderRadius: 2 }}>
        <div style={{
          height: '100%',
          width: `${pct * 100}%`,
          background: color,
          borderRadius: 2,
          transition: 'width 0.6s ease',
        }} />
      </div>
    </div>
  );
}

/* ── Stat card ── */
function StatCard({ label, value, sub, color, history }) {
  return (
    <div style={{
      background: C.panel,
      border: `1px solid ${C.border}`,
      borderTop: `2px solid ${color}`,
      borderRadius: 4,
      padding: '16px 20px',
      display: 'flex',
      flexDirection: 'column',
      gap: 6,
    }}>
      <span style={{
        fontSize: 10,
        letterSpacing: '0.1em',
        textTransform: 'uppercase',
        color: C.muted,
      }}>
        {label}
      </span>
      <span style={{
        fontSize: 22,
        fontWeight: 700,
        fontFamily: "'Syne', sans-serif",
        color: C.text,
        lineHeight: 1,
      }}>
        {value}
      </span>
      {history && history.length > 1 && (
        <div style={{ marginTop: 4 }}>
          <Sparkline data={history} color={color} height={28} />
        </div>
      )}
      <span style={{ fontSize: 10, color: C.muted }}>{sub}</span>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════
   Main component
═══════════════════════════════════════════════════════════ */
export default function TrafficMonitor() {
  const [capturing, setCapturing] = useState(true);
  const [blink, setBlink]         = useState(true);
  const [elapsed, setElapsed]     = useState(0);
  const [window_, setWindow_]     = useState('1m');
  const [ppsHistory, setPpsHistory] = useState(Array(HISTORY_LEN).fill(0));
  const [bpsHistory, setBpsHistory] = useState(Array(HISTORY_LEN).fill(0));
  const elapsedRef = useRef(0);

  /* ── Poll /capture/stats every 5 s ── */
  const { data: stats, isError, isFetching } = useQuery({
    queryKey: ['traffic', 'stats'],
    queryFn:  fetchTrafficStats,
    staleTime:      4_000,
    refetchInterval: capturing ? 5_000 : false,
    enabled: capturing,
  });

  /* ── Accumulate sparkline history from real API data ── */
  useEffect(() => {
    if (!stats) return;
    setPpsHistory(prev =>
      padHistory([...prev, stats.packets_per_sec ?? 0], HISTORY_LEN)
    );
    setBpsHistory(prev =>
      padHistory([...prev, stats.bytes_per_sec ?? 0], HISTORY_LEN)
    );
  }, [stats]);

  /* ── Blink cursor ── */
  useEffect(() => {
    const id = setInterval(() => setBlink(b => !b), 600);
    return () => clearInterval(id);
  }, []);

  /* ── Session elapsed timer ── */
  useEffect(() => {
    if (!capturing) return;
    const id = setInterval(() => {
      elapsedRef.current += 1;
      setElapsed(elapsedRef.current);
    }, 1000);
    return () => clearInterval(id);
  }, [capturing]);

  /* ── Derived values from real API ── */
  const pps    = stats?.packets_per_sec ?? 0;
  const bps    = stats?.bytes_per_sec   ?? 0;
  const protos = stats?.protocol_distribution ?? {};
  const rawIPs = stats?.top_source_ips ?? [];

  // Normalise: API may return strings or {ip, pps} objects
  const topIPs = rawIPs.map(entry =>
    typeof entry === 'string' ? { ip: entry, pps: 0 } : entry
  );

  const total        = Object.values(protos).reduce((a, b) => a + b, 0);
  const protoEntries = Object.entries(protos).sort(([, a], [, b]) => b - a);

  /* ── Format elapsed ── */
  const mm = String(Math.floor(elapsed / 60)).padStart(2, '0');
  const ss = String(elapsed % 60).padStart(2, '0');

  return (
    <div style={{
      minHeight: '100vh',
      background: C.bg,
      padding: '0 0 40px',
      fontFamily: "'JetBrains Mono', monospace",
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
        padding: '12px 28px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        position: 'sticky',
        top: 0,
        zIndex: 10,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <PulseDot active={capturing} />
          <span style={{ fontSize: 12, color: C.text, letterSpacing: '0.06em' }}>
            TRAFFIC MONITOR
          </span>
          <span style={{
            fontSize: 11,
            color: capturing ? C.green : C.muted,
            borderLeft: `1px solid ${C.border}`,
            paddingLeft: 14,
          }}>
            {capturing ? `LIVE${blink ? ' ▮' : '  '}` : 'PAUSED'}
          </span>
          {isError && (
            <span style={{ fontSize: 11, color: C.red, paddingLeft: 14 }}>
              ⚠ API unreachable
            </span>
          )}
          {isFetching && !isError && (
            <span style={{ fontSize: 11, color: C.cyan, paddingLeft: 14 }}>
              ↻
            </span>
          )}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          {/* Time window selector */}
          <div style={{ display: 'flex', gap: 4 }}>
            {Object.keys(WINDOW_LABELS).map(w => (
              <button
                key={w}
                className="window-btn"
                onClick={() => setWindow_(w)}
                style={{
                  padding: '4px 10px',
                  fontSize: 11,
                  fontFamily: 'monospace',
                  background: 'transparent',
                  border: `1px solid ${window_ === w ? C.amber : C.border}`,
                  color: window_ === w ? C.amber : C.textDim,
                  borderRadius: 3,
                  outline: 'none',
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
              padding: '4px 14px',
              fontSize: 11,
              fontFamily: 'monospace',
              background: capturing ? C.greenDim : C.border,
              border: `1px solid ${capturing ? C.green : C.border}`,
              color: capturing ? C.green : C.textDim,
              borderRadius: 3,
              outline: 'none',
              letterSpacing: '0.05em',
            }}
          >
            {capturing ? '■ STOP' : '▶ CAPTURE'}
          </button>
        </div>
      </div>

      <div style={{ padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: 24 }}>

        {/* ── Stat cards row ── */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: 16,
          animation: 'fadeSlideIn 0.4s ease',
        }}>
          <StatCard
            label="Packets / sec"
            value={fmtNum(pps)}
            sub={`peak ${fmtNum(Math.max(...ppsHistory))} pkt/s`}
            color={C.amber}
            history={ppsHistory}
          />
          <StatCard
            label="Throughput"
            value={fmtBps(bps)}
            sub={`window: ${window_}`}
            color={C.green}
            history={bpsHistory.map(v => v / 1e6)}
          />
          <StatCard
            label="Active Protocols"
            value={protoEntries.length || '—'}
            sub="distinct protocol types"
            color={C.cyan}
          />
          <StatCard
            label="Uptime"
            value={`${mm}:${ss}`}
            sub="session elapsed"
            color={C.textDim}
          />
        </div>

        {/* ── Protocol breakdown + Top IPs ── */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: 16,
        }}>

          {/* Protocol panel */}
          <div style={{
            background: C.panel,
            border: `1px solid ${C.border}`,
            borderRadius: 4,
            padding: '20px 24px',
          }}>
            <SectionHeader title="Protocol Distribution">
              <span style={{ fontSize: 11, color: C.textDim }}>
                {fmtNum(total)} pkt/s total
              </span>
            </SectionHeader>

            {protoEntries.length === 0 ? (
              <div style={{ color: C.muted, fontSize: 11, textAlign: 'center', padding: '20px 0' }}>
                {capturing ? 'Waiting for traffic data…' : 'Capture stopped'}
              </div>
            ) : (
              <div style={{ display: 'flex', gap: 24, alignItems: 'flex-start' }}>
                <DonutChart protos={protos} total={total} />
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
            )}

            {/* Legend chips */}
            {protoEntries.length > 0 && (
              <div style={{
                display: 'flex',
                flexWrap: 'wrap',
                gap: 8,
                marginTop: 16,
                paddingTop: 12,
                borderTop: `1px solid ${C.border}`,
              }}>
                {protoEntries.map(([name]) => (
                  <span key={name} style={{
                    display: 'flex', alignItems: 'center', gap: 5,
                    fontSize: 10, color: C.textDim,
                  }}>
                    <span style={{
                      width: 8, height: 8,
                      borderRadius: '50%',
                      background: PROTOCOL_COLORS[name] || C.muted,
                      display: 'inline-block',
                    }} />
                    {name}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Top IPs panel */}
          <div style={{
            background: C.panel,
            border: `1px solid ${C.border}`,
            borderRadius: 4,
            padding: '20px 24px',
            display: 'flex',
            flexDirection: 'column',
          }}>
            <SectionHeader title="Top Source IPs">
              <span style={{ fontSize: 11, color: C.textDim }}>by packet rate</span>
            </SectionHeader>

            {/* Table header */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: '1fr 80px 60px',
              gap: 8,
              padding: '0 10px 8px',
              borderBottom: `1px solid ${C.border}`,
              marginBottom: 4,
            }}>
              {['IP ADDRESS', 'PKT/S', 'SHARE'].map(h => (
                <span key={h} style={{
                  fontSize: 10,
                  color: C.muted,
                  letterSpacing: '0.08em',
                  textAlign: h !== 'IP ADDRESS' ? 'right' : 'left',
                }}>
                  {h}
                </span>
              ))}
            </div>

            {topIPs.length === 0 ? (
              <div style={{ color: C.muted, fontSize: 11, textAlign: 'center', padding: '20px 0' }}>
                {capturing ? 'Waiting for traffic data…' : 'Capture stopped'}
              </div>
            ) : (
              topIPs.map((row, i) => {
                const share  = pps > 0 ? ((row.pps / pps) * 100).toFixed(1) : '—';
                const isHigh = row.pps > 300;
                return (
                  <div
                    key={row.ip}
                    className="ip-row"
                    style={{
                      display: 'grid',
                      gridTemplateColumns: '1fr 80px 60px',
                      gap: 8,
                      padding: '7px 10px',
                      borderRadius: 3,
                      alignItems: 'center',
                      background: 'transparent',
                      transition: 'background 0.15s',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
                      <span style={{ fontSize: 10, color: C.dim, width: 14, flexShrink: 0 }}>
                        {i + 1}
                      </span>
                      <span style={{
                        fontSize: 12,
                        fontFamily: 'monospace',
                        color: isHigh ? C.amber : C.text,
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}>
                        {row.ip}
                      </span>
                      {isHigh && (
                        <span style={{
                          fontSize: 9,
                          color: C.red,
                          border: `1px solid ${C.red}`,
                          borderRadius: 2,
                          padding: '0 4px',
                          flexShrink: 0,
                          letterSpacing: '0.05em',
                        }}>
                          HIGH
                        </span>
                      )}
                    </div>
                    <div style={{ textAlign: 'right' }}>
                      <span style={{
                        fontSize: 12,
                        fontFamily: 'monospace',
                        color: isHigh ? C.amber : C.text,
                      }}>
                        {row.pps > 0 ? fmtNum(row.pps) : '—'}
                      </span>
                    </div>
                    <div style={{ textAlign: 'right' }}>
                      <span style={{ fontSize: 11, fontFamily: 'monospace', color: C.textDim }}>
                        {share !== '—' ? `${share}%` : '—'}
                      </span>
                    </div>
                  </div>
                );
              })
            )}

            <div style={{
              marginTop: 'auto',
              paddingTop: 12,
              borderTop: `1px solid ${C.border}`,
            }}>
              <span style={{ fontSize: 10, color: C.muted, letterSpacing: '0.06em' }}>
                SHOWING TOP {topIPs.length} ACTIVE SOURCES
              </span>
            </div>
          </div>
        </div>

        {/* ── Sparkline history row ── */}
        <div style={{
          background: C.panel,
          border: `1px solid ${C.border}`,
          borderRadius: 4,
          padding: '20px 24px',
        }}>
          <SectionHeader title="Traffic History (last 40 ticks)">
            <div style={{ display: 'flex', gap: 16 }}>
              <span style={{ fontSize: 11, color: C.amber, display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ width: 16, height: 2, background: C.amber, display: 'inline-block' }} />
                PKT/S
              </span>
              <span style={{ fontSize: 11, color: C.green, display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ width: 16, height: 2, background: C.green, display: 'inline-block' }} />
                MBPS
              </span>
            </div>
          </SectionHeader>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div>
              <div style={{ fontSize: 10, color: C.muted, marginBottom: 6 }}>PACKETS PER SECOND</div>
              <Sparkline data={ppsHistory} color={C.amber} height={60} />
              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4 }}>
                <span style={{ fontSize: 10, color: C.muted }}>
                  min {fmtNum(Math.min(...ppsHistory))}
                </span>
                <span style={{ fontSize: 10, color: C.amber }}>
                  {fmtNum(pps)} now
                </span>
                <span style={{ fontSize: 10, color: C.muted }}>
                  max {fmtNum(Math.max(...ppsHistory))}
                </span>
              </div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: C.muted, marginBottom: 6 }}>THROUGHPUT (MBPS)</div>
              <Sparkline data={bpsHistory.map(v => v / 1e6)} color={C.green} height={60} />
              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4 }}>
                <span style={{ fontSize: 10, color: C.muted }}>
                  min {(Math.min(...bpsHistory) / 1e6).toFixed(1)}
                </span>
                <span style={{ fontSize: 10, color: C.green }}>
                  {(bps / 1e6).toFixed(1)} now
                </span>
                <span style={{ fontSize: 10, color: C.muted }}>
                  max {(Math.max(...bpsHistory) / 1e6).toFixed(1)}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* ── Status footer ── */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '10px 16px',
          background: C.panel,
          border: `1px solid ${C.border}`,
          borderRadius: 4,
          fontSize: 10,
          color: C.muted,
          letterSpacing: '0.06em',
        }}>
          <span>AI-NIDS :: TRAFFIC MONITOR</span>
          <div style={{ display: 'flex', gap: 24 }}>
            <span>INTERFACE: eth0 (PCAP MODE)</span>
            <span>POLL: 5s</span>
            <span style={{ color: capturing ? C.green : C.muted }}>
              {capturing ? '● CAPTURING' : '○ STOPPED'}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}