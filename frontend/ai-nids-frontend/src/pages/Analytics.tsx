/**
 * AI-NIDS — Analytics & Reports Page
 * File: frontend/src/pages/AnalyticsPage.tsx
 *
 * Features:
 *  - Alert trend chart (inline SVG sparkline)
 *  - Severity breakdown donut
 *  - Top attackers table (GET /api/v1/analytics/summary)
 *  - Attack category distribution bar chart
 *  - On-demand PDF report generation (POST /api/v1/reports/generate)
 *  - Time range selector: 24h / 7d / 30d
 */

import { useState, useEffect, useCallback } from "react";
import apiClient from "../api/client";

// ── Types ──────────────────────────────────────────────────────────────────

type TimeRange = "24h" | "7d" | "30d";

interface Summary {
  total_alerts: number;
  by_severity: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number };
  by_attack_type: Record<string, number>;
  top_src_ips: { ip: string; count: number; country?: string; last_seen: string }[];
  false_positive_rate: number;
  avg_confidence: number;
  alerts_per_hour: number[];
}

// ── Helpers ────────────────────────────────────────────────────────────────

const fmt = (n: number) => n.toLocaleString();
const pct = (n: number) => `${(n * 100).toFixed(1)}%`;

const SEV_COLORS = { CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#eab308", LOW: "#64748b" };
const ATTACK_COLORS = ["#3b82f6", "#8b5cf6", "#10b981", "#f59e0b", "#ef4444", "#06b6d4", "#ec4899", "#84cc16"];

const EMPTY_SUMMARY: Summary = {
  total_alerts: 0,
  by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
  by_attack_type: {},
  top_src_ips: [],
  false_positive_rate: 0,
  avg_confidence: 0,
  alerts_per_hour: Array(24).fill(0),
};

// ── Inline sparkline chart (SVG) ──────────────────────────────────────────

function SparkLine({ data, color = "#3b82f6", height = 80 }: { data: number[]; color?: string; height?: number }) {
  if (!data.length) return null;
  const w = 100, h = height;
  const max = Math.max(...data, 1);
  const step = w / (data.length - 1);
  const points = data.map((v, i) => `${i * step},${h - (v / max) * (h - 8)}`).join(" ");
  const area = `0,${h} ${points} ${w},${h}`;

  return (
    <svg viewBox={`0 0 ${w} ${h}`} style={{ width: "100%", height }} preserveAspectRatio="none">
      <defs>
        <linearGradient id={`grad-${color.replace("#","")}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.25" />
          <stop offset="100%" stopColor={color} stopOpacity="0.02" />
        </linearGradient>
      </defs>
      <polygon points={area} fill={`url(#grad-${color.replace("#","")})`} />
      <polyline points={points} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

// ── Severity donut ────────────────────────────────────────────────────────

function SeverityDonut({ data, total }: { data: Summary["by_severity"]; total: number }) {
  const segments = (Object.entries(data) as [keyof typeof SEV_COLORS, number][]);
  const r = 52, cx = 64, cy = 64, stroke = 14;
  const circumference = 2 * Math.PI * r;
  let offset = 0;

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 24, flexWrap: "wrap" }}>
      <svg width={128} height={128} viewBox="0 0 128 128">
        {segments.map(([sev, count]) => {
          const frac = count / (total || 1);
          const dash = circumference * frac;
          const gap = circumference - dash;
          const rot = offset * 360 - 90;
          offset += frac;
          return (
            <circle key={sev} cx={cx} cy={cy} r={r} fill="none"
              stroke={SEV_COLORS[sev]} strokeWidth={stroke}
              strokeDasharray={`${dash} ${gap}`}
              transform={`rotate(${rot} ${cx} ${cy})`} strokeLinecap="butt" />
          );
        })}
        <text x={cx} y={cy - 5} textAnchor="middle" fill="#f1f5f9" fontSize={14} fontWeight={700} fontFamily="'JetBrains Mono', monospace">{fmt(total)}</text>
        <text x={cx} y={cy + 12} textAnchor="middle" fill="#64748b" fontSize={9} fontFamily="'JetBrains Mono', monospace">TOTAL</text>
      </svg>
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {segments.map(([sev, count]) => (
          <div key={sev} style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ width: 8, height: 8, borderRadius: 2, background: SEV_COLORS[sev], flexShrink: 0 }} />
            <span style={{ fontSize: 12, color: "#94a3b8", width: 72 }}>{sev}</span>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: "#f1f5f9", fontWeight: 700 }}>{fmt(count)}</span>
            <span style={{ fontSize: 11, color: "#475569", fontFamily: "'JetBrains Mono', monospace" }}>
              {pct(count / (total || 1))}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Attack type bar chart ─────────────────────────────────────────────────

function AttackBars({ data }: { data: Record<string, number> }) {
  const sorted = Object.entries(data).sort((a, b) => b[1] - a[1]);
  const max = sorted[0]?.[1] || 1;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {sorted.map(([type, count], i) => (
        <div key={type} style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ fontSize: 12, color: "#94a3b8", width: 88, textAlign: "right", flexShrink: 0 }}>{type}</span>
          <div style={{ flex: 1, height: 8, background: "#1e293b", borderRadius: 999, overflow: "hidden" }}>
            <div style={{ height: "100%", width: `${(count / max) * 100}%`, background: ATTACK_COLORS[i % ATTACK_COLORS.length], borderRadius: 999, transition: "width 0.6s ease" }} />
          </div>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "#f1f5f9", width: 52, textAlign: "right", flexShrink: 0 }}>{fmt(count)}</span>
        </div>
      ))}
    </div>
  );
}

// ── KPI card ──────────────────────────────────────────────────────────────

function KpiCard({ label, value, sub, pass }: { label: string; value: string; sub?: string; pass?: boolean }) {
  return (
    <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 10, padding: "18px 20px", flex: 1, minWidth: 150 }}>
      <div style={{ fontSize: 11, color: "#475569", fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 8 }}>{label}</div>
      <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 24, fontWeight: 700, color: pass === false ? "#f87171" : pass === true ? "#4ade80" : "#f1f5f9" }}>
          {value}
        </span>
        {pass === true && <span style={{ color: "#22c55e", fontSize: 12 }}>✓</span>}
        {pass === false && <span style={{ color: "#ef4444", fontSize: 12 }}>✗</span>}
      </div>
      {sub && <div style={{ fontSize: 11, color: "#475569", marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────

export default function Analytics() {
  const [range, setRange] = useState<TimeRange>("7d");
  const [summary, setSummary] = useState<Summary>(EMPTY_SUMMARY);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const showToast = (msg: string) => { setToast(msg); setTimeout(() => setToast(null), 3000); };

  const fetchSummary = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiClient.get<Summary>("/api/v1/analytics/summary", { params: { range } }).then(r => r.data);
      setSummary(data);
    } catch (e: any) {
      setError(e.message || "Failed to load analytics data");
    } finally {
      setLoading(false);
    }
  }, [range]);

  useEffect(() => { fetchSummary(); }, [fetchSummary]);

  const handleGenerateReport = async () => {
    setGenerating(true);
    setError(null);
    try {
      const blob = await apiClient.post(
        "/api/v1/reports/generate",
        { range, format: "pdf" },
        { responseType: "blob" }
      ).then(r => r.data);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `ai-nids-report-${range}-${Date.now()}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
      showToast("Report downloaded");
    } catch (e: any) {
      setError(e.message || "Report generation failed");
    } finally {
      setGenerating(false);
    }
  };

  const handleExportCsv = async () => {
    try {
      const blob = await apiClient.get("/api/v1/alerts/export", {
        params: { format: "csv", range },
        responseType: "blob",
      }).then(r => r.data);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `ai-nids-alerts-${range}-${Date.now()}.csv`;
      a.click();
      URL.revokeObjectURL(url);
      showToast("CSV downloaded");
    } catch (e: any) {
      setError(e.message || "CSV export failed");
    }
  };

  const total = summary.total_alerts;
  const hourLabels = Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2, "0")}:00`);

  return (
    <div style={{ padding: "32px 40px", fontFamily: "'IBM Plex Sans', sans-serif", color: "#f1f5f9", minHeight: "100vh", background: "#020817" }}>

      {/* Toast */}
      {toast && (
        <div style={{ position: "fixed", top: 24, right: 24, background: "#052e16", border: "1px solid #166534", borderRadius: 8, padding: "12px 18px", color: "#4ade80", fontSize: 13, zIndex: 1000, boxShadow: "0 4px 24px #000a" }}>
          ✓ {toast}
        </div>
      )}

      {/* Header */}
      <div style={{ display: "flex", alignItems: "flex-start", marginBottom: 32 }}>
        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 6 }}>
            <div style={{ width: 3, height: 28, background: "#f59e0b", borderRadius: 2 }} />
            <h1 style={{ margin: 0, fontSize: 22, fontWeight: 700, color: "#f8fafc", letterSpacing: "-0.02em" }}>Analytics & Reports</h1>
          </div>
          <p style={{ margin: "0 0 0 15px", color: "#64748b", fontSize: 13 }}>
            Threat trends, attack distribution, and compliance reporting
          </p>
        </div>

        {/* Controls */}
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          {/* Time range */}
          <div style={{ display: "flex", background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8, overflow: "hidden" }}>
            {(["24h", "7d", "30d"] as TimeRange[]).map((r) => (
              <button
                key={r}
                onClick={() => setRange(r)}
                style={{
                  background: range === r ? "#1d4ed8" : "transparent",
                  border: "none",
                  color: range === r ? "#eff6ff" : "#64748b",
                  padding: "8px 16px",
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 12,
                  cursor: "pointer",
                  fontWeight: range === r ? 700 : 400,
                  transition: "all 0.15s",
                }}
              >
                {r}
              </button>
            ))}
          </div>

          {/* Export buttons */}
          <button
            onClick={handleExportCsv}
            style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8, padding: "8px 14px", color: "#94a3b8", fontSize: 12, fontFamily: "'JetBrains Mono', monospace", cursor: "pointer" }}
          >
            ↓ CSV
          </button>
          <button
            onClick={handleGenerateReport}
            disabled={generating}
            style={{
              background: generating ? "#1e293b" : "#b45309",
              border: `1px solid ${generating ? "#334155" : "#d97706"}`,
              borderRadius: 8, padding: "8px 16px",
              color: generating ? "#475569" : "#fef3c7",
              fontSize: 12, fontFamily: "'JetBrains Mono', monospace",
              cursor: generating ? "not-allowed" : "pointer",
              fontWeight: 600,
            }}
          >
            {generating ? "Generating..." : "⬇ PDF Report"}
          </button>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div style={{ background: "#1c0a0a", border: "1px solid #7f1d1d", borderRadius: 8, padding: "12px 16px", marginBottom: 24, color: "#f87171", fontSize: 13, display: "flex", gap: 10 }}>
          <span>⚠</span> {error}
          <button onClick={() => setError(null)} style={{ marginLeft: "auto", background: "none", border: "none", color: "#f87171", cursor: "pointer", fontSize: 16 }}>×</button>
        </div>
      )}

      {/* KPI row */}
      <div style={{ display: "flex", gap: 12, marginBottom: 28, flexWrap: "wrap", opacity: loading ? 0.4 : 1, transition: "opacity 0.2s" }}>
        <KpiCard label="Total Alerts" value={loading ? "—" : fmt(total)} sub={`Last ${range}`} />
        <KpiCard label="FPR (Live)" value={loading ? "—" : pct(summary.false_positive_rate)} sub="target ≤ 5%" pass={loading ? undefined : summary.false_positive_rate <= 0.05} />
        <KpiCard label="Avg Confidence" value={loading ? "—" : pct(summary.avg_confidence)} sub="ensemble score" />
        <KpiCard label="Alerts / Hour" value={loading ? "—" : fmt(Math.round(summary.alerts_per_hour.reduce((a, b) => a + b, 0) / (summary.alerts_per_hour.length || 1)))} sub="rolling average" />
      </div>

      {/* Trend chart */}
      <section style={{ marginBottom: 28 }}>
        <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 12, padding: 24 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
            <h2 style={{ margin: 0, fontSize: 14, fontWeight: 600, color: "#f1f5f9" }}>Alert Volume — Past 24 Hours</h2>
            <span style={{ fontSize: 11, color: "#475569", fontFamily: "'JetBrains Mono', monospace" }}>hourly</span>
          </div>
          <SparkLine data={summary.alerts_per_hour} color="#3b82f6" height={100} />
          <div style={{ display: "flex", justifyContent: "space-between", marginTop: 8 }}>
            {[0, 6, 12, 18, 23].map((h) => (
              <span key={h} style={{ fontSize: 10, color: "#334155", fontFamily: "'JetBrains Mono', monospace" }}>{hourLabels[h]}</span>
            ))}
          </div>
        </div>
      </section>

      {/* Two-column: donut + attack bars */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 28 }}>
        <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 12, padding: 24 }}>
          <h2 style={{ margin: "0 0 20px", fontSize: 14, fontWeight: 600, color: "#f1f5f9" }}>Severity Breakdown</h2>
          <SeverityDonut data={summary.by_severity} total={total} />
        </div>
        <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 12, padding: 24 }}>
          <h2 style={{ margin: "0 0 20px", fontSize: 14, fontWeight: 600, color: "#f1f5f9" }}>Attack Categories</h2>
          <AttackBars data={summary.by_attack_type} />
        </div>
      </div>

      {/* Top attackers */}
      <section>
        <h2 style={{ margin: "0 0 16px", fontSize: 13, fontWeight: 600, color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.1em" }}>
          Top Source IPs
        </h2>
        <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 12, overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #1e293b" }}>
                {["Rank", "IP Address", "Country", "Alert Count", "Last Seen", "Actions"].map((h) => (
                  <th key={h} style={{ padding: "12px 16px", textAlign: "left", fontSize: 11, color: "#64748b", fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.08em", textTransform: "uppercase", fontWeight: 600 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {summary.top_src_ips.map((row, i) => {
                const maxCount = summary.top_src_ips[0].count;
                return (
                  <tr key={row.ip} style={{ borderBottom: i < summary.top_src_ips.length - 1 ? "1px solid #0f172a" : "none" }}>
                    <td style={{ padding: "14px 16px", fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: i === 0 ? "#f87171" : "#475569", fontWeight: 700 }}>
                      #{i + 1}
                    </td>
                    <td style={{ padding: "14px 16px" }}>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: "#e2e8f0" }}>{row.ip}</span>
                    </td>
                    <td style={{ padding: "14px 16px", fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "#64748b" }}>
                      {row.country || "—"}
                    </td>
                    <td style={{ padding: "14px 16px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                        <div style={{ width: 80, height: 4, background: "#1e293b", borderRadius: 999 }}>
                          <div style={{ height: "100%", width: `${(row.count / maxCount) * 100}%`, background: "#ef4444", borderRadius: 999 }} />
                        </div>
                        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: "#f87171", fontWeight: 700 }}>{fmt(row.count)}</span>
                      </div>
                    </td>
                    <td style={{ padding: "14px 16px", fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "#64748b" }}>
                      {new Date(row.last_seen).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" })}
                    </td>
                    <td style={{ padding: "14px 16px" }}>
                      <button
                        onClick={() => window.location.href = `/alerts?src_ip=${row.ip}`}
                        style={{ background: "none", border: "1px solid #1e293b", borderRadius: 6, padding: "4px 10px", color: "#60a5fa", fontSize: 11, fontFamily: "'JetBrains Mono', monospace", cursor: "pointer" }}
                      >
                        View Alerts →
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}