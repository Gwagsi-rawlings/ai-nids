/**
 * AI-NIDS — Capture Page
 * File: frontend/src/pages/CapturePage.tsx
 *
 * Features:
 *  - Live capture start/stop (POST /api/v1/capture/start | /stop)
 *  - PCAP file upload (POST /api/v1/capture/pcap/upload)
 *  - Real-time capture stats polling from GET /api/v1/status
 *  - Upload job progress tracking
 */

import { useState, useEffect, useRef, useCallback } from "react";

// ── Types ──────────────────────────────────────────────────────────────────

interface CaptureStats {
  packets_captured: number;
  packets_dropped: number;
  packets_enqueued: number;
  packets_malformed: number;
}

interface PcapJob {
  id: string;
  filename: string;
  status: "queued" | "running" | "complete" | "failed";
  flow_count: number | null;
  alert_count: number | null;
  file_size_bytes: number;
  submitted_at: string;
  completed_at: string | null;
  error_message: string | null;
}

interface LiveCaptureState {
  running: boolean;
  interface: string;
  started_at: string | null;
}

// ── Helpers ────────────────────────────────────────────────────────────────

const getToken = () => localStorage.getItem("nids_token") || "";

const apiFetch = async (path: string, options: RequestInit = {}) => {
  const res = await fetch(`/api/v1${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${getToken()}`,
      ...(options.headers || {}),
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
};

const fmt = (n: number) => n.toLocaleString();
const fmtBytes = (b: number) => {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 / 1024).toFixed(1)} MB`;
};
const fmtTime = (iso: string) =>
  new Date(iso).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });

// ── Sub-components ─────────────────────────────────────────────────────────

function StatCard({ label, value, accent = false }: { label: string; value: string | number; accent?: boolean }) {
  return (
    <div
      style={{
        background: "#0f172a",
        border: `1px solid ${accent ? "#1d4ed8" : "#1e293b"}`,
        borderRadius: 8,
        padding: "20px 24px",
        flex: 1,
        minWidth: 140,
      }}
    >
      <div style={{ color: "#64748b", fontSize: 11, fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 8 }}>
        {label}
      </div>
      <div style={{ color: accent ? "#60a5fa" : "#f1f5f9", fontSize: 26, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>
        {typeof value === "number" ? fmt(value) : value}
      </div>
    </div>
  );
}

function StatusPill({ status }: { status: PcapJob["status"] }) {
  const map: Record<PcapJob["status"], { color: string; bg: string; label: string }> = {
    queued:   { color: "#94a3b8", bg: "#1e293b", label: "Queued" },
    running:  { color: "#fbbf24", bg: "#451a03", label: "Processing" },
    complete: { color: "#4ade80", bg: "#052e16", label: "Complete" },
    failed:   { color: "#f87171", bg: "#1c0a0a", label: "Failed" },
  };
  const s = map[status];
  return (
    <span style={{ background: s.bg, color: s.color, borderRadius: 999, padding: "2px 10px", fontSize: 11, fontFamily: "'JetBrains Mono', monospace", fontWeight: 600, letterSpacing: "0.05em" }}>
      {s.label}
    </span>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────

export default function Capture() {
  const [liveState, setLiveState] = useState<LiveCaptureState>({ running: false, interface: "eth0", started_at: null });
  const [captureIface, setCaptureIface] = useState("eth0");
  const [stats, setStats] = useState<CaptureStats | null>(null);
  const [jobs, setJobs] = useState<PcapJob[]>([]);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [liveLoading, setLiveLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Poll status for live stats
  const pollStats = useCallback(async () => {
    try {
      const data = await apiFetch("/status");
      const pc = data?.pipeline_stages?.packet_capture;
      if (pc && typeof pc === "object") setStats(pc as CaptureStats);
      const mode = data?.detection_engines?.capture_mode;
      if (mode === "live") setLiveState((p) => ({ ...p, running: true }));
    } catch {
      // non-fatal
    }
  }, []);

  const fetchJobs = useCallback(async () => {
    try {
      const data = await apiFetch("/capture/jobs");
      if (Array.isArray(data)) setJobs(data);
      else if (data?.items) setJobs(data.items);
    } catch {
      // endpoint may not exist yet; silently ignore
    }
  }, []);

  useEffect(() => {
    pollStats();
    fetchJobs();
    pollRef.current = setInterval(() => {
      pollStats();
      fetchJobs();
    }, 5000);
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [pollStats, fetchJobs]);

  // Live capture
  const handleLiveToggle = async () => {
    setLiveLoading(true);
    setError(null);
    try {
      if (liveState.running) {
        await apiFetch("/capture/stop", { method: "POST" });
        setLiveState({ running: false, interface: captureIface, started_at: null });
      } else {
        await apiFetch("/capture/start", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ interface: captureIface }),
        });
        setLiveState({ running: true, interface: captureIface, started_at: new Date().toISOString() });
      }
    } catch (e: any) {
      setError(e.message || "Capture toggle failed");
    } finally {
      setLiveLoading(false);
    }
  };

  // PCAP upload
  const handleUpload = async (file: File) => {
    if (!file.name.match(/\.(pcap|pcapng)$/i)) {
      setError("Only .pcap and .pcapng files are supported.");
      return;
    }
    setUploading(true);
    setUploadProgress(0);
    setError(null);
    const formData = new FormData();
    formData.append("file", file);

    try {
      // Simulate progress for UX (XHR would give real progress)
      const progressInterval = setInterval(() => {
        setUploadProgress((p) => Math.min(p + 10, 85));
      }, 300);

      await apiFetch("/capture/pcap/upload", {
        method: "POST",
        body: formData,
        headers: {}, // let browser set Content-Type for multipart
      });

      clearInterval(progressInterval);
      setUploadProgress(100);
      setTimeout(() => { setUploading(false); setUploadProgress(0); fetchJobs(); }, 800);
    } catch (e: any) {
      setError(e.message || "Upload failed");
      setUploading(false);
      setUploadProgress(0);
    }
  };

  const onFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) handleUpload(file);
    e.target.value = "";
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) handleUpload(file);
  };

  // ── Render ───────────────────────────────────────────────────────────────

  return (
    <div style={{ padding: "32px 40px", fontFamily: "'IBM Plex Sans', sans-serif", color: "#f1f5f9", minHeight: "100vh", background: "#020817" }}>

      {/* Header */}
      <div style={{ marginBottom: 36 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 6 }}>
          <div style={{ width: 3, height: 28, background: "#2563eb", borderRadius: 2 }} />
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 700, color: "#f8fafc", letterSpacing: "-0.02em" }}>
            Packet Capture
          </h1>
        </div>
        <p style={{ margin: "0 0 0 15px", color: "#64748b", fontSize: 13 }}>
          Live interface monitoring and offline PCAP file analysis
        </p>
      </div>

      {/* Error banner */}
      {error && (
        <div style={{ background: "#1c0a0a", border: "1px solid #7f1d1d", borderRadius: 8, padding: "12px 16px", marginBottom: 24, color: "#f87171", fontSize: 13, display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ fontSize: 16 }}>⚠</span> {error}
          <button onClick={() => setError(null)} style={{ marginLeft: "auto", background: "none", border: "none", color: "#f87171", cursor: "pointer", fontSize: 16 }}>×</button>
        </div>
      )}

      {/* ── Live Capture Section ── */}
      <section style={{ marginBottom: 36 }}>
        <h2 style={{ margin: "0 0 16px", fontSize: 13, fontWeight: 600, color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.1em" }}>
          Live Capture
        </h2>

        <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 12, padding: 24 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 20, flexWrap: "wrap" }}>

            {/* Interface selector */}
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              <label style={{ fontSize: 11, color: "#64748b", fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.08em", textTransform: "uppercase" }}>
                Network Interface
              </label>
              <input
                value={captureIface}
                onChange={(e) => setCaptureIface(e.target.value)}
                disabled={liveState.running}
                placeholder="eth0"
                style={{
                  background: "#020817",
                  border: "1px solid #334155",
                  borderRadius: 6,
                  padding: "8px 12px",
                  color: "#f1f5f9",
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 13,
                  width: 140,
                  opacity: liveState.running ? 0.5 : 1,
                }}
              />
            </div>

            {/* Status indicator */}
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              <label style={{ fontSize: 11, color: "#64748b", fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.08em", textTransform: "uppercase" }}>
                Status
              </label>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <div style={{
                  width: 8, height: 8, borderRadius: "50%",
                  background: liveState.running ? "#22c55e" : "#475569",
                  boxShadow: liveState.running ? "0 0 8px #22c55e" : "none",
                  animation: liveState.running ? "pulse 2s infinite" : "none",
                }} />
                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: liveState.running ? "#22c55e" : "#64748b" }}>
                  {liveState.running ? "CAPTURING" : "IDLE"}
                </span>
              </div>
            </div>

            {/* Started at */}
            {liveState.running && liveState.started_at && (
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                <label style={{ fontSize: 11, color: "#64748b", fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.08em", textTransform: "uppercase" }}>
                  Started
                </label>
                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: "#94a3b8" }}>
                  {fmtTime(liveState.started_at)}
                </span>
              </div>
            )}

            {/* Toggle button */}
            <div style={{ marginLeft: "auto" }}>
              <button
                onClick={handleLiveToggle}
                disabled={liveLoading}
                style={{
                  background: liveState.running ? "#450a0a" : "#1d4ed8",
                  border: `1px solid ${liveState.running ? "#7f1d1d" : "#2563eb"}`,
                  borderRadius: 8,
                  padding: "10px 24px",
                  color: liveState.running ? "#f87171" : "#eff6ff",
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 13,
                  fontWeight: 600,
                  cursor: liveLoading ? "not-allowed" : "pointer",
                  opacity: liveLoading ? 0.6 : 1,
                  letterSpacing: "0.05em",
                  transition: "all 0.15s",
                }}
              >
                {liveLoading ? "..." : liveState.running ? "⏹ STOP CAPTURE" : "▶ START CAPTURE"}
              </button>
            </div>
          </div>

          {/* WSL2 note */}
          <div style={{ marginTop: 16, padding: "10px 14px", background: "#020817", borderRadius: 6, border: "1px solid #1e293b" }}>
            <span style={{ fontSize: 11, color: "#475569", fontFamily: "'JetBrains Mono', monospace" }}>
              ⓘ Live capture requires <code style={{ color: "#60a5fa" }}>network_mode: host</code> + <code style={{ color: "#60a5fa" }}>NET_ADMIN</code> capabilities in docker-compose.yml. For WSL2 development, use PCAP file upload below.
            </span>
          </div>
        </div>
      </section>

      {/* ── Live Stats ── */}
      {stats && (
        <section style={{ marginBottom: 36 }}>
          <h2 style={{ margin: "0 0 16px", fontSize: 13, fontWeight: 600, color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.1em" }}>
            Capture Statistics
          </h2>
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
            <StatCard label="Captured" value={stats.packets_captured} accent />
            <StatCard label="Enqueued" value={stats.packets_enqueued} />
            <StatCard label="Dropped" value={stats.packets_dropped} />
            <StatCard label="Malformed" value={stats.packets_malformed} />
          </div>
        </section>
      )}

      {/* ── PCAP Upload ── */}
      <section style={{ marginBottom: 36 }}>
        <h2 style={{ margin: "0 0 16px", fontSize: 13, fontWeight: 600, color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.1em" }}>
          PCAP File Upload
        </h2>

        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={onDrop}
          onClick={() => fileInputRef.current?.click()}
          style={{
            background: dragOver ? "#0f172a" : "#060f1e",
            border: `2px dashed ${dragOver ? "#2563eb" : "#1e293b"}`,
            borderRadius: 12,
            padding: "48px 32px",
            textAlign: "center",
            cursor: "pointer",
            transition: "all 0.15s",
            position: "relative",
            overflow: "hidden",
          }}
        >
          <input ref={fileInputRef} type="file" accept=".pcap,.pcapng" onChange={onFileChange} style={{ display: "none" }} />

          {uploading ? (
            <div>
              <div style={{ fontSize: 32, marginBottom: 12 }}>📡</div>
              <div style={{ color: "#94a3b8", fontSize: 14, marginBottom: 16 }}>Uploading and processing...</div>
              <div style={{ background: "#0f172a", borderRadius: 999, height: 6, width: "60%", margin: "0 auto", overflow: "hidden" }}>
                <div style={{ height: "100%", width: `${uploadProgress}%`, background: "#2563eb", borderRadius: 999, transition: "width 0.3s" }} />
              </div>
              <div style={{ color: "#60a5fa", fontSize: 12, marginTop: 8, fontFamily: "'JetBrains Mono', monospace" }}>
                {uploadProgress}%
              </div>
            </div>
          ) : (
            <div>
              <div style={{ fontSize: 36, marginBottom: 12 }}>📂</div>
              <div style={{ color: "#f1f5f9", fontSize: 15, fontWeight: 600, marginBottom: 6 }}>
                Drop a PCAP file here
              </div>
              <div style={{ color: "#475569", fontSize: 13 }}>
                or click to browse — supports <span style={{ color: "#60a5fa", fontFamily: "'JetBrains Mono', monospace" }}>.pcap</span> and <span style={{ color: "#60a5fa", fontFamily: "'JetBrains Mono', monospace" }}>.pcapng</span>
              </div>
              <div style={{ color: "#334155", fontSize: 12, marginTop: 8 }}>Max 10 GB per file</div>
            </div>
          )}
        </div>
      </section>

      {/* ── Upload Jobs ── */}
      {jobs.length > 0 && (
        <section>
          <h2 style={{ margin: "0 0 16px", fontSize: 13, fontWeight: 600, color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.1em" }}>
            Analysis Jobs
          </h2>
          <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 12, overflow: "hidden" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid #1e293b" }}>
                  {["Filename", "Size", "Flows", "Alerts", "Status", "Submitted"].map((h) => (
                    <th key={h} style={{ padding: "12px 16px", textAlign: "left", fontSize: 11, color: "#64748b", fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.08em", textTransform: "uppercase", fontWeight: 600 }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {jobs.map((job, i) => (
                  <tr key={job.id} style={{ borderBottom: i < jobs.length - 1 ? "1px solid #1e293b" : "none" }}>
                    <td style={{ padding: "14px 16px", fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "#e2e8f0", maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{job.filename}</td>
                    <td style={{ padding: "14px 16px", fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "#94a3b8" }}>{fmtBytes(job.file_size_bytes)}</td>
                    <td style={{ padding: "14px 16px", fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "#94a3b8" }}>{job.flow_count != null ? fmt(job.flow_count) : "—"}</td>
                    <td style={{ padding: "14px 16px", fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: job.alert_count ? "#f87171" : "#94a3b8" }}>{job.alert_count != null ? fmt(job.alert_count) : "—"}</td>
                    <td style={{ padding: "14px 16px" }}><StatusPill status={job.status} /></td>
                    <td style={{ padding: "14px 16px", fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "#64748b" }}>{fmtTime(job.submitted_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Pulse animation */}
      <style>{`
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
      `}</style>
    </div>
  );
}