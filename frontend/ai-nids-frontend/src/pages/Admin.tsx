/**
 * AI-NIDS — Administration Page
 * File: frontend/src/pages/AdminPage.tsx
 *
 * Features:
 *  - System health panel (GET /api/v1/status + GET /health)
 *  - User management: list, create, deactivate, role change
 *  - System configuration: data retention, alert thresholds
 *  - SIEM integration config
 *  - Audit log viewer (GET /api/v1/audit-log)
 */

import { useState, useEffect, useCallback } from "react";

// ── Types ──────────────────────────────────────────────────────────────────

interface User {
  id: string;
  username: string;
  email: string;
  role: "system_admin" | "soc_manager" | "network_admin" | "read_only_analyst";
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
}

interface AuditEntry {
  id: string;
  user_id: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  ip_address: string;
  created_at: string;
}

interface PipelineStatus {
  status: string;
  pipeline_stages: Record<string, string>;
  detection_engines: Record<string, { status: string; rules_loaded?: number }>;
  ensemble: { weights: Record<string, number>; alert_threshold: number };
  uptime_seconds: number;
}

interface HealthData {
  status: string;
  uptime_seconds: number;
  components: { database: string; redis: string; signature_rules: string; ml_models: string | string[]; ws_clients: number };
}

// ── Helpers ────────────────────────────────────────────────────────────────

const getToken = () => localStorage.getItem("nids_token") || "";
const apiFetch = async (path: string, opts: RequestInit = {}) => {
  const res = await fetch(`/api/v1${path}`, {
    ...opts,
    headers: { Authorization: `Bearer ${getToken()}`, "Content-Type": "application/json", ...(opts.headers || {}) },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
};

const fmtDate = (iso: string | null) =>
  iso ? new Date(iso).toLocaleString("en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }) : "Never";

const fmtUptime = (secs: number) => {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  return `${h}h ${m}m`;
};

const ROLE_LABELS: Record<User["role"], string> = {
  system_admin:       "System Admin",
  soc_manager:        "SOC Manager",
  network_admin:      "Network Admin",
  read_only_analyst:  "Read-only Analyst",
};

const ROLE_COLORS: Record<User["role"], string> = {
  system_admin:       "#3b82f6",
  soc_manager:        "#8b5cf6",
  network_admin:      "#10b981",
  read_only_analyst:  "#64748b",
};

// ── Sub-components ─────────────────────────────────────────────────────────

function StatusDot({ ok }: { ok: boolean }) {
  return (
    <span style={{
      display: "inline-block", width: 8, height: 8, borderRadius: "50%",
      background: ok ? "#22c55e" : "#ef4444",
      boxShadow: ok ? "0 0 6px #22c55e" : "none",
      marginRight: 8, flexShrink: 0,
    }} />
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section style={{ marginBottom: 36 }}>
      <h2 style={{ margin: "0 0 16px", fontSize: 13, fontWeight: 600, color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.1em" }}>
        {title}
      </h2>
      {children}
    </section>
  );
}

// ── Create User Modal ─────────────────────────────────────────────────────

function CreateUserModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({ username: "", email: "", role: "network_admin", password: "" });
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const handleSubmit = async () => {
    if (!form.username || !form.email || !form.password) { setErr("All fields required"); return; }
    setLoading(true);
    try {
      await apiFetch("/users", { method: "POST", body: JSON.stringify(form) });
      onCreated();
      onClose();
    } catch (e: any) {
      setErr(e.message || "Failed to create user");
    } finally {
      setLoading(false);
    }
  };

  const inputStyle: React.CSSProperties = {
    background: "#020817", border: "1px solid #334155", borderRadius: 6,
    padding: "9px 12px", color: "#f1f5f9", fontFamily: "'IBM Plex Sans', sans-serif",
    fontSize: 13, width: "100%", boxSizing: "border-box",
  };
  const labelStyle: React.CSSProperties = { fontSize: 11, color: "#64748b", fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.08em", textTransform: "uppercase", display: "block", marginBottom: 6 };

  return (
    <div style={{ position: "fixed", inset: 0, background: "#000a", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 14, padding: 32, width: 440, maxWidth: "90vw" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
          <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: "#f8fafc" }}>Create User Account</h3>
          <button onClick={onClose} style={{ background: "none", border: "none", color: "#64748b", cursor: "pointer", fontSize: 20 }}>×</button>
        </div>

        {err && <div style={{ background: "#1c0a0a", border: "1px solid #7f1d1d", borderRadius: 6, padding: "10px 14px", color: "#f87171", fontSize: 13, marginBottom: 16 }}>{err}</div>}

        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          {[["Username", "username", "text"], ["Email", "email", "email"], ["Password", "password", "password"]].map(([label, key, type]) => (
            <div key={key}>
              <label style={labelStyle}>{label}</label>
              <input type={type} value={(form as any)[key]} onChange={(e) => setForm((p) => ({ ...p, [key]: e.target.value }))} style={inputStyle} />
            </div>
          ))}
          <div>
            <label style={labelStyle}>Role</label>
            <select value={form.role} onChange={(e) => setForm((p) => ({ ...p, role: e.target.value }))}
              style={{ ...inputStyle, cursor: "pointer" }}>
              {Object.entries(ROLE_LABELS).map(([val, label]) => (
                <option key={val} value={val}>{label}</option>
              ))}
            </select>
          </div>
        </div>

        <div style={{ display: "flex", gap: 10, marginTop: 24 }}>
          <button onClick={onClose} style={{ flex: 1, background: "none", border: "1px solid #1e293b", borderRadius: 8, padding: "10px 0", color: "#64748b", fontSize: 13, cursor: "pointer" }}>
            Cancel
          </button>
          <button onClick={handleSubmit} disabled={loading}
            style={{ flex: 1, background: loading ? "#1e293b" : "#1d4ed8", border: "1px solid #2563eb", borderRadius: 8, padding: "10px 0", color: loading ? "#475569" : "#eff6ff", fontSize: 13, fontWeight: 600, cursor: loading ? "not-allowed" : "pointer" }}>
            {loading ? "Creating..." : "Create Account"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────

export default function Admin() {
  const [activeTab, setActiveTab] = useState<"health" | "users" | "audit" | "config">("health");
  const [health, setHealth] = useState<HealthData | null>(null);
  const [pipeStatus, setPipeStatus] = useState<PipelineStatus | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [auditLog, setAuditLog] = useState<AuditEntry[]>([]);
  const [showCreateUser, setShowCreateUser] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [retentionDays, setRetentionDays] = useState(90);
  const [alertThreshold, setAlertThreshold] = useState(0.5);
  const [siemEnabled, setSiemEnabled] = useState(false);
  const [siemUrl, setSiemUrl] = useState("");

  const showToast = (msg: string) => { setToast(msg); setTimeout(() => setToast(null), 3000); };

  const fetchHealth = useCallback(async () => {
    try {
      const [h, s] = await Promise.all([
        fetch("/health", { headers: { Authorization: `Bearer ${getToken()}` } }).then((r) => r.json()),
        apiFetch("/status"),
      ]);
      setHealth(h);
      setPipeStatus(s);
    } catch {
      // Try just status
      try {
        const s = await apiFetch("/status");
        setPipeStatus(s);
      } catch { /* silent */ }
    }
  }, []);

  const fetchUsers = useCallback(async () => {
    try {
      const data = await apiFetch("/users");
      setUsers(Array.isArray(data) ? data : (data?.items || []));
    } catch { /* silent — may need higher role */ }
  }, []);

  const fetchAudit = useCallback(async () => {
    try {
      const data = await apiFetch("/audit-log?limit=50");
      setAuditLog(Array.isArray(data) ? data : (data?.items || []));
    } catch { /* silent */ }
  }, []);

  useEffect(() => {
    fetchHealth();
    fetchUsers();
    fetchAudit();
    const id = setInterval(fetchHealth, 10000);
    return () => clearInterval(id);
  }, [fetchHealth, fetchUsers, fetchAudit]);

  const handleDeactivateUser = async (userId: string) => {
    try {
      await apiFetch(`/users/${userId}`, { method: "DELETE" });
      showToast("User deactivated");
      fetchUsers();
    } catch (e: any) { setError(e.message); }
  };

  const handleRoleChange = async (userId: string, role: string) => {
    try {
      await apiFetch(`/users/${userId}/role`, { method: "PUT", body: JSON.stringify({ role }) });
      showToast("Role updated");
      fetchUsers();
    } catch (e: any) { setError(e.message); }
  };

  const handleSaveConfig = async () => {
    try {
      await apiFetch("/config", { method: "PUT", body: JSON.stringify({ retention_days: retentionDays, alert_threshold: alertThreshold, siem_enabled: siemEnabled, siem_url: siemUrl }) });
      showToast("Configuration saved");
    } catch (e: any) { setError(e.message || "Save failed"); }
  };

  // ── Health panel helpers ──────────────────────────────────────────────

  const comps = health?.components;
  const stages = pipeStatus?.pipeline_stages || {};
  const engines = pipeStatus?.detection_engines || {};

  const stageOk = (v: string) => v === "active" || v === "ready" || v.startsWith("active");

  const tabs = [
    { key: "health", label: "System Health" },
    { key: "users",  label: "Users" },
    { key: "audit",  label: "Audit Log" },
    { key: "config", label: "Configuration" },
  ] as const;

  return (
    <div style={{ padding: "32px 40px", fontFamily: "'IBM Plex Sans', sans-serif", color: "#f1f5f9", minHeight: "100vh", background: "#020817" }}>

      {/* Toast */}
      {toast && (
        <div style={{ position: "fixed", top: 24, right: 24, background: "#052e16", border: "1px solid #166534", borderRadius: 8, padding: "12px 18px", color: "#4ade80", fontSize: 13, zIndex: 1000, boxShadow: "0 4px 24px #000a" }}>
          ✓ {toast}
        </div>
      )}

      {showCreateUser && <CreateUserModal onClose={() => setShowCreateUser(false)} onCreated={fetchUsers} />}

      {/* Header */}
      <div style={{ marginBottom: 32 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 6 }}>
          <div style={{ width: 3, height: 28, background: "#64748b", borderRadius: 2 }} />
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 700, color: "#f8fafc", letterSpacing: "-0.02em" }}>System Administration</h1>
        </div>
        <p style={{ margin: "0 0 0 15px", color: "#64748b", fontSize: 13 }}>
          Health monitoring, user management, configuration, and audit trail
        </p>
      </div>

      {/* Error */}
      {error && (
        <div style={{ background: "#1c0a0a", border: "1px solid #7f1d1d", borderRadius: 8, padding: "12px 16px", marginBottom: 24, color: "#f87171", fontSize: 13, display: "flex", gap: 10 }}>
          <span>⚠</span> {error}
          <button onClick={() => setError(null)} style={{ marginLeft: "auto", background: "none", border: "none", color: "#f87171", cursor: "pointer", fontSize: 16 }}>×</button>
        </div>
      )}

      {/* Tab nav */}
      <div style={{ display: "flex", gap: 0, marginBottom: 28, background: "#0f172a", border: "1px solid #1e293b", borderRadius: 10, overflow: "hidden", width: "fit-content" }}>
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => setActiveTab(t.key)}
            style={{
              background: activeTab === t.key ? "#1e293b" : "transparent",
              border: "none",
              color: activeTab === t.key ? "#f1f5f9" : "#64748b",
              padding: "10px 22px",
              fontSize: 13,
              fontWeight: activeTab === t.key ? 600 : 400,
              cursor: "pointer",
              transition: "all 0.15s",
              borderRight: "1px solid #1e293b",
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* ── TAB: Health ── */}
      {activeTab === "health" && (
        <>
          {/* Component statuses */}
          <Section title="Component Status">
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 12 }}>
              {comps && [
                { label: "PostgreSQL", ok: comps.database === "connected", value: comps.database },
                { label: "Redis",      ok: comps.redis === "connected",    value: comps.redis },
                { label: "Signature Rules", ok: !comps.signature_rules.includes("0"), value: comps.signature_rules },
                { label: "ML Models", ok: Array.isArray(comps.ml_models) ? comps.ml_models.length > 0 : comps.ml_models !== "not yet trained", value: Array.isArray(comps.ml_models) ? `${comps.ml_models.length} loaded` : String(comps.ml_models) },
                { label: "WebSocket Clients", ok: true, value: `${comps.ws_clients} connected` },
                { label: "Uptime", ok: true, value: health ? fmtUptime(health.uptime_seconds) : "—" },
              ].map((item) => (
                <div key={item.label} style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 10, padding: "16px 18px" }}>
                  <div style={{ fontSize: 11, color: "#475569", fontFamily: "'JetBrains Mono', monospace", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8 }}>{item.label}</div>
                  <div style={{ display: "flex", alignItems: "center" }}>
                    <StatusDot ok={item.ok} />
                    <span style={{ fontSize: 13, color: item.ok ? "#e2e8f0" : "#f87171", fontFamily: "'JetBrains Mono', monospace" }}>{item.value}</span>
                  </div>
                </div>
              ))}
            </div>
          </Section>

          {/* Pipeline stages */}
          <Section title="Pipeline Stages">
            <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 12, overflow: "hidden" }}>
              {Object.entries(stages).map(([stage, val], i, arr) => (
                <div key={stage} style={{ display: "flex", alignItems: "center", padding: "14px 18px", borderBottom: i < arr.length - 1 ? "1px solid #0a1525" : "none" }}>
                  <StatusDot ok={stageOk(val)} />
                  <span style={{ color: "#94a3b8", width: 200, fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>{stage.replace(/_/g, " ")}</span>
                  <span style={{ color: stageOk(val) ? "#4ade80" : "#f87171", fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>{val}</span>
                </div>
              ))}
            </div>
          </Section>

          {/* Detection engines */}
          <Section title="Detection Engines">
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 12 }}>
              {/* Signature engine */}
              <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 10, padding: "16px 18px" }}>
                <div style={{ fontSize: 11, color: "#475569", fontFamily: "'JetBrains Mono', monospace", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8 }}>Signature Engine</div>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <StatusDot ok={engines?.signature?.status === "active"} />
                  <span style={{ fontSize: 12, color: "#e2e8f0", fontFamily: "'JetBrains Mono', monospace" }}>
                    {engines?.signature?.rules_loaded != null ? `${engines.signature.rules_loaded} rules` : engines?.signature?.status || "—"}
                  </span>
                </div>
                <div style={{ fontSize: 11, color: "#475569", marginTop: 6, fontFamily: "'JetBrains Mono', monospace" }}>Weight: 40%</div>
              </div>
              {[
                { key: "random_forest", label: "Random Forest", weight: "35%" },
                { key: "isolation_forest", label: "Isolation Forest", weight: "10%" },
                { key: "lstm", label: "LSTM Sequence", weight: "15%" },
              ].map((eng) => {
                const e = engines?.[eng.key] as any;
                return (
                  <div key={eng.key} style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 10, padding: "16px 18px" }}>
                    <div style={{ fontSize: 11, color: "#475569", fontFamily: "'JetBrains Mono', monospace", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8 }}>{eng.label}</div>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <StatusDot ok={e?.status === "active"} />
                      <span style={{ fontSize: 12, color: "#e2e8f0", fontFamily: "'JetBrains Mono', monospace" }}>{e?.status || "—"}</span>
                    </div>
                    <div style={{ fontSize: 11, color: "#475569", marginTop: 6, fontFamily: "'JetBrains Mono', monospace" }}>Weight: {eng.weight}</div>
                  </div>
                );
              })}
            </div>
          </Section>
        </>
      )}

      {/* ── TAB: Users ── */}
      {activeTab === "users" && (
        <Section title="User Accounts">
          <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 16 }}>
            <button
              onClick={() => setShowCreateUser(true)}
              style={{ background: "#1d4ed8", border: "1px solid #2563eb", borderRadius: 8, padding: "9px 18px", color: "#eff6ff", fontSize: 13, fontWeight: 600, fontFamily: "'JetBrains Mono', monospace", cursor: "pointer", letterSpacing: "0.04em" }}
            >
              + Create User
            </button>
          </div>

          {users.length === 0 ? (
            <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 12, padding: 32, textAlign: "center", color: "#475569", fontFamily: "'JetBrains Mono', monospace", fontSize: 13 }}>
              No users found — requires system_admin role
            </div>
          ) : (
            <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 12, overflow: "hidden" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid #1e293b" }}>
                    {["Username", "Email", "Role", "Last Login", "Status", "Actions"].map((h) => (
                      <th key={h} style={{ padding: "12px 16px", textAlign: "left", fontSize: 11, color: "#64748b", fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.08em", textTransform: "uppercase", fontWeight: 600 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {users.map((user, i) => (
                    <tr key={user.id} style={{ borderBottom: i < users.length - 1 ? "1px solid #0a1525" : "none" }}>
                      <td style={{ padding: "14px 16px", fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: "#f1f5f9" }}>{user.username}</td>
                      <td style={{ padding: "14px 16px", fontSize: 13, color: "#94a3b8" }}>{user.email}</td>
                      <td style={{ padding: "14px 16px" }}>
                        <span style={{ background: ROLE_COLORS[user.role] + "22", color: ROLE_COLORS[user.role], borderRadius: 999, padding: "2px 10px", fontSize: 11, fontFamily: "'JetBrains Mono', monospace", fontWeight: 600, letterSpacing: "0.04em" }}>
                          {ROLE_LABELS[user.role]}
                        </span>
                      </td>
                      <td style={{ padding: "14px 16px", fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "#64748b" }}>{fmtDate(user.last_login_at)}</td>
                      <td style={{ padding: "14px 16px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                          <StatusDot ok={user.is_active} />
                          <span style={{ fontSize: 12, color: user.is_active ? "#4ade80" : "#f87171", fontFamily: "'JetBrains Mono', monospace" }}>
                            {user.is_active ? "Active" : "Inactive"}
                          </span>
                        </div>
                      </td>
                      <td style={{ padding: "14px 16px" }}>
                        <div style={{ display: "flex", gap: 8 }}>
                          <select
                            value={user.role}
                            onChange={(e) => handleRoleChange(user.id, e.target.value)}
                            style={{ background: "#020817", border: "1px solid #1e293b", borderRadius: 5, padding: "4px 8px", color: "#94a3b8", fontSize: 11, fontFamily: "'JetBrains Mono', monospace", cursor: "pointer" }}
                          >
                            {Object.entries(ROLE_LABELS).map(([val, label]) => (
                              <option key={val} value={val}>{label}</option>
                            ))}
                          </select>
                          {user.is_active && (
                            <button
                              onClick={() => handleDeactivateUser(user.id)}
                              style={{ background: "none", border: "1px solid #7f1d1d", borderRadius: 5, padding: "4px 10px", color: "#f87171", fontSize: 11, fontFamily: "'JetBrains Mono', monospace", cursor: "pointer" }}
                            >
                              Deactivate
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Section>
      )}

      {/* ── TAB: Audit Log ── */}
      {activeTab === "audit" && (
        <Section title="Audit Log">
          {auditLog.length === 0 ? (
            <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 12, padding: 32, textAlign: "center", color: "#475569", fontFamily: "'JetBrains Mono', monospace", fontSize: 13 }}>
              No audit entries — requires system_admin role
            </div>
          ) : (
            <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 12, overflow: "hidden", maxHeight: 520, overflowY: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead style={{ position: "sticky", top: 0, background: "#0f172a", zIndex: 1 }}>
                  <tr style={{ borderBottom: "1px solid #1e293b" }}>
                    {["Time", "User", "Action", "Resource", "IP"].map((h) => (
                      <th key={h} style={{ padding: "12px 16px", textAlign: "left", fontSize: 11, color: "#64748b", fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.08em", textTransform: "uppercase", fontWeight: 600 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {auditLog.map((entry, i) => (
                    <tr key={entry.id} style={{ borderBottom: i < auditLog.length - 1 ? "1px solid #0a1525" : "none" }}>
                      <td style={{ padding: "10px 16px", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "#64748b", whiteSpace: "nowrap" }}>{fmtDate(entry.created_at)}</td>
                      <td style={{ padding: "10px 16px", fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "#94a3b8" }}>{entry.user_id.slice(0, 8)}…</td>
                      <td style={{ padding: "10px 16px" }}>
                        <span style={{ background: "#1e293b", color: "#60a5fa", borderRadius: 4, padding: "2px 8px", fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }}>{entry.action}</span>
                      </td>
                      <td style={{ padding: "10px 16px", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "#64748b" }}>
                        {entry.resource_type}{entry.resource_id ? `:${entry.resource_id.slice(0, 8)}` : ""}
                      </td>
                      <td style={{ padding: "10px 16px", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "#475569" }}>{entry.ip_address}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Section>
      )}

      {/* ── TAB: Config ── */}
      {activeTab === "config" && (
        <>
          <Section title="Data Retention">
            <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 12, padding: 24 }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
                <div>
                  <label style={{ fontSize: 11, color: "#64748b", fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.08em", textTransform: "uppercase", display: "block", marginBottom: 8 }}>
                    Alert Retention (days)
                  </label>
                  <input type="number" value={retentionDays} onChange={(e) => setRetentionDays(Number(e.target.value))} min={7} max={365}
                    style={{ background: "#020817", border: "1px solid #334155", borderRadius: 6, padding: "9px 12px", color: "#f1f5f9", fontFamily: "'JetBrains Mono', monospace", fontSize: 13, width: "100%", boxSizing: "border-box" }} />
                  <div style={{ fontSize: 11, color: "#475569", marginTop: 6 }}>Compliance target: ≥ 90 days</div>
                </div>
                <div>
                  <label style={{ fontSize: 11, color: "#64748b", fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.08em", textTransform: "uppercase", display: "block", marginBottom: 8 }}>
                    Ensemble Alert Threshold
                  </label>
                  <input type="number" value={alertThreshold} onChange={(e) => setAlertThreshold(Number(e.target.value))} min={0.1} max={1.0} step={0.05}
                    style={{ background: "#020817", border: "1px solid #334155", borderRadius: 6, padding: "9px 12px", color: "#f1f5f9", fontFamily: "'JetBrains Mono', monospace", fontSize: 13, width: "100%", boxSizing: "border-box" }} />
                  <div style={{ fontSize: 11, color: "#475569", marginTop: 6 }}>Design value: 0.50 — higher = fewer alerts</div>
                </div>
              </div>
            </div>
          </Section>

          <Section title="SIEM Integration">
            <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 12, padding: 24 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 20 }}>
                <button
                  onClick={() => setSiemEnabled((p) => !p)}
                  style={{
                    width: 44, height: 24, background: siemEnabled ? "#1d4ed8" : "#1e293b", border: "none", borderRadius: 999, cursor: "pointer", position: "relative", transition: "background 0.2s",
                  }}
                >
                  <span style={{ position: "absolute", top: 3, left: siemEnabled ? 22 : 3, width: 18, height: 18, background: "#f1f5f9", borderRadius: "50%", transition: "left 0.2s" }} />
                </button>
                <span style={{ fontSize: 13, color: "#94a3b8" }}>Enable Syslog / CEF forwarding</span>
              </div>
              {siemEnabled && (
                <div>
                  <label style={{ fontSize: 11, color: "#64748b", fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.08em", textTransform: "uppercase", display: "block", marginBottom: 8 }}>
                    SIEM Destination URL
                  </label>
                  <input
                    type="text"
                    value={siemUrl}
                    onChange={(e) => setSiemUrl(e.target.value)}
                    placeholder="syslog://10.0.0.50:514"
                    style={{ background: "#020817", border: "1px solid #334155", borderRadius: 6, padding: "9px 12px", color: "#f1f5f9", fontFamily: "'JetBrains Mono', monospace", fontSize: 13, width: "100%", boxSizing: "border-box" }}
                  />
                  <div style={{ fontSize: 11, color: "#475569", marginTop: 6 }}>Supports syslog:// and https:// webhook URLs</div>
                </div>
              )}
            </div>
          </Section>

          <div>
            <button
              onClick={handleSaveConfig}
              style={{ background: "#1d4ed8", border: "1px solid #2563eb", borderRadius: 8, padding: "10px 28px", color: "#eff6ff", fontSize: 13, fontWeight: 600, fontFamily: "'JetBrains Mono', monospace", cursor: "pointer", letterSpacing: "0.04em" }}
            >
              Save Configuration
            </button>
          </div>
        </>
      )}
    </div>
  );
}