import { useState, useRef, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { fetchRules, createRule, toggleRule as toggleRuleApi, deleteRule as deleteRuleApi, updateRule as updateRuleApi } from '../api/rules';

// ── Palette & constants ───────────────────────────────────────────────────────
const C = {
  bg:        "#0a0d08",
  panel:     "#0d110b",
  panelB:    "#111510",
  border:    "#1c2419",
  borderHi:  "#2a3826",
  text:      "#8a9e80",
  textDim:   "#3a4e35",
  textBright:"#c8dfc0",
  green:     "#4ade80",
  greenDim:  "#1a3a20",
  acid:      "#a3e635",
  amber:     "#f59e0b",
  red:       "#ef4444",
  redDim:    "#2a1010",
  blue:      "#60a5fa",
  purple:    "#a78bfa",
  muted:     "#252f22",
};

const SEV_COLOR = { CRITICAL: C.red, HIGH: C.amber, MEDIUM: C.blue, LOW: C.green };
const CAT_LIST  = ["DoS", "DDoS", "PortScan", "BruteForce", "WebAttack", "Botnet", "Infiltration"];

function nextSid(rules) {
  const max = rules.reduce((m, r) => {
    const n = parseInt(r.rule_id.replace("SID:", ""), 10);
    return n > m ? n : m;
  }, 1012);
  return `SID:${max + 1}`;
}

// ── Syntax-highlight Snort rule ───────────────────────────────────────────────
function highlightRule(raw = "") {
  if (!raw) return null;
  const parts = raw.match(/^(\w+)\s+(\w+)\s+(.+?)\s+(->|<>)\s+(.+?)\s+\((.+)\)$/s);
  if (!parts) return <span style={{ color: C.text }}>{raw}</span>;
  const [, action, proto, src, dir, dst, opts] = parts;

  const colorOpts = opts.split(";").map((seg, i) => {
    const s = seg.trim();
    if (!s) return null;
    const kv = s.match(/^(\w+):(.*)/);
    if (!kv) return <span key={i} style={{ color: C.textDim }}>;</span>;
    const [, key, val] = kv;
    const keyColor = key === "msg" ? C.acid : key === "content" ? C.amber : key === "sid" ? C.purple : C.blue;
    return (
      <span key={i}>
        <span style={{ color: keyColor }}>{key}</span>
        <span style={{ color: C.textDim }}>:</span>
        <span style={{ color: C.textBright }}>{val}</span>
        <span style={{ color: C.textDim }}>; </span>
      </span>
    );
  });

  return (
    <span>
      <span style={{ color: C.red, fontWeight: 700 }}>{action} </span>
      <span style={{ color: C.acid }}>{proto} </span>
      <span style={{ color: C.text }}>{src} </span>
      <span style={{ color: C.textDim }}>{dir} </span>
      <span style={{ color: C.text }}>{dst} </span>
      <span style={{ color: C.textDim }}>(</span>
      {colorOpts}
      <span style={{ color: C.textDim }}>)</span>
    </span>
  );
}

// ── Validate Snort rule ───────────────────────────────────────────────────────
function validateRule(raw) {
  const errors = [];
  if (!raw.trim()) { errors.push("Rule cannot be empty."); return errors; }
  if (!raw.trim().startsWith("alert")) errors.push('Must start with action keyword "alert".');
  if (!/sid:\d+/i.test(raw)) errors.push("Missing required field: sid:NNNN");
  if (!/msg:"[^"]+"/i.test(raw)) errors.push('Missing required field: msg:"..."');
  if (!raw.includes("(") || !raw.includes(")")) errors.push("Rule options must be wrapped in parentheses.");
  return errors;
}

// ── RuleModal (create / edit) ─────────────────────────────────────────────────
function RuleModal({ rule, onSave, onClose }) {
  const isEdit = !!rule;
  const [raw, setRaw]       = useState(rule?.raw || 'alert tcp any any -> any 80 (msg:""; content:""; nocase; classtype:web-application-attack; sid:; rev:1;)');
  const [name, setName]     = useState(rule?.rule_name || "");
  const [cat, setCat]       = useState(rule?.attack_category || "WebAttack");
  const [sev, setSev]       = useState(rule?.severity || "MEDIUM");
  const [errors, setErrors] = useState([]);
  const taRef = useRef(null);

  function handleSave() {
    const errs = validateRule(raw);
    if (!name.trim()) errs.push("Rule name is required.");
    if (errs.length) { setErrors(errs); return; }
    onSave({ raw, name, category: cat, severity: sev });
  }

  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 200,
      background: "rgba(0,0,0,0.75)",
      display: "flex", alignItems: "center", justifyContent: "center",
      backdropFilter: "blur(2px)",
    }}
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div style={{
        width: 740, maxHeight: "90vh",
        background: C.panel,
        border: `1px solid ${C.borderHi}`,
        borderRadius: 6,
        display: "flex", flexDirection: "column",
        overflow: "hidden",
        boxShadow: `0 0 60px rgba(0,0,0,0.8), 0 0 0 1px ${C.border}`,
      }}>
        {/* Modal header */}
        <div style={{
          padding: "14px 20px",
          borderBottom: `1px solid ${C.border}`,
          display: "flex", alignItems: "center", justifyContent: "space-between",
          background: C.panelB,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ width: 3, height: 18, background: C.acid, borderRadius: 2 }} />
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: C.textBright, letterSpacing: 1 }}>
              {isEdit ? "EDIT RULE" : "CREATE RULE"}
            </span>
          </div>
          <button onClick={onClose} style={{ background: "none", border: "none", color: C.textDim, cursor: "pointer", fontSize: 18, lineHeight: 1 }}>×</button>
        </div>

        {/* Body */}
        <div style={{ padding: "20px", overflowY: "auto", flex: 1 }}>
          {/* Name + Category + Severity row */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 140px 120px", gap: 12, marginBottom: 16 }}>
            <div>
              <label style={labelStyle}>RULE NAME</label>
              <input
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="e.g. SQL Injection UNION SELECT"
                style={inputStyle}
              />
            </div>
            <div>
              <label style={labelStyle}>CATEGORY</label>
              <select value={cat} onChange={e => setCat(e.target.value)} style={inputStyle}>
                {CAT_LIST.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <label style={labelStyle}>SEVERITY</label>
              <select value={sev} onChange={e => setSev(e.target.value)} style={{ ...inputStyle, color: SEV_COLOR[sev] }}>
                {["CRITICAL","HIGH","MEDIUM","LOW"].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
          </div>

          {/* Raw rule editor */}
          <div>
            <label style={{ ...labelStyle, display: "flex", justifyContent: "space-between" }}>
              <span>SNORT RULE SYNTAX</span>
              <span style={{ color: C.textDim, fontSize: 9, letterSpacing: 0 }}>
                Snort 2/3 compatible · sid required
              </span>
            </label>
            <div style={{
              border: `1px solid ${errors.length ? C.red + "80" : C.border}`,
              borderRadius: 4,
              background: C.bg,
              overflow: "hidden",
            }}>
              <textarea
                ref={taRef}
                value={raw}
                onChange={e => { setRaw(e.target.value); setErrors([]); }}
                spellCheck={false}
                rows={5}
                style={{
                  width: "100%",
                  background: "transparent",
                  border: "none",
                  outline: "none",
                  padding: "12px 14px",
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 11,
                  color: C.textBright,
                  resize: "vertical",
                  lineHeight: 1.7,
                  letterSpacing: 0.3,
                }}
              />
              {/* Preview */}
              <div style={{
                borderTop: `1px solid ${C.border}`,
                padding: "8px 14px",
                fontSize: 10,
                fontFamily: "'JetBrains Mono', monospace",
                lineHeight: 1.8,
                wordBreak: "break-all",
              }}>
                <span style={{ color: C.textDim, marginRight: 8, fontSize: 9 }}>PREVIEW</span>
                {highlightRule(raw)}
              </div>
            </div>
          </div>

          {/* Validation errors */}
          {errors.length > 0 && (
            <div style={{ marginTop: 12, padding: "10px 14px", background: C.redDim, border: `1px solid ${C.red}40`, borderRadius: 4 }}>
              {errors.map((e, i) => (
                <div key={i} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: C.red, marginBottom: i < errors.length - 1 ? 4 : 0 }}>
                  ✕ {e}
                </div>
              ))}
            </div>
          )}

          {/* Template shortcuts */}
          {!isEdit && (
            <div style={{ marginTop: 16 }}>
              <label style={labelStyle}>TEMPLATES</label>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {[
                  { label: "DoS Flood",    raw: 'alert tcp any any -> any 80 (msg:"DoS HTTP Flood"; content:"GET"; threshold: type both, track by_src, count 200, seconds 1; classtype:attempted-dos; sid:2001; rev:1;)' },
                  { label: "SQL Inject",   raw: 'alert tcp any any -> any 80 (msg:"SQL Injection"; content:"UNION"; content:"SELECT"; nocase; classtype:web-application-attack; sid:2002; rev:1;)' },
                  { label: "Port Scan",    raw: 'alert tcp any any -> any any (msg:"SYN Port Scan"; flags:S; threshold: type both, track by_src, count 20, seconds 60; classtype:network-scan; sid:2003; rev:1;)' },
                  { label: "SSH Brute",    raw: 'alert tcp any any -> any 22 (msg:"SSH Brute Force"; flags:S; threshold: type both, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:2004; rev:1;)' },
                ].map(t => (
                  <button key={t.label} onClick={() => { setRaw(t.raw); setErrors([]); }}
                    style={{ padding: "4px 10px", background: C.muted, border: `1px solid ${C.border}`, borderRadius: 3, color: C.text, fontSize: 10, cursor: "pointer", fontFamily: "'JetBrains Mono', monospace" }}>
                    {t.label}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div style={{ padding: "12px 20px", borderTop: `1px solid ${C.border}`, display: "flex", justifyContent: "flex-end", gap: 8, background: C.panelB }}>
          <button onClick={onClose} style={{ ...btnStyle, background: C.muted, color: C.text, border: `1px solid ${C.border}` }}>
            CANCEL
          </button>
          <button onClick={handleSave} style={{ ...btnStyle, background: C.greenDim, color: C.acid, border: `1px solid ${C.acid}50` }}>
            {isEdit ? "SAVE CHANGES" : "CREATE RULE"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── DeleteConfirm ─────────────────────────────────────────────────────────────
function DeleteConfirm({ rule, onConfirm, onClose }) {
  if (!rule) return null;
  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 300, background: "rgba(0,0,0,0.8)", display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ width: 420, background: C.panel, border: `1px solid ${C.red}60`, borderRadius: 6, overflow: "hidden" }}>
        <div style={{ padding: "16px 20px", borderBottom: `1px solid ${C.border}`, background: C.redDim }}>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: C.red, letterSpacing: 1 }}>DELETE RULE</span>
        </div>
        <div style={{ padding: "20px" }}>
          <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: C.text, lineHeight: 1.7, marginBottom: 8 }}>
            Permanently delete rule <span style={{ color: C.textBright }}>{rule.rule_id}</span>?
          </p>
          <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: C.textDim, lineHeight: 1.6 }}>
            "{rule.rule_name}"
          </p>
          <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: C.red, marginTop: 12 }}>
            This action cannot be undone. {rule.hits} recorded hits will be lost.
          </p>
        </div>
        <div style={{ padding: "12px 20px", borderTop: `1px solid ${C.border}`, display: "flex", justifyContent: "flex-end", gap: 8 }}>
          <button onClick={onClose} style={{ ...btnStyle, background: C.muted, color: C.text, border: `1px solid ${C.border}` }}>CANCEL</button>
          <button onClick={onConfirm} style={{ ...btnStyle, background: C.redDim, color: C.red, border: `1px solid ${C.red}60` }}>DELETE</button>
        </div>
      </div>
    </div>
  );
}

// ── Shared styles ─────────────────────────────────────────────────────────────
const labelStyle = {
  display: "block",
  fontFamily: "'JetBrains Mono', monospace",
  fontSize: 9,
  color: C.textDim,
  letterSpacing: 1.5,
  marginBottom: 5,
};
const inputStyle = {
  width: "100%",
  background: C.bg,
  border: `1px solid ${C.border}`,
  borderRadius: 3,
  padding: "7px 10px",
  fontFamily: "'JetBrains Mono', monospace",
  fontSize: 11,
  color: C.textBright,
  outline: "none",
};
const btnStyle = {
  padding: "6px 16px",
  borderRadius: 3,
  fontSize: 10,
  fontFamily: "'JetBrains Mono', monospace",
  cursor: "pointer",
  letterSpacing: 1,
  fontWeight: 700,
  border: "1px solid transparent",
};

// ── RuleRow ───────────────────────────────────────────────────────────────────
function RuleRow({ rule, expanded, onExpand, onToggle, onEdit, onDelete }) {
  if (!rule) return null;
  const sevColor = SEV_COLOR[rule.severity] || C.text;
  return (
    <>
      <div
        onClick={onExpand}
        style={{
          display: "grid",
          gridTemplateColumns: "26px 90px 1fr 90px 70px 80px 90px 110px",
          alignItems: "center",
          gap: 0,
          padding: "0 0",
          borderBottom: `1px solid ${expanded ? C.borderHi : C.border}`,
          cursor: "pointer",
          background: expanded ? "#0f1a0d" : "transparent",
          transition: "background 0.12s",
        }}
        onMouseEnter={e => { if (!expanded) e.currentTarget.style.background = "#0c110a"; }}
        onMouseLeave={e => { if (!expanded) e.currentTarget.style.background = "transparent"; }}
      >
        {/* Expand chevron */}
        <div style={{ padding: "10px 0 10px 14px", color: C.textDim, fontSize: 10 }}>
          {expanded ? "▾" : "▸"}
        </div>

        {/* SID */}
        <div style={{ padding: "10px 8px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: C.purple }}>
          {rule.rule_id}
        </div>

        {/* Name */}
        <div style={{ padding: "10px 8px", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: C.textBright, overflow: "hidden", whiteSpace: "nowrap", textOverflow: "ellipsis" }}>
          {rule.rule_name}
        </div>

        {/* Category */}
        <div style={{ padding: "10px 8px" }}>
          <span style={{
            padding: "2px 7px", borderRadius: 3,
            background: C.muted, border: `1px solid ${C.border}`,
            fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: C.text, letterSpacing: 0.5,
          }}>
            {rule.attack_category}
          </span>
        </div>

        {/* Severity */}
        <div style={{ padding: "10px 8px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: sevColor, fontWeight: 700 }}>
          {rule.severity}
        </div>

        {/* Hits */}
        <div style={{ padding: "10px 8px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: rule.hits > 0 ? C.amber : C.textDim, textAlign: "right" }}>
          {rule.hits.toLocaleString()}
        </div>

        {/* Toggle */}
        <div style={{ padding: "10px 8px" }} onClick={e => { e.stopPropagation(); onToggle(); }}>
          <div style={{
            width: 36, height: 18, borderRadius: 10,
            background: rule.is_enabled ? C.greenDim : C.muted,
            border: `1px solid ${rule.is_enabled ? C.acid + "60" : C.border}`,
            position: "relative", cursor: "pointer", transition: "all 0.2s",
          }}>
            <div style={{
              position: "absolute", top: 2,
              left: rule.is_enabled ? 18 : 2,
              width: 12, height: 12, borderRadius: "50%",
              background: rule.is_enabled ? C.acid : C.textDim,
              transition: "left 0.2s, background 0.2s",
              boxShadow: rule.is_enabled ? `0 0 6px ${C.acid}80` : "none",
            }} />
          </div>
        </div>

        {/* Actions */}
        <div style={{ padding: "10px 14px 10px 0", display: "flex", gap: 6, justifyContent: "flex-end" }} onClick={e => e.stopPropagation()}>
          <button
            onClick={onEdit}
            style={{ padding: "3px 10px", background: "transparent", border: `1px solid ${C.border}`, borderRadius: 3, color: C.text, fontSize: 9, cursor: "pointer", fontFamily: "'JetBrains Mono', monospace", letterSpacing: 0.5 }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = C.blue; e.currentTarget.style.color = C.blue; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.color = C.text; }}
          >
            EDIT
          </button>
          <button
            onClick={onDelete}
            style={{ padding: "3px 10px", background: "transparent", border: `1px solid ${C.border}`, borderRadius: 3, color: C.text, fontSize: 9, cursor: "pointer", fontFamily: "'JetBrains Mono', monospace", letterSpacing: 0.5 }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = C.red; e.currentTarget.style.color = C.red; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.color = C.text; }}
          >
            DEL
          </button>
        </div>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div style={{ background: "#0b140a", borderBottom: `1px solid ${C.borderHi}`, padding: "12px 20px 14px 50px" }}>
          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, lineHeight: 1.9, wordBreak: "break-all" }}>
            {highlightRule(rule.raw)}
          </div>
          <div style={{ marginTop: 10, display: "grid", gridTemplateColumns: "repeat(5, auto)", gap: "4px 24px", width: "fit-content" }}>
            {[
              ["PROTOCOL", rule.protocol?.toUpperCase()],
              ["SRC", `${rule.src}:${rule.srcPort}`],
              ["DST", `${rule.dst}:${rule.dstPort}`],
              ["CREATED", rule.created],
              ["HITS", rule.hits.toLocaleString()],
            ].map(([k, v]) => (
              <div key={k}>
                <div style={{ fontSize: 8, color: C.textDim, letterSpacing: 1 }}>{k}</div>
                <div style={{ fontSize: 10, color: C.text, fontFamily: "'JetBrains Mono', monospace" }}>{v}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function RulesManagement() {
  const queryClient = useQueryClient();
  const { data: rulesData, isLoading, isError } = useQuery(['rules'], fetchRules, {
    staleTime: 30_000,
  });

  const [search, setSearch]       = useState("");
  const [filterCat, setFilterCat] = useState("ALL");
  const [filterSev, setFilterSev] = useState("ALL");
  const [filterStat, setFilterStat] = useState("ALL");
  const [expanded, setExpanded]   = useState(null);
  const [showCreate, setShowCreate] = useState(false);
  const [editTarget, setEditTarget] = useState(null);  // rule obj | null
  const [delTarget, setDelTarget] = useState(null);
  const [toast, setToast]         = useState(null);

  const rules = rulesData?.rules ?? [];

  function showToast(msg, type = "ok") {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 2800);
  }

  async function toggleRule(id) {
    const rule = rules.find(r => r.rule_id === id);
    if (!rule) return;
    try {
      const updated = await toggleRuleApi(id, !rule.is_enabled);
      queryClient.invalidateQueries(['rules']);
      showToast(`${updated.rule_id} ${updated.is_enabled ? 'enabled' : 'disabled'}`);
    } catch (err) {
      showToast('Failed to update rule', 'warn');
    }
  }

  async function saveRule(data) {
    try {
      if (showCreate) {
        const newRuleId = nextSid(rules);
        await createRule({
          rule_id: newRuleId,
          rule_name: data.name,
          rule_content: data.raw,
          attack_category: data.category,
          severity: data.severity,
          is_enabled: true,
        });
        queryClient.invalidateQueries(['rules']);
        showToast(`${newRuleId} created`);
        setShowCreate(false);
      } else if (editTarget) {
        const id = editTarget.rule_id;
        await updateRuleApi(id, {
          rule_name: data.name,
          rule_content: data.raw,
          attack_category: data.category,
          severity: data.severity,
        });
        queryClient.invalidateQueries(['rules']);
        setEditTarget(null);
        showToast(`${id} updated`);
      }
    } catch (err) {
      showToast('Failed to save rule', 'warn');
    }
  }

  async function deleteRule() {
    if (!delTarget) return;
    const id = delTarget.rule_id;
    try {
      await deleteRuleApi(id);
      queryClient.invalidateQueries(['rules']);
      setDelTarget(null);
      setExpanded(null);
      showToast(`${id} deleted`, 'warn');
    } catch (err) {
      showToast('Failed to delete rule', 'warn');
    }
  }

  const filtered = rules.filter(r => {
    if (filterCat !== "ALL" && r.attack_category !== filterCat) return false;
    if (filterSev !== "ALL" && r.severity !== filterSev) return false;
    if (filterStat === "ENABLED"  && !r.is_enabled) return false;
    if (filterStat === "DISABLED" && r.is_enabled)  return false;
    if (search && !r.rule_name.toLowerCase().includes(search.toLowerCase()) && !r.rule_id.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const enabledCount  = rules.filter(r => r.is_enabled).length;
  const alertCount    = rules.filter(r => r.severity === "CRITICAL" || r.severity === "HIGH").length;
  const totalHits     = rules.reduce((s, r) => s + (r.hits ?? 0), 0);

  return (
    <div style={{ background: C.bg, minHeight: "100vh", color: C.text, display: "flex", flexDirection: "column", fontFamily: "'JetBrains Mono', monospace", position: "relative" }}>

      {/* Scanlines */}
      <div style={{ position: "fixed", inset: 0, pointerEvents: "none", zIndex: 0, backgroundImage: "repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(0,0,0,0.025) 3px,rgba(0,0,0,0.025) 4px)" }} />

      {/* Toast */}
      {toast && (
        <div style={{
          position: "fixed", bottom: 24, right: 24, zIndex: 500,
          padding: "10px 18px",
          background: toast.type === "warn" ? C.redDim : C.greenDim,
          border: `1px solid ${toast.type === "warn" ? C.red + "60" : C.acid + "50"}`,
          borderRadius: 4,
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 11,
          color: toast.type === "warn" ? C.red : C.acid,
          boxShadow: "0 4px 24px rgba(0,0,0,0.5)",
          animation: "fadeIn 0.2s ease",
        }}>
          ✓ {toast.msg}
        </div>
      )}

      {/* Header */}
      <div style={{
        padding: "14px 24px",
        borderBottom: `1px solid ${C.border}`,
        background: C.panelB,
        display: "flex", alignItems: "center", justifyContent: "space-between",
        position: "relative", zIndex: 10,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 3, height: 20, background: C.acid, borderRadius: 2 }} />
            <span style={{ fontSize: 12, color: C.textBright, letterSpacing: 2 }}>DETECTION RULES</span>
          </div>
          <span style={{ color: C.border, fontSize: 12 }}>|</span>
          <span style={{ fontSize: 10, color: C.textDim }}>SNORT-COMPATIBLE · {rules.length} RULES LOADED</span>
        </div>

        {/* Stats */}
        <div style={{ display: "flex", gap: 20, alignItems: "center" }}>
          {[
            { label: "TOTAL", val: rules.length, color: C.text },
            { label: "ENABLED", val: enabledCount, color: C.acid },
            { label: "HIGH+CRITICAL", val: alertCount, color: C.amber },
            { label: "TOTAL HITS", val: totalHits.toLocaleString(), color: C.blue },
          ].map(({ label, val, color }) => (
            <div key={label} style={{ textAlign: "right" }}>
              <div style={{ fontSize: 8, color: C.textDim, letterSpacing: 1 }}>{label}</div>
              <div style={{ fontSize: 14, fontWeight: 700, color }}>{val}</div>
            </div>
          ))}

          <button
            onClick={() => setShowCreate(true)}
            style={{ ...btnStyle, background: C.greenDim, color: C.acid, border: `1px solid ${C.acid}50`, marginLeft: 8 }}
            onMouseEnter={e => { e.currentTarget.style.background = "#1e3a18"; }}
            onMouseLeave={e => { e.currentTarget.style.background = C.greenDim; }}
          >
            + CREATE RULE
          </button>
        </div>
      </div>

      {/* Filter bar */}
      <div style={{
        padding: "8px 24px",
        borderBottom: `1px solid ${C.border}`,
        background: C.panel,
        display: "flex", alignItems: "center", gap: 16,
        position: "relative", zIndex: 10,
        flexWrap: "wrap",
      }}>
        {/* Search */}
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search by name or SID…"
          style={{ ...inputStyle, width: 220, padding: "5px 10px", fontSize: 10 }}
        />

        {/* Category filter */}
        <div style={{ display: "flex", gap: 5, alignItems: "center" }}>
          <span style={{ fontSize: 9, color: C.textDim, letterSpacing: 1 }}>CAT</span>
          {["ALL", ...CAT_LIST].map(c => (
            <button key={c} onClick={() => setFilterCat(c)} style={{
              padding: "3px 8px", borderRadius: 3, fontSize: 9, cursor: "pointer",
              fontFamily: "'JetBrains Mono', monospace", letterSpacing: 0.3,
              background: filterCat === c ? C.muted : "transparent",
              border: `1px solid ${filterCat === c ? C.borderHi : C.border}`,
              color: filterCat === c ? C.textBright : C.textDim,
            }}>{c}</button>
          ))}
        </div>

        <span style={{ color: C.border }}>|</span>

        {/* Severity filter */}
        <div style={{ display: "flex", gap: 5, alignItems: "center" }}>
          <span style={{ fontSize: 9, color: C.textDim, letterSpacing: 1 }}>SEV</span>
          {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map(s => (
            <button key={s} onClick={() => setFilterSev(s)} style={{
              padding: "3px 8px", borderRadius: 3, fontSize: 9, cursor: "pointer",
              fontFamily: "'JetBrains Mono', monospace", letterSpacing: 0.3,
              background: filterSev === s ? C.muted : "transparent",
              border: `1px solid ${filterSev === s ? (SEV_COLOR[s] || C.borderHi) + "80" : C.border}`,
              color: filterSev === s ? (SEV_COLOR[s] || C.textBright) : C.textDim,
            }}>{s}</button>
          ))}
        </div>

        <span style={{ color: C.border }}>|</span>

        {/* Status filter */}
        <div style={{ display: "flex", gap: 5, alignItems: "center" }}>
          <span style={{ fontSize: 9, color: C.textDim, letterSpacing: 1 }}>STATUS</span>
          {["ALL", "ENABLED", "DISABLED"].map(s => (
            <button key={s} onClick={() => setFilterStat(s)} style={{
              padding: "3px 8px", borderRadius: 3, fontSize: 9, cursor: "pointer",
              fontFamily: "'JetBrains Mono', monospace", letterSpacing: 0.3,
              background: filterStat === s ? C.muted : "transparent",
              border: `1px solid ${filterStat === s ? C.borderHi : C.border}`,
              color: filterStat === s ? C.textBright : C.textDim,
            }}>{s}</button>
          ))}
        </div>

        <span style={{ marginLeft: "auto", fontSize: 10, color: C.textDim }}>
          {filtered.length} of {rules.length} rules
        </span>
      </div>

      {/* Table header */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "26px 90px 1fr 90px 70px 80px 90px 110px",
        padding: "6px 0",
        borderBottom: `1px solid ${C.borderHi}`,
        background: C.panelB,
        position: "relative", zIndex: 10,
      }}>
        {["", "SID", "NAME", "CATEGORY", "SEVERITY", "HITS", "STATUS", ""].map((h, i) => (
          <div key={i} style={{ padding: "0 8px", fontSize: 9, color: C.textDim, letterSpacing: 1.5, textAlign: i === 5 ? "right" : "left" }}>
            {h}
          </div>
        ))}
      </div>

      {/* Rule rows */}
      <div style={{ flex: 1, overflowY: "auto", position: "relative", zIndex: 10 }}>
        {filtered.length === 0 ? (
          <div style={{ padding: 40, textAlign: "center", color: C.textDim, fontSize: 11 }}>
            No rules match the current filters.
          </div>
        ) : (
          filtered.map(rule => (
            <RuleRow
              key={rule.rule_id}
              rule={rule}
              expanded={expanded === rule.rule_id}
              onExpand={() => setExpanded(expanded === rule.rule_id ? null : rule.rule_id)}
              onToggle={() => toggleRule(rule.rule_id)}
              onEdit={() => setEditTarget(rule)}
              onDelete={() => setDelTarget(rule)}
            />
          ))
        )}
      </div>

      {/* Modals */}
      {showCreate && (
        <RuleModal
          rule={null}
          onSave={saveRule}
          onClose={() => setShowCreate(false)}
        />
      )}
      {editTarget && (
        <RuleModal
          rule={editTarget}
          onSave={saveRule}
          onClose={() => setEditTarget(null)}
        />
      )}
      {delTarget && (
        <DeleteConfirm
          rule={delTarget}
          onConfirm={deleteRule}
          onClose={() => setDelTarget(null)}
        />
      )}

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700;900&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: ${C.bg}; }
        ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 2px; }
        select option { background: ${C.panel}; color: ${C.textBright}; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
      `}</style>
    </div>
  );
}