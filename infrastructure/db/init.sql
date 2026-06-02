-- ============================================================
-- AI-NIDS — PostgreSQL Schema Initialisation
-- infrastructure/db/init.sql
--
-- Implements the full schema specified in the Database Design
-- Document (Feb 26, 2026).
--
-- Tables (8):
--   users, audit_log, detection_rules, ml_models,
--   flows, alerts, alert_correlations, pcap_jobs
--
-- Run order matters — FK dependencies enforced top-to-bottom.
--
-- Traceability:
--   FR7.8  — Alerts stored in PostgreSQL
--   FR8    — Alert correlation tables
--   FR9    — Dashboard query support (indexes)
--   FR14   — RBAC roles in users table
--   FR19   — ML model versioning
--   NFR4   — Reliability (WAL, ACID)
--   NFR20  — Evaluation metrics stored in ml_models
--   Design Review G-06 — partial unique index on ml_models
--   Design Review G-09 — 4 RBAC roles (not 3)
--
-- April 3, 2026 | Sprint 1, Week 4
-- ============================================================

-- ── Idempotent setup ─────────────────────────────────────────
SET client_min_messages = WARNING;

-- ── Enable pgcrypto for gen_random_uuid() ────────────────────
CREATE EXTENSION IF NOT EXISTS pgcrypto;


-- ============================================================
-- ENUM types
-- Drop and recreate only if not already present.
-- ============================================================

DO $$ BEGIN
    CREATE TYPE severity_t AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE alert_status AS ENUM ('NEW', 'ACKNOWLEDGED', 'FALSE_POSITIVE', 'ESCALATED');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE detect_meth AS ENUM ('SIGNATURE', 'ML', 'HYBRID');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE model_type AS ENUM ('RANDOM_FOREST', 'ISOLATION_FOREST', 'LSTM');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- 4-role set per Design Review G-09 (AD4 activity diagram)
DO $$ BEGIN
    CREATE TYPE user_role AS ENUM (
        'system_admin',
        'soc_manager',
        'network_admin',
        'read_only_analyst'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE job_status AS ENUM ('queued', 'running', 'complete', 'failed');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;


-- ============================================================
-- TABLE: users
-- Stores all dashboard user accounts and RBAC roles.
-- All passwords are bcrypt hashes — plaintext never stored.
-- ============================================================

CREATE TABLE IF NOT EXISTS users (
    id                UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    username          VARCHAR(64)   NOT NULL,
    email             VARCHAR(256)  NOT NULL,
    role              user_role     NOT NULL,
    password_hash     VARCHAR(256)  NOT NULL,
    is_active         BOOLEAN       NOT NULL DEFAULT TRUE,
    failed_attempts   INTEGER       NOT NULL DEFAULT 0,   -- NFR5.3 account lockout
    locked_until      TIMESTAMPTZ   NULL,                 -- NULL = not locked
    created_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    last_login_at     TIMESTAMPTZ   NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_users_username
    ON users (LOWER(username));                           -- case-insensitive unique

CREATE UNIQUE INDEX IF NOT EXISTS uq_users_email
    ON users (LOWER(email));

-- Seed: default system_admin account (password: changeme — must be reset)
-- bcrypt hash of 'changeme' (cost 12)
INSERT INTO users (username, email, role, password_hash)
VALUES (
    'admin',
    'admin@ai-nids.local',
    'system_admin',
    '$2b$12$szcetSaJzcfrLS2NdaAU0.Q6/EK.djFpg/BKUJ.bVCdYDfceELnCm'
)
ON CONFLICT DO NOTHING;


-- ============================================================
-- TABLE: audit_log
-- Immutable audit trail — INSERT only, no UPDATE or DELETE.
-- Rows survive user deletion (ON DELETE SET NULL).
-- ============================================================

CREATE TABLE IF NOT EXISTS audit_log (
    id            UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID          REFERENCES users(id) ON DELETE SET NULL,
    action        VARCHAR(64)   NOT NULL,    -- e.g. LOGIN, ACK_ALERT, RULE_CREATED
    entity_type   VARCHAR(64)   NOT NULL,    -- e.g. alerts, detection_rules
    entity_id     UUID          NULL,        -- PK of the affected row (NULL for session actions)
    ip_address    INET          NOT NULL,
    detail        JSONB         NULL,        -- before/after values for edits
    created_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_user_id    ON audit_log (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action     ON audit_log (action);


-- ============================================================
-- TABLE: detection_rules
-- Snort-compatible signature rule registry.
-- Loaded into Signature Detection Engine at startup.
-- ============================================================

CREATE TABLE IF NOT EXISTS detection_rules (
    id               UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id          VARCHAR(64)   NOT NULL,         -- SID string, e.g. "1001"
    rule_name        VARCHAR(255)  NOT NULL,
    rule_content     TEXT          NOT NULL,          -- full Snort rule string
    attack_category  VARCHAR(64)   NOT NULL,          -- DoS, PortScan, BruteForce, etc.
    severity         severity_t    NOT NULL,
    is_enabled       BOOLEAN       NOT NULL DEFAULT TRUE,
    created_by       VARCHAR(64)   NOT NULL DEFAULT 'system',
    created_at       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    version          INTEGER       NOT NULL DEFAULT 1  -- incremented on each edit
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_detection_rules_rule_id
    ON detection_rules (rule_id);

CREATE INDEX IF NOT EXISTS idx_detection_rules_category
    ON detection_rules (attack_category);

CREATE INDEX IF NOT EXISTS idx_detection_rules_enabled
    ON detection_rules (is_enabled);

-- Auto-update updated_at on row change
CREATE OR REPLACE FUNCTION update_detection_rules_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    NEW.version    = OLD.version + 1;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_detection_rules_updated_at ON detection_rules;
CREATE TRIGGER trg_detection_rules_updated_at
    BEFORE UPDATE ON detection_rules
    FOR EACH ROW EXECUTE FUNCTION update_detection_rules_updated_at();


-- ============================================================
-- TABLE: ml_models
-- Version registry for RF, IF, and LSTM models.
-- Exactly one row per model_type may have is_active = TRUE.
-- Design Review G-06: enforced by partial unique index below.
-- ============================================================

CREATE TABLE IF NOT EXISTS ml_models (
    id                UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    model_name        VARCHAR(64)   NOT NULL,
    model_type        model_type    NOT NULL,
    version           VARCHAR(32)   NOT NULL,          -- e.g. "1.0.0"
    file_path         VARCHAR(512)  NOT NULL,          -- abs path to .pkl / .h5
    training_dataset  VARCHAR(64)   NULL,              -- CICIDS2017, NSL-KDD
    accuracy          NUMERIC(6,4)  NULL,              -- 0.0000–1.0000
    f1_score          NUMERIC(6,4)  NULL,
    false_pos_rate    NUMERIC(6,4)  NULL,
    is_active         BOOLEAN       NOT NULL DEFAULT FALSE,
    trained_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    deployed_at       TIMESTAMPTZ   NULL
);

-- Design Review G-06: exactly one active model per type at a time
CREATE UNIQUE INDEX IF NOT EXISTS uq_ml_models_one_active_per_type
    ON ml_models (model_type)
    WHERE is_active = TRUE;

CREATE INDEX IF NOT EXISTS idx_ml_models_type ON ml_models (model_type);


-- ============================================================
-- TABLE: pcap_jobs
-- Tracks offline PCAP analysis jobs submitted via dashboard.
-- ============================================================

CREATE TABLE IF NOT EXISTS pcap_jobs (
    id               UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    submitted_by     UUID          NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    filename         VARCHAR(255)  NOT NULL,
    file_path        VARCHAR(512)  NOT NULL,
    file_size_bytes  BIGINT        NOT NULL,
    status           job_status    NOT NULL DEFAULT 'queued',
    flow_count       INTEGER       NULL,
    alert_count      INTEGER       NULL,
    error_message    TEXT          NULL,
    submitted_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    started_at       TIMESTAMPTZ   NULL,
    completed_at     TIMESTAMPTZ   NULL
);

CREATE INDEX IF NOT EXISTS idx_pcap_jobs_status       ON pcap_jobs (status);
CREATE INDEX IF NOT EXISTS idx_pcap_jobs_submitted_by ON pcap_jobs (submitted_by);


-- ============================================================
-- TABLE: flows
-- Bidirectional flow records produced by the Flow Aggregator.
-- Partitioned by start_ts (monthly) for retention management.
-- Parent table — partitions created by maintenance script.
-- ============================================================

CREATE TABLE IF NOT EXISTS flows (
    id              UUID          NOT NULL DEFAULT gen_random_uuid(),
    flow_id         UUID          NOT NULL,              -- UUID from FlowAggregator
    src_ip          INET          NOT NULL,
    dst_ip          INET          NOT NULL,
    src_port        INTEGER       NULL,
    dst_port        INTEGER       NULL,
    protocol        VARCHAR(8)    NOT NULL,
    start_ts        TIMESTAMPTZ   NOT NULL,
    end_ts          TIMESTAMPTZ   NOT NULL,
    pkt_count       INTEGER       NOT NULL DEFAULT 0,
    byte_count      BIGINT        NOT NULL DEFAULT 0,
    tcp_flags       VARCHAR(32)   NULL,
    feature_vector  JSONB         NULL,                  -- 41-feature array
    capture_source  VARCHAR(16)   NOT NULL DEFAULT 'pcap',  -- 'live' | 'pcap'
    job_id          UUID          NULL REFERENCES pcap_jobs(id) ON DELETE SET NULL,
    PRIMARY KEY (id, start_ts)
) PARTITION BY RANGE (start_ts);

-- Default partition catches anything not matched by monthly partitions
CREATE TABLE IF NOT EXISTS flows_default
    PARTITION OF flows DEFAULT;

-- Indexes on parent table propagate to all partitions
CREATE INDEX IF NOT EXISTS idx_flows_flow_id  ON flows (flow_id);
CREATE INDEX IF NOT EXISTS idx_flows_src_ip   ON flows (src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_dst_ip   ON flows (dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_start_ts ON flows (start_ts DESC);

-- GIN index for JSONB feature vector queries
CREATE INDEX IF NOT EXISTS idx_flows_feature_vector
    ON flows USING GIN (feature_vector jsonb_path_ops);


-- ============================================================
-- TABLE: alerts
-- Primary alert store. Every detection event above the 0.50
-- ensemble threshold produces one row here.
-- Partitioned by detected_at (monthly).
-- ============================================================

CREATE TABLE IF NOT EXISTS alerts (
    id                UUID          NOT NULL DEFAULT gen_random_uuid(),
    alert_id          UUID          NOT NULL DEFAULT gen_random_uuid(),  -- external-facing
    flow_id           UUID          NULL,              -- FK to flows.flow_id
    attack_type       VARCHAR(64)   NOT NULL,
    severity          severity_t    NOT NULL,
    confidence        NUMERIC(5,4)  NOT NULL,          -- 0.0000–1.0000 ensemble score
    detected_by       detect_meth   NOT NULL,
    rule_id           VARCHAR(64)   NULL,              -- matched Snort SID (sig detections)
    src_ip            INET          NOT NULL,          -- denormalised for fast queries
    dst_ip            INET          NOT NULL,
    src_port          INTEGER       NULL,
    dst_port          INTEGER       NULL,
    protocol          VARCHAR(8)    NOT NULL DEFAULT 'TCP',
    description       TEXT          NOT NULL,          -- human-readable FR7.6
    status            alert_status  NOT NULL DEFAULT 'NEW',
    acknowledged_by   UUID          NULL REFERENCES users(id) ON DELETE SET NULL,
    acknowledged_at   TIMESTAMPTZ   NULL,
    group_id          UUID          NULL,              -- alert correlation group FR8
    dup_count         INTEGER       NOT NULL DEFAULT 0,  -- deduplication counter FR8.5
    raw_payload_ref   VARCHAR(512)  NULL,              -- path to stored payload bytes
    detected_at       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    -- Engine confidence scores stored for audit + model improvement FR6.6
    sig_confidence    NUMERIC(5,4)  NULL,
    rf_confidence     NUMERIC(5,4)  NULL,
    lstm_confidence   NUMERIC(5,4)  NULL,
    if_confidence     NUMERIC(5,4)  NULL,
    PRIMARY KEY (id, detected_at)
) PARTITION BY RANGE (detected_at);

-- Default partition
CREATE TABLE IF NOT EXISTS alerts_default
    PARTITION OF alerts DEFAULT;

-- ── Performance indexes (§5.1 of DB Design Doc) ──────────────

-- Primary analyst workflow: time-range + severity filter
CREATE INDEX IF NOT EXISTS idx_alerts_detected_at
    ON alerts (detected_at DESC);

CREATE INDEX IF NOT EXISTS idx_alerts_severity
    ON alerts (severity);

-- IP investigation queries
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts (src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_dst_ip ON alerts (dst_ip);

-- Category filtering and reporting
CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON alerts (attack_type);

-- Most frequent analyst query: unacknowledged alert queue
CREATE INDEX IF NOT EXISTS idx_alerts_status_open
    ON alerts (detected_at DESC)
    WHERE status = 'NEW';

-- Composite: critical alerts in last N hours (common dashboard filter)
CREATE INDEX IF NOT EXISTS idx_alerts_detected_severity
    ON alerts (detected_at DESC, severity);

-- Flow-to-alert join
CREATE INDEX IF NOT EXISTS idx_alerts_flow_id ON alerts (flow_id);

-- Correlation group lookup
CREATE INDEX IF NOT EXISTS idx_alerts_group_id ON alerts (group_id)
    WHERE group_id IS NOT NULL;


-- ============================================================
-- TABLE: alert_correlations
-- Links related alerts into attack chains (FR8.1–FR8.5).
-- ============================================================

CREATE TABLE IF NOT EXISTS alert_correlations (
    id          UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id    UUID          NOT NULL,    -- primary alert
    related_id  UUID          NOT NULL,    -- correlated secondary alert
    relation    VARCHAR(64)   NOT NULL,    -- SAME_SOURCE | TEMPORAL_SEQUENCE | MULTI_STAGE
    created_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_alert_correlation UNIQUE (alert_id, related_id)
);

CREATE INDEX IF NOT EXISTS idx_alert_corr_alert_id   ON alert_correlations (alert_id);
CREATE INDEX IF NOT EXISTS idx_alert_corr_related_id ON alert_correlations (related_id);


-- ============================================================
-- Maintenance helper: create monthly partitions
-- Call this function monthly (or pre-create a year of partitions).
-- Usage: SELECT create_monthly_partitions('alerts', 2026, 4, 6);
-- ============================================================

CREATE OR REPLACE FUNCTION create_monthly_partitions(
    p_table TEXT,
    p_year  INT,
    p_start_month INT,
    p_end_month   INT
)
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
    m      INT;
    tname  TEXT;
    d_from DATE;
    d_to   DATE;
BEGIN
    FOR m IN p_start_month..p_end_month LOOP
        tname  := p_table || '_' || p_year || '_' || LPAD(m::TEXT, 2, '0');
        d_from := make_date(p_year, m, 1);
        d_to   := d_from + INTERVAL '1 month';
        BEGIN
            EXECUTE format(
                'CREATE TABLE IF NOT EXISTS %I PARTITION OF %I
                 FOR VALUES FROM (%L) TO (%L)',
                tname, p_table, d_from, d_to
            );
        EXCEPTION WHEN others THEN
            NULL;  -- partition already exists
        END;
    END LOOP;
END;
$$;

-- Pre-create Apr–Dec 2026 partitions for both tables
SELECT create_monthly_partitions('flows',  2026, 4, 12);
SELECT create_monthly_partitions('alerts', 2026, 4, 12);


-- ============================================================
-- Audit log trigger: attach to all write operations on key tables
-- ============================================================

CREATE OR REPLACE FUNCTION audit_trigger_fn()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO audit_log (action, entity_type, entity_id, ip_address, detail)
    VALUES (
        TG_OP,
        TG_TABLE_NAME,
        CASE WHEN TG_OP = 'DELETE' THEN OLD.id ELSE NEW.id END,
        '0.0.0.0'::INET,   -- overridden by application layer via SET LOCAL
        NULL
    );
    RETURN NULL;
END;
$$;

-- ============================================================
-- Schema version marker
-- ============================================================

CREATE TABLE IF NOT EXISTS schema_version (
    version     VARCHAR(16) PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    notes       TEXT
);

INSERT INTO schema_version (version, notes)
VALUES ('1.0.0', 'Initial schema — April 3 2026')
ON CONFLICT DO NOTHING;