"""
AI-NIDS — SQLAlchemy ORM Models
db/models.py

Implements the eight-table schema from the Database Design Document (Feb 26).
All tables use UUID PKs, TIMESTAMPTZ stored as UTC, JSONB for feature vectors.

FR Traceability:
    FR7.8   — Alerts stored in PostgreSQL
    FR8     — Alert correlations
    FR4.1   — Detection rules
    FR5.8   — ML model versioning
    FR14.2  — User RBAC roles
    NFR7.1  — Immutable audit log

April 3, 2026 | Sprint 1, Week 4
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Enum as SAEnum, Float, Integer,
    String, Text, ForeignKey, UniqueConstraint, Index,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET
from sqlalchemy.orm import relationship

from infrastructure.db.database import Base


def _now():
    return datetime.now(timezone.utc)


def _uuid():
    return str(uuid.uuid4())


# ── Users ─────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(256), unique=True, nullable=False)
    role = Column(SAEnum('system_admin', 'soc_manager', 'network_admin', 'read_only_analyst', name='user_role', create_type=False), nullable=False, default="read_only_analyst")
    password_hash = Column(String(256), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_now)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    failed_attempts = Column(Integer, nullable=False, default=0)

    acknowledged_alerts = relationship("Alert", back_populates="acknowledged_by_user",
                                       foreign_keys="Alert.acknowledged_by")
    audit_entries = relationship("AuditLog", back_populates="user")


# ── Detection Rules ───────────────────────────────────────────
class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    rule_id = Column(String(64), unique=True, nullable=False, index=True)   # e.g. SID:1001
    rule_name = Column(String(255), nullable=False)
    rule_content = Column(Text, nullable=False)                              # Full Snort rule string
    attack_category = Column(String(64), nullable=False, index=True)
    severity = Column(SAEnum('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', name='severity_t', create_type=False), nullable=False, default="MEDIUM")
    is_enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_now, onupdate=_now)
    version = Column(Integer, nullable=False, default=1)

    alerts = relationship("Alert", back_populates="rule")


# ── ML Models ─────────────────────────────────────────────────
class MLModel(Base):
    __tablename__ = "ml_models"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    model_name = Column(String(64), nullable=False)
    # Enum: RANDOM_FOREST | ISOLATION_FOREST | LSTM
    model_type = Column(String(32), nullable=False)
    version = Column(String(32), nullable=False)
    file_path = Column(String(512), nullable=False)
    training_dataset = Column(String(64), nullable=True)
    accuracy = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)
    false_pos_rate = Column(Float, nullable=True)
    # Only one active model per type — enforced by partial unique index below
    is_active = Column(Boolean, nullable=False, default=False)
    trained_at = Column(DateTime(timezone=True), nullable=False, default=_now)
    deployed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        # G-06 fix: enforce one active model per type at DB level
        Index(
            "ix_ml_models_one_active_per_type",
            "model_type",
            unique=True,
            postgresql_where=(is_active.is_(True)),
        ),
    )


# ── Flows ─────────────────────────────────────────────────────
class Flow(Base):
    __tablename__ = "flows"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    flow_id = Column(UUID(as_uuid=False), unique=True, nullable=False, index=True)
    src_ip = Column(String(45), nullable=False, index=True)     # INET stored as string for portability
    dst_ip = Column(String(45), nullable=False, index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True, index=True)
    protocol = Column(String(8), nullable=False)                # TCP | UDP | ICMP | OTHER
    start_ts = Column(DateTime(timezone=True), nullable=False, index=True)
    end_ts = Column(DateTime(timezone=True), nullable=False)
    pkt_count = Column(Integer, nullable=False, default=0)
    byte_count = Column(Integer, nullable=False, default=0)
    tcp_flags = Column(String(16), nullable=True)
    feature_vector = Column(JSONB, nullable=True)               # 41-feature array as JSON
    capture_source = Column(String(64), nullable=False, default="pcap")  # live | pcap_upload

    alerts = relationship("Alert", back_populates="flow")


# ── Alerts ────────────────────────────────────────────────────
class Alert(Base):
    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    alert_id = Column(UUID(as_uuid=False), unique=True, nullable=False, default=_uuid, index=True)

    # FK → flows
    flow_id = Column(UUID(as_uuid=False), ForeignKey("flows.flow_id"), nullable=True, index=True)

    attack_type = Column(String(64), nullable=False, index=True)
    # Enum: CRITICAL | HIGH | MEDIUM | LOW
    severity = Column(String(16), nullable=False, index=True)
    confidence = Column(Float, nullable=False)
    # Enum: signature | ml | both
    detected_by = Column(String(32), nullable=False, default="ml")

    # FK → detection_rules (nullable — ML-only detections have no rule)
    rule_id = Column(UUID(as_uuid=False), ForeignKey("detection_rules.id"), nullable=True)

    # Denormalised from flow for fast IP queries (FR9.4)
    src_ip = Column(String(45), nullable=False, index=True)
    dst_ip = Column(String(45), nullable=False, index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(8), nullable=True)

    description = Column(Text, nullable=False, default="")
    raw_payload_ref = Column(String(255), nullable=True)        # Path to stored packet payload

    # Enum: open | acknowledged | false_positive | escalated
    status = Column(String(32), nullable=False, default="open", index=True)

    # FK → users (who acknowledged)
    acknowledged_by = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=True)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)

    detected_at = Column(DateTime(timezone=True), nullable=False, default=_now, index=True)

    # Individual engine scores — stored for audit and model improvement (FR6.6)
    sig_confidence = Column(Float, nullable=True)
    rf_confidence = Column(Float, nullable=True)
    lstm_confidence = Column(Float, nullable=True)
    if_confidence = Column(Float, nullable=True)

    # Alert correlation group UUID (FR8)
    group_id = Column(UUID(as_uuid=False), nullable=True, index=True)

    # Duplicate suppression counter (FR8.5)
    dup_count = Column(Integer, nullable=False, default=0)

    # Relationships
    flow = relationship("Flow", back_populates="alerts")
    rule = relationship("DetectionRule", back_populates="alerts")
    acknowledged_by_user = relationship("User", back_populates="acknowledged_alerts",
                                        foreign_keys=[acknowledged_by])

    __table_args__ = (
        Index("ix_alerts_status_open", "status",
              postgresql_where=(status == "open")),
        Index("ix_alerts_detected_at_severity", "detected_at", "severity"),
    )


# ── Alert Correlations ────────────────────────────────────────
class AlertCorrelation(Base):
    __tablename__ = "alert_correlations"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    alert_id = Column(UUID(as_uuid=False), ForeignKey("alerts.alert_id"), nullable=False)
    related_id = Column(UUID(as_uuid=False), ForeignKey("alerts.alert_id"), nullable=False)
    # Enum: SAME_SOURCE | SAME_TARGET | TEMPORAL_SEQUENCE | MULTI_STAGE
    relation = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_now)


# ── Audit Log ─────────────────────────────────────────────────
class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    user_id = Column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"),
                     nullable=True, index=True)
    # e.g. ALERT_ACKNOWLEDGE | RULE_CREATED | MODEL_ACTIVATED | USER_LOGIN
    action = Column(String(64), nullable=False, index=True)
    entity_type = Column(String(64), nullable=False)            # Table name
    entity_id = Column(UUID(as_uuid=False), nullable=True)
    ip_address = Column(String(45), nullable=False, default="127.0.0.1")
    detail = Column(JSONB, nullable=True)                       # Before/after JSON
    created_at = Column(DateTime(timezone=True), nullable=False, default=_now, index=True)

    user = relationship("User", back_populates="audit_entries")