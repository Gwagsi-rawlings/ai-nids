"""
AI-NIDS — Pydantic API Schemas
api/schemas.py

Request / response models for all API endpoints.
Keeps ORM models separate from API contracts.

FR Traceability:
    FR7.2–FR7.7 — Alert fields (severity, attack_type, confidence, src_ip, description)
    FR9.2–FR9.5 — Alert filtering (severity, date, IP, type)
    FR4.2       — Snort-compatible rule syntax

April 3, 2026 | Sprint 1, Week 4
"""

from datetime import datetime
from typing import List, Optional, Union
from uuid import UUID

import enum

class DetectionMethod(str, enum.Enum):
    SIGNATURE   = "signature"
    RANDOM_FOREST = "random_forest"
    ISOLATION_FOREST = "isolation_forest"
    LSTM        = "lstm"
    ENSEMBLE    = "ensemble"
    HYBRID      = "HYBRID"


from pydantic import BaseModel, Field, field_validator, computed_field


# ─────────────────────────────────────────────
# Shared enumerations (as string literals)
# ─────────────────────────────────────────────

SEVERITY_LEVELS = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
ALERT_STATUSES = {"open", "acknowledged", "false_positive", "escalated"}
DETECT_METHODS = {"signature", "ml", "both"}


# ─────────────────────────────────────────────
# Alert schemas
# ─────────────────────────────────────────────

class AlertCreate(BaseModel):
    """Schema for ingesting a detection event from the pipeline (POST /alerts)."""
    attack_type: str = Field(..., max_length=64, description="Attack category label")
    severity: str = Field(default="LOW", description="CRITICAL | HIGH | MEDIUM | LOW")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Ensemble confidence [0,1]")
    detected_by: str = Field(default="ml", description="signature | ml | both")
    src_ip: str = Field(..., max_length=45)
    dst_ip: str = Field(..., max_length=45)
    src_port: Optional[int] = Field(None, ge=0, le=65535)
    dst_port: Optional[int] = Field(None, ge=0, le=65535)
    protocol: Optional[str] = Field(None, max_length=8)
    description: str = Field(default="", max_length=2000)
    flow_id: Optional[str] = None
    rule_id: Optional[str] = None
    # Per-engine confidence scores (FR6.6)
    sig_confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    rf_confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    lstm_confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    if_confidence: Optional[float] = Field(None, ge=0.0, le=1.0)

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v):
        if v.upper() not in SEVERITY_LEVELS:
            raise ValueError(f"severity must be one of {SEVERITY_LEVELS}")
        return v.upper()

    @field_validator("detected_by")
    @classmethod
    def validate_detected_by(cls, v):
        if v.lower() not in DETECT_METHODS:
            raise ValueError(f"detected_by must be one of {DETECT_METHODS}")
        return v.lower()


class AlertNote(BaseModel):
    ts: Optional[datetime]
    text: str


class AlertNoteRequest(BaseModel):
    """Body for POST /alerts/{id}/notes."""
    text: str = Field(..., min_length=1, max_length=1000)


class AlertResponse(BaseModel):
    """Full alert record returned to clients."""
    id: str
    alert_id: str
    attack_type: str
    severity: str
    confidence: float
    detected_by: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    description: str
    status: str
    detected_at: datetime
    acknowledged_at: Optional[datetime]
    dup_count: int
    sig_confidence: Optional[float]
    rf_confidence: Optional[float]
    lstm_confidence: Optional[float]
    if_confidence: Optional[float]
    flow_id: Optional[str]
    notes: List[AlertNote] = Field(default_factory=list)
    group_id: Optional[str]

    model_config = {"from_attributes": True}


class AlertListResponse(BaseModel):
    """Paginated alert list."""
    total: int
    page: int
    page_size: int
    alerts: List[AlertResponse]


class AlertAcknowledge(BaseModel):
    """Body for PATCH /alerts/{id}/acknowledge."""
    note: Optional[str] = Field(None, max_length=1000)


class AlertFilter(BaseModel):
    """Query parameters for GET /alerts."""
    severity: Optional[str] = None
    status: Optional[str] = None
    src_ip: Optional[str] = None
    attack_type: Optional[str] = None
    from_dt: Optional[datetime] = None
    to_dt: Optional[datetime] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=200)


# ─────────────────────────────────────────────
# Detection rule schemas
# ─────────────────────────────────────────────

class RuleResponse(BaseModel):
    """Detection rule record returned to clients."""
    id: str
    rule_id: str
    rule_name: str
    rule_content: str
    attack_category: str
    severity: str
    is_enabled: bool
    version: int
    created_at: datetime
    updated_at: datetime
    hits: int = 0

    model_config = {"from_attributes": True}


class RuleListResponse(BaseModel):
    total: int
    rules: List[RuleResponse]


class RuleCreate(BaseModel):
    """Body for POST /rules."""
    rule_id: str = Field(..., max_length=64, description="Unique SID e.g. SID:2001")
    rule_name: str = Field(..., max_length=255)
    rule_content: str = Field(..., description="Full Snort-compatible rule string")
    attack_category: str = Field(..., max_length=64)
    severity: str = Field(default="MEDIUM")
    is_enabled: bool = Field(default=True)


class RuleUpdate(BaseModel):
    """Body for PUT /rules/{id} — all fields optional."""
    rule_name: Optional[str] = None
    rule_content: Optional[str] = None
    attack_category: Optional[str] = None
    severity: Optional[str] = None
    is_enabled: Optional[bool] = None


class RuleToggle(BaseModel):
    """Body for PATCH /rules/{id}/toggle."""
    enabled: bool = Field(..., description="Whether to enable or disable the rule")


# ─────────────────────────────────────────────
# Generic responses
# ─────────────────────────────────────────────

class MessageResponse(BaseModel):
    message: str


class ErrorResponse(BaseModel):
    detail: str


# --- ML Model schema ---
from pydantic import ConfigDict

class MLModelRead(BaseModel):
    id: int
    name: str
    version: str
    algorithm: str
    is_active: bool
    accuracy: Optional[float] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class AlertRead(BaseModel):
    id: Union[int, str] = 0
    flow_id: str = ""
    severity: str = "LOW"
    attack_class: str = "BENIGN"
    confidence: float = 0.0
    is_false_positive: bool = False
    created_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)


class SeverityLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectionEvent(BaseModel):
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    attack_class: str = 'BENIGN'
    attack_type: str = 'BENIGN'
    detection_method: str = 'ensemble'
    ensemble_score: float = 0.0
    sig_confidence: float = 0.0
    rf_confidence: float = 0.0
    lstm_confidence: float = 0.0
    if_confidence: float = 0.0
    matched_rule_id: str = ''
    description: str = ''
    severity: SeverityLevel = SeverityLevel.LOW
    confidence: float = 0.0
    timestamp: Optional[datetime] = None
