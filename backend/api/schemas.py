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
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


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
    severity: str = Field(..., description="CRITICAL | HIGH | MEDIUM | LOW")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Ensemble confidence [0,1]")
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


# ─────────────────────────────────────────────
# Generic responses
# ─────────────────────────────────────────────

class MessageResponse(BaseModel):
    message: str


class ErrorResponse(BaseModel):
    detail: str
# --- ML Model schema ---
from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class MLModelRead(BaseModel):
    id: int
    name: str
    version: str
    algorithm: str
    is_active: bool
    accuracy: Optional[float] = None
    created_at: datetime

    class Config:
        from_attributes = True

class AlertRead(BaseModel):
    id: int
    flow_id: str
    severity: str
    attack_class: str
    confidence: float
    is_false_positive: bool = False
    created_at: datetime

    class Config:
        from_attributes = True

import enum

class SeverityLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class DetectionEvent(BaseModel):
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    attack_class: str
    severity: SeverityLevel
    confidence: float
    timestamp: datetime

class AlertCreate(BaseModel):
    flow_id: str
    attack_class: str
    severity: SeverityLevel
    confidence: float
    src_ip: str
    dst_ip: str
