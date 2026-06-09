"""
AI-NIDS — Report Builder
backend/api/reporting/report_builder.py

Queries PostgreSQL to aggregate all data required for report generation.
Covers FR12.1–FR12.10 (Security Reporting) and FR13.1–FR13.5 (Compliance).

FR Traceability:
    FR12.1  — Security summary reports
    FR12.2  — Total alerts by severity
    FR12.3  — Top attack types
    FR12.4  — Top source IPs
    FR12.5  — Traffic statistics
    FR12.6  — Date range selection
    FR13.4  — Full audit trail (compliance)
    FR13.5  — Configurable retention

April 26, 2026 | Sprint 2, Week 7 | Developer: GWAGSI Rawlings Nshom
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("ai-nids.reporting")


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class SeverityBreakdown:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low

    def to_dict(self) -> dict:
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "total": self.total,
        }


@dataclass
class AttackCategory:
    name: str
    count: int
    percentage: float


@dataclass
class TopSourceIP:
    ip: str
    count: int
    top_attack: str
    first_seen: datetime
    last_seen: datetime


@dataclass
class DailyAlertPoint:
    date: str          # ISO date string YYYY-MM-DD
    critical: int
    high: int
    medium: int
    low: int


@dataclass
class DetectionEngineStats:
    signature_triggered: int = 0
    ml_triggered: int = 0
    both_triggered: int = 0
    false_positive_count: int = 0

    @property
    def false_positive_rate(self) -> float:
        total = self.signature_triggered + self.ml_triggered + self.both_triggered
        return round(self.false_positive_count / total, 4) if total > 0 else 0.0


@dataclass
class ComplianceStats:
    total_events_logged: int = 0
    audit_entries: int = 0
    acknowledged_alerts: int = 0
    unacknowledged_alerts: int = 0
    mean_acknowledgement_minutes: float = 0.0
    data_retained_days: int = 90


@dataclass
class ReportData:
    # Metadata
    report_type: str                          # security | compliance | analytics
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None
    generated_by: str = "system"

    # Core metrics
    severity: SeverityBreakdown = field(default_factory=SeverityBreakdown)
    top_attack_types: list[AttackCategory] = field(default_factory=list)
    top_source_ips: list[TopSourceIP] = field(default_factory=list)
    daily_timeline: list[DailyAlertPoint] = field(default_factory=list)

    # Detection engine breakdown
    engine_stats: DetectionEngineStats = field(default_factory=DetectionEngineStats)

    # Compliance data (populated for compliance reports)
    compliance: Optional[ComplianceStats] = None

    # Analytics extras
    average_confidence_score: float = 0.0
    peak_alert_hour: Optional[int] = None       # 0-23
    resolution_rate: float = 0.0               # fraction of alerts resolved


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

class ReportBuilder:
    """
    Builds a ReportData object by querying the AI-NIDS PostgreSQL schema.
    All queries are parameterised — no raw string interpolation.
    """

    def __init__(self, session: AsyncSession):
        self._db = session

    async def build(
        self,
        report_type: str,
        start: datetime,
        end: datetime,
        generated_by: str = "system",
        top_n: int = 10,
    ) -> ReportData:
        """
        Main entry point.  Runs all sub-queries and returns a populated ReportData.

        Args:
            report_type: "security" | "compliance" | "analytics"
            start:       Period start (UTC)
            end:         Period end   (UTC)
            generated_by: Username or "system" for scheduled runs
            top_n:       How many top IPs / attack types to include
        """
        data = ReportData(
            report_type=report_type,
            period_start=start,
            period_end=end,
            generated_by=generated_by,
        )

        params = {"start": start, "end": end}

        data.severity         = await self._severity_breakdown(params)
        data.top_attack_types = await self._top_attack_types(params, top_n)
        data.top_source_ips   = await self._top_source_ips(params, top_n)
        data.daily_timeline   = await self._daily_timeline(params)
        data.engine_stats     = await self._engine_stats(params)
        data.average_confidence_score = await self._avg_confidence(params)
        data.peak_alert_hour  = await self._peak_hour(params)
        data.resolution_rate  = await self._resolution_rate(params)

        if report_type == "compliance":
            data.compliance = await self._compliance_stats(params)

        logger.info(
            "ReportData built: type=%s period=%s→%s total_alerts=%d",
            report_type, start.date(), end.date(), data.severity.total,
        )
        return data

    # ------------------------------------------------------------------
    # Sub-queries
    # ------------------------------------------------------------------

    async def _severity_breakdown(self, params: dict) -> SeverityBreakdown:
        sql = text("""
            SELECT
                COUNT(*) FILTER (WHERE severity = 'CRITICAL') AS critical,
                COUNT(*) FILTER (WHERE severity = 'HIGH')     AS high,
                COUNT(*) FILTER (WHERE severity = 'MEDIUM')   AS medium,
                COUNT(*) FILTER (WHERE severity = 'LOW')      AS low
            FROM alerts
            WHERE detected_at BETWEEN :start AND :end
        """)
        row = (await self._db.execute(sql, params)).one()
        return SeverityBreakdown(
            critical=row.critical or 0,
            high=row.high or 0,
            medium=row.medium or 0,
            low=row.low or 0,
        )

    async def _top_attack_types(self, params: dict, top_n: int) -> list[AttackCategory]:
        sql = text("""
            SELECT attack_type, COUNT(*) AS cnt
            FROM alerts
            WHERE detected_at BETWEEN :start AND :end
            GROUP BY attack_type
            ORDER BY cnt DESC
            LIMIT :top_n
        """)
        rows = (await self._db.execute(sql, {**params, "top_n": top_n})).all()
        total = sum(r.cnt for r in rows) or 1
        return [
            AttackCategory(
                name=r.attack_type,
                count=r.cnt,
                percentage=round(r.cnt / total * 100, 1),
            )
            for r in rows
        ]

    async def _top_source_ips(self, params: dict, top_n: int) -> list[TopSourceIP]:
        sql = text("""
            SELECT
                src_ip::text                AS ip,
                COUNT(*)                    AS cnt,
                MODE() WITHIN GROUP (ORDER BY attack_type) AS top_attack,
                MIN(detected_at)            AS first_seen,
                MAX(detected_at)            AS last_seen
            FROM alerts
            WHERE detected_at BETWEEN :start AND :end
            GROUP BY src_ip
            ORDER BY cnt DESC
            LIMIT :top_n
        """)
        rows = (await self._db.execute(sql, {**params, "top_n": top_n})).all()
        return [
            TopSourceIP(
                ip=r.ip,
                count=r.cnt,
                top_attack=r.top_attack or "Unknown",
                first_seen=r.first_seen,
                last_seen=r.last_seen,
            )
            for r in rows
        ]

    async def _daily_timeline(self, params: dict) -> list[DailyAlertPoint]:
        sql = text("""
            SELECT
                DATE(detected_at)                                           AS day,
                COUNT(*) FILTER (WHERE severity = 'CRITICAL')               AS critical,
                COUNT(*) FILTER (WHERE severity = 'HIGH')                   AS high,
                COUNT(*) FILTER (WHERE severity = 'MEDIUM')                 AS medium,
                COUNT(*) FILTER (WHERE severity = 'LOW')                    AS low
            FROM alerts
            WHERE detected_at BETWEEN :start AND :end
            GROUP BY day
            ORDER BY day
        """)
        rows = (await self._db.execute(sql, params)).all()
        return [
            DailyAlertPoint(
                date=str(r.day),
                critical=r.critical or 0,
                high=r.high or 0,
                medium=r.medium or 0,
                low=r.low or 0,
            )
            for r in rows
        ]

    async def _engine_stats(self, params: dict) -> DetectionEngineStats:
        sql = text("""
            SELECT
                COUNT(*) FILTER (WHERE detected_by::text LIKE '%signature%')                                        AS sig,
                COUNT(*) FILTER (WHERE detected_by::text LIKE '%random_forest%' OR detected_by::text LIKE '%lstm%')       AS ml,
                COUNT(*) FILTER (WHERE detected_by::text LIKE '%ensemble%')                                         AS both,
                COUNT(*) FILTER (WHERE status = 'FALSE_POSITIVE')                                             AS fp
            FROM alerts
            WHERE detected_at BETWEEN :start AND :end
        """)
        row = (await self._db.execute(sql, params)).one()
        return DetectionEngineStats(
            signature_triggered=row.sig or 0,
            ml_triggered=row.ml or 0,
            both_triggered=row.both or 0,
            false_positive_count=row.fp or 0,
        )

    async def _avg_confidence(self, params: dict) -> float:
        sql = text("""
            SELECT COALESCE(AVG(confidence), 0) AS avg_conf
            FROM alerts
            WHERE detected_at BETWEEN :start AND :end
        """)
        row = (await self._db.execute(sql, params)).one()
        return round(float(row.avg_conf), 4)

    async def _peak_hour(self, params: dict) -> Optional[int]:
        sql = text("""
            SELECT EXTRACT(HOUR FROM detected_at)::int AS hr, COUNT(*) AS cnt
            FROM alerts
            WHERE detected_at BETWEEN :start AND :end
            GROUP BY hr
            ORDER BY cnt DESC
            LIMIT 1
        """)
        row = (await self._db.execute(sql, params)).one_or_none()
        return row.hr if row else None

    async def _resolution_rate(self, params: dict) -> float:
        sql = text("""
            SELECT
                COUNT(*) FILTER (WHERE status IN ('ACKNOWLEDGED', 'FALSE_POSITIVE')) AS resolved,
                COUNT(*)                                                               AS total
            FROM alerts
            WHERE detected_at BETWEEN :start AND :end
        """)
        row = (await self._db.execute(sql, params)).one()
        total = row.total or 1
        return round(row.resolved / total, 4)

    async def _compliance_stats(self, params: dict) -> ComplianceStats:
        # Audit log entries in period
        audit_sql = text("""
            SELECT COUNT(*) AS cnt FROM audit_log
            WHERE created_at BETWEEN :start AND :end
        """)
        audit_row = (await self._db.execute(audit_sql, params)).one()

        # Acknowledgement stats
        ack_sql = text("""
            SELECT
                COUNT(*) FILTER (WHERE status = 'ACKNOWLEDGED')  AS acked,
                COUNT(*) FILTER (WHERE status = 'NEW')           AS unacked,
                AVG(EXTRACT(EPOCH FROM (acknowledged_at - detected_at)) / 60)
                    FILTER (WHERE acknowledged_at IS NOT NULL)   AS mean_ack_mins
            FROM alerts
            WHERE detected_at BETWEEN :start AND :end
        """)
        ack_row = (await self._db.execute(ack_sql, params)).one()

        return ComplianceStats(
            total_events_logged=ack_row.acked + ack_row.unacked if (ack_row.acked and ack_row.unacked) else 0,
            audit_entries=audit_row.cnt or 0,
            acknowledged_alerts=ack_row.acked or 0,
            unacknowledged_alerts=ack_row.unacked or 0,
            mean_acknowledgement_minutes=round(float(ack_row.mean_ack_mins or 0), 1),
        )