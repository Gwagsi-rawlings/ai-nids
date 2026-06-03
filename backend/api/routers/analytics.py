"""
AI-NIDS — Analytics Router
backend/api/routers/analytics.py

Endpoints:
    GET /analytics/summary?range=24h|7d|30d  — Aggregated threat statistics

FR Traceability:
    FR12.1  — Security summary reports
    FR9.1   — Alert trend analysis
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import cast, func, select, case, text
from sqlalchemy.ext.asyncio import AsyncSession

from infrastructure.db.database import get_db
from infrastructure.db.models import Alert

router = APIRouter(prefix="/analytics", tags=["Analytics"])


class TopSrcIP(BaseModel):
    ip: str
    count: int
    last_seen: str
    country: Optional[str] = None


class BySeverity(BaseModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0


class AnalyticsSummary(BaseModel):
    total_alerts: int
    by_severity: BySeverity
    by_attack_type: dict
    top_src_ips: List[TopSrcIP]
    false_positive_rate: float
    avg_confidence: float
    alerts_per_hour: List[int]


def _range_to_window(range_str: str) -> datetime:
    now = datetime.now(timezone.utc)
    if range_str == "24h":
        return now - timedelta(hours=24)
    if range_str == "30d":
        return now - timedelta(days=30)
    return now - timedelta(days=7)  # default 7d


@router.get("/summary", response_model=AnalyticsSummary, summary="Aggregated alert analytics")
async def analytics_summary(
    range: str = Query("7d", pattern="^(24h|7d|30d)$"),
    db: AsyncSession = Depends(get_db),
):
    since = _range_to_window(range)

    base = select(Alert).where(Alert.detected_at >= since)

    # Total count
    total_result = await db.execute(
        select(func.count(Alert.id)).where(Alert.detected_at >= since)
    )
    total = total_result.scalar_one() or 0

    # By severity
    sev_result = await db.execute(
        select(Alert.severity, func.count(Alert.id))
        .where(Alert.detected_at >= since)
        .group_by(Alert.severity)
    )
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for sev, cnt in sev_result.all():
        if sev in by_severity:
            by_severity[sev] = cnt

    # By attack type
    attack_result = await db.execute(
        select(Alert.attack_type, func.count(Alert.id))
        .where(Alert.detected_at >= since)
        .group_by(Alert.attack_type)
        .order_by(func.count(Alert.id).desc())
        .limit(10)
    )
    by_attack_type = {row[0]: row[1] for row in attack_result.all()}

    # Top source IPs
    ip_result = await db.execute(
        select(Alert.src_ip, func.count(Alert.id), func.max(Alert.detected_at))
        .where(Alert.detected_at >= since)
        .group_by(Alert.src_ip)
        .order_by(func.count(Alert.id).desc())
        .limit(10)
    )
    top_src_ips = [
        TopSrcIP(ip=str(ip), count=cnt, last_seen=last.isoformat() if last else since.isoformat())
        for ip, cnt, last in ip_result.all()
        if ip
    ]

    # False positive rate
    fp_result = await db.execute(
        text("""
            SELECT COUNT(*) FROM alerts
            WHERE detected_at >= :since
            AND status = 'false_positive'::alert_status
        """),
        {"since": since},
    )
    fp_count = fp_result.scalar() or 0
    false_positive_rate = (fp_count / total) if total > 0 else 0.0

    # Avg confidence
    conf_result = await db.execute(
        select(func.avg(Alert.confidence)).where(Alert.detected_at >= since)
    )
    avg_confidence = float(conf_result.scalar_one() or 0.0)

    # Alerts per hour (last 24 buckets)
    now = datetime.now(timezone.utc)
    hour_counts = [0] * 24
    hourly_result = await db.execute(
        select(Alert.detected_at)
        .where(Alert.detected_at >= now - timedelta(hours=24))
    )
    for (ts,) in hourly_result.all():
        if ts:
            hour_ago = int((now - ts.replace(tzinfo=timezone.utc)).total_seconds() // 3600)
            if 0 <= hour_ago < 24:
                hour_counts[23 - hour_ago] += 1

    return AnalyticsSummary(
        total_alerts=total,
        by_severity=BySeverity(**by_severity),
        by_attack_type=by_attack_type,
        top_src_ips=top_src_ips,
        false_positive_rate=false_positive_rate,
        avg_confidence=avg_confidence,
        alerts_per_hour=hour_counts,
    )
