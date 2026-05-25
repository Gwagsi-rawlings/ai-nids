from typing import Dict, List

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from infrastructure.db.database import get_db
from infrastructure.db.models import Alert
from app.services.alert_service import get_live_stats as get_live_stats_service

router = APIRouter(prefix="/capture", tags=["Capture"])


class TopSourceIP(BaseModel):
    ip: str
    pps: float


class TrafficStats(BaseModel):
    packets_per_sec: float
    bytes_per_sec: float
    protocol_distribution: Dict[str, int]
    top_source_ips: List[TopSourceIP]


@router.get("/stats", response_model=TrafficStats, summary="Live packet capture traffic statistics")
async def capture_stats(db: AsyncSession = Depends(get_db)):
    """Return current packet capture traffic statistics for the dashboard."""
    live_stats = await get_live_stats_service()
    packets_per_sec = float(live_stats.get("packets_per_second", 0)) if live_stats else 0.0
    bytes_per_sec = float(live_stats.get("bytes_per_second", 0)) if live_stats else 0.0

    protocol_distribution: Dict[str, int] = {}
    result = await db.execute(
        select(Alert.protocol, func.count()).group_by(Alert.protocol)
    )
    for protocol, count in result.all():
        protocol_distribution[protocol or "Other"] = count

    top_source_ips = []
    result = await db.execute(
        select(Alert.src_ip, func.count())
        .group_by(Alert.src_ip)
        .order_by(func.count().desc())
        .limit(5)
    )
    for src_ip, count in result.all():
        top_source_ips.append({"ip": src_ip, "pps": float(count)})

    return {
        "packets_per_sec": packets_per_sec,
        "bytes_per_sec": bytes_per_sec,
        "protocol_distribution": protocol_distribution,
        "top_source_ips": top_source_ips,
    }
