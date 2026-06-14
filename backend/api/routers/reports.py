"""
AI-NIDS — Reporting Router
backend/api/routers/reports.py

FastAPI endpoints for report generation, viewing, and download.

Endpoints:
    POST /api/v1/reports/generate          — Generate a new report
    GET  /api/v1/reports/{report_id}       — Get report metadata
    GET  /api/v1/reports/{report_id}/html  — View report as HTML
    GET  /api/v1/reports/{report_id}/pdf   — Download report as PDF
    GET  /api/v1/reports/{report_id}/csv   — Download alert CSV for period
    GET  /api/v1/reports                   — List recent reports

FR Traceability:
    FR12.1  — Generate security summary reports
    FR12.6  — Select report date range
    FR12.7  — Export to PDF
    FR12.8  — Export to CSV
    FR12.9  — Schedule automated reports (separate scheduler task)
    FR13.1  — Compliance reports
    FR14.2  — RBAC: soc_manager role required for report generation

April 26, 2026 | Sprint 2, Week 7 | Developer: GWAGSI Rawlings Nshom
"""

from __future__ import annotations

import csv
import io
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_db, require_role
from backend.api.reporting.report_builder import ReportBuilder
from backend.api.reporting.html_renderer import HTMLRenderer
from backend.api.reporting.pdf_exporter import html_to_pdf
from backend.api.security import TokenData

logger = logging.getLogger("ai-nids.reporting.router")
router = APIRouter(prefix="/reports", tags=["Reports"])

# In-memory report cache: {report_id: {"html": str, "meta": dict}}
# In production this would be stored in PostgreSQL or Redis.
_report_cache: dict[str, dict] = {}

_renderer = HTMLRenderer()


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class ReportRequest(BaseModel):
    report_type: Literal["security", "compliance", "analytics"] = "security"
    # Accept either explicit dates or a convenience range shorthand
    start_date:  Optional[str] = Field(None, description="ISO date YYYY-MM-DD (UTC)")
    end_date:    Optional[str] = Field(None, description="ISO date YYYY-MM-DD (UTC)")
    range:       Optional[Literal["24h", "7d", "30d"]] = Field(None, description="Shorthand range")
    format:      Optional[Literal["pdf", "csv", "json"]] = Field("json", description="Response format")
    top_n:       int = Field(10, ge=1, le=50, description="Top N IPs / attack types")

    def parse_dates(self) -> tuple[datetime, datetime]:
        end = datetime.now(timezone.utc)
        if self.range:
            delta = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
            start = end - delta[self.range]
            return start, end
        if not self.start_date or not self.end_date:
            start = end - timedelta(days=7)
            return start, end
        start = datetime.fromisoformat(self.start_date).replace(
            hour=0, minute=0, second=0, tzinfo=timezone.utc
        )
        end_parsed = datetime.fromisoformat(self.end_date).replace(
            hour=23, minute=59, second=59, tzinfo=timezone.utc
        )
        if end_parsed <= start:
            raise ValueError("end_date must be after start_date")
        return start, end_parsed


class ReportMeta(BaseModel):
    report_id:   str
    report_type: str
    period_start: str
    period_end:   str
    generated_at: str
    generated_by: str
    total_alerts: int


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/generate",
    summary="Generate a new report (FR12.1, FR13.1)",
)
async def generate_report(
    req: ReportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(require_role("soc_manager", "system_admin", "network_admin")),
):
    """
    Generate a security, compliance, or analytics report.
    When format=pdf, returns the PDF file directly as a download.
    Otherwise returns report metadata JSON.
    """
    try:
        start, end = req.parse_dates()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    builder = ReportBuilder(db)
    try:
        data = await builder.build(
            report_type=req.report_type,
            start=start,
            end=end,
            generated_by=current_user.username,
            top_n=req.top_n,
        )
    except Exception as exc:
        logger.exception("Report build failed: %s", exc)
        raise HTTPException(status_code=500, detail="Report generation failed")

    html = _renderer.render(data)
    report_id = str(uuid.uuid4())

    _report_cache[report_id] = {
        "html":  html,
        "data":  data,
        "meta": {
            "report_id":    report_id,
            "report_type":  data.report_type,
            "period_start": data.period_start.isoformat(),
            "period_end":   data.period_end.isoformat(),
            "generated_at": data.generated_at.isoformat(),
            "generated_by": data.generated_by,
            "total_alerts": data.severity.total,
        },
    }

    logger.info(
        "Report generated: id=%s type=%s alerts=%d user=%s",
        report_id, req.report_type, data.severity.total,
        current_user.username,
    )

    # Return the PDF blob directly when format=pdf
    if req.format == "pdf":
        try:
            pdf_bytes = html_to_pdf(html)
        except RuntimeError as exc:
            raise HTTPException(status_code=501, detail=str(exc))
        except Exception as exc:
            logger.exception("PDF conversion failed: %s", exc)
            raise HTTPException(status_code=500, detail="PDF conversion failed")

        meta = _report_cache[report_id]["meta"]
        filename = (
            f"ai-nids_{meta['report_type']}_"
            f"{meta['period_start'][:10]}_to_{meta['period_end'][:10]}.pdf"
        )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    return ReportMeta(**_report_cache[report_id]["meta"])


@router.get(
    "",
    response_model=list[ReportMeta],
    summary="List recently generated reports",
)
async def list_reports(
    current_user: TokenData = Depends(require_role("soc_manager", "system_admin", "network_admin")),
):
    """Return metadata for all reports in the in-memory cache (most recent first)."""
    items = [ReportMeta(**v["meta"]) for v in _report_cache.values()]
    return sorted(items, key=lambda r: r.generated_at, reverse=True)


@router.get(
    "/{report_id}",
    response_model=ReportMeta,
    summary="Get report metadata",
)
async def get_report_meta(
    report_id: str,
    current_user: TokenData = Depends(require_role("soc_manager", "system_admin", "network_admin")),
):
    entry = _report_cache.get(report_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Report not found")
    return ReportMeta(**entry["meta"])


@router.get(
    "/{report_id}/html",
    response_class=HTMLResponse,
    summary="View report as HTML in browser",
)
async def get_report_html(
    report_id: str,
    current_user: TokenData = Depends(require_role("soc_manager", "system_admin", "network_admin")),
):
    """Stream the HTML report directly to the browser for in-page viewing."""
    entry = _report_cache.get(report_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Report not found")
    return HTMLResponse(content=entry["html"], status_code=200)


@router.get(
    "/{report_id}/pdf",
    summary="Download report as PDF (FR12.7)",
)
async def download_report_pdf(
    report_id: str,
    current_user: TokenData = Depends(require_role("soc_manager", "system_admin", "network_admin")),
):
    """
    Convert the cached HTML report to PDF and stream it as a file download.
    Uses WeasyPrint for high-fidelity HTML→PDF conversion.
    """
    entry = _report_cache.get(report_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Report not found")

    try:
        pdf_bytes = html_to_pdf(entry["html"])
    except RuntimeError as exc:
        raise HTTPException(status_code=501, detail=str(exc))
    except Exception as exc:
        logger.exception("PDF conversion failed: %s", exc)
        raise HTTPException(status_code=500, detail="PDF conversion failed")

    meta = entry["meta"]
    filename = (
        f"ai-nids_{meta['report_type']}_"
        f"{meta['period_start'][:10]}_to_{meta['period_end'][:10]}.pdf"
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get(
    "/{report_id}/csv",
    summary="Download alert data as CSV for the report period (FR12.8)",
)
async def download_report_csv(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(require_role("soc_manager", "system_admin", "network_admin")),
):
    """
    Export raw alert records for the report period as a downloadable CSV file.
    Includes all FR7.3–FR7.7 alert fields.
    """
    entry = _report_cache.get(report_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Report not found")

    data = entry["data"]
    sql = text("""
        SELECT
            alert_id::text,
            detected_at,
            severity,
            attack_type,
            confidence,
            detected_by,
            src_ip::text,
            dst_ip::text,
            src_port,
            dst_port,
            protocol,
            status,
            description,
            rule_id::text
        FROM alerts
        WHERE detected_at BETWEEN :start AND :end
        ORDER BY detected_at DESC
    """)
    rows = (await db.execute(sql, {
        "start": data.period_start,
        "end":   data.period_end,
    })).all()

    # Build CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "alert_id", "detected_at", "severity", "attack_type",
        "confidence", "detected_by", "src_ip", "dst_ip",
        "src_port", "dst_port", "protocol", "status",
        "description", "rule_id",
    ])
    for row in rows:
        writer.writerow([
            row.alert_id, row.detected_at, row.severity, row.attack_type,
            row.confidence, row.detected_by, row.src_ip, row.dst_ip,
            row.src_port, row.dst_port, row.protocol, row.status,
            row.description, row.rule_id,
        ])

    meta = entry["meta"]
    filename = (
        f"ai-nids_alerts_"
        f"{meta['period_start'][:10]}_to_{meta['period_end'][:10]}.csv"
    )
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Scheduled report helper (called by APScheduler in main.py — FR12.9)
# ---------------------------------------------------------------------------

async def generate_scheduled_report(
    db: AsyncSession,
    report_type: str = "security",
    days_back: int = 7,
) -> str:
    """
    Build and cache a report for the last N days.
    Returns the report_id. Called from the scheduler, not directly from HTTP.
    """
    end   = datetime.now(timezone.utc)
    start = end - timedelta(days=days_back)

    builder = ReportBuilder(db)
    data    = await builder.build(
        report_type=report_type,
        start=start,
        end=end,
        generated_by="scheduler",
    )
    html      = _renderer.render(data)
    report_id = str(uuid.uuid4())

    _report_cache[report_id] = {
        "html": html,
        "data": data,
        "meta": {
            "report_id":    report_id,
            "report_type":  data.report_type,
            "period_start": data.period_start.isoformat(),
            "period_end":   data.period_end.isoformat(),
            "generated_at": data.generated_at.isoformat(),
            "generated_by": "scheduler",
            "total_alerts": data.severity.total,
        },
    }
    logger.info("Scheduled report cached: id=%s type=%s", report_id, report_type)
    return report_id
