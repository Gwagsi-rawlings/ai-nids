import asyncio
import logging
import os
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from infrastructure.db.database import get_db
from infrastructure.db.models import Alert
from app.services.alert_service import get_live_stats as get_live_stats_service

logger = logging.getLogger("ai-nids.capture")
router = APIRouter(prefix="/capture", tags=["Capture"])


# ── In-memory state ────────────────────────────────────────────────────────

_live_state = {
    "running": False,
    "interface": "eth0",
    "started_at": None,
}

_pcap_jobs: Dict[str, dict] = {}


# ── Schemas ────────────────────────────────────────────────────────────────

class TopSourceIP(BaseModel):
    ip: str
    pps: float


class TrafficStats(BaseModel):
    packets_per_sec: float
    bytes_per_sec: float
    protocol_distribution: Dict[str, int]
    top_source_ips: List[TopSourceIP]


class CaptureStartRequest(BaseModel):
    interface: str = "eth0"


class LiveCaptureStatus(BaseModel):
    running: bool
    interface: str
    started_at: Optional[str]


class PcapJob(BaseModel):
    id: str
    filename: str
    status: str
    flow_count: Optional[int]
    alert_count: Optional[int]
    file_size_bytes: int
    submitted_at: str
    completed_at: Optional[str]
    error_message: Optional[str]


# ── GET /capture/stats ─────────────────────────────────────────────────────

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


# ── POST /capture/start ────────────────────────────────────────────────────

@router.post("/start", response_model=LiveCaptureStatus, summary="Start live packet capture")
async def start_capture(body: CaptureStartRequest):
    if _live_state["running"]:
        raise HTTPException(status_code=409, detail="Capture already running")

    _live_state["running"] = True
    _live_state["interface"] = body.interface
    _live_state["started_at"] = datetime.now(timezone.utc).isoformat()

    # Attempt to kick off the live pipeline if available
    try:
        from backend.detection.ml.model_loader import load_models
        from backend.detection.ml.signature_engine_runtime import SignatureEngine
        from backend.detection.ml.pipeline_runner import start_live_pipeline

        model_bundle = load_models()
        sig_engine = SignatureEngine()
        asyncio.create_task(
            start_live_pipeline(body.interface, sig_engine, model_bundle),
            name="live-pipeline-api",
        )
        logger.info("Live capture pipeline started on interface: %s", body.interface)
    except Exception as e:
        logger.warning(
            "Live pipeline not available (WSL2 / missing deps): %s. "
            "State updated but capture is simulated.",
            e,
        )

    return LiveCaptureStatus(
        running=True,
        interface=_live_state["interface"],
        started_at=_live_state["started_at"],
    )


# ── POST /capture/stop ─────────────────────────────────────────────────────

@router.post("/stop", response_model=LiveCaptureStatus, summary="Stop live packet capture")
async def stop_capture():
    _live_state["running"] = False
    _live_state["started_at"] = None
    logger.info("Live capture stopped")
    return LiveCaptureStatus(
        running=False,
        interface=_live_state["interface"],
        started_at=None,
    )


# ── GET /capture/jobs ──────────────────────────────────────────────────────

@router.get("/jobs", response_model=List[PcapJob], summary="List PCAP analysis jobs")
async def list_jobs():
    """Return all submitted PCAP upload jobs, newest first."""
    return sorted(_pcap_jobs.values(), key=lambda j: j["submitted_at"], reverse=True)


# ── POST /capture/pcap/upload ──────────────────────────────────────────────

@router.post("/pcap/upload", response_model=PcapJob, summary="Upload a PCAP file for offline analysis")
async def upload_pcap(file: UploadFile = File(...)):
    if not (file.filename or "").lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=400, detail="Only .pcap and .pcapng files are supported")

    contents = await file.read()
    file_size = len(contents)

    job_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    job: dict = {
        "id": job_id,
        "filename": file.filename,
        "status": "queued",
        "flow_count": None,
        "alert_count": None,
        "file_size_bytes": file_size,
        "submitted_at": now_iso,
        "completed_at": None,
        "error_message": None,
    }
    _pcap_jobs[job_id] = job

    # Save to temp file and kick off background analysis
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    tmp.write(contents)
    tmp.close()

    asyncio.create_task(_run_pcap_job(job_id, tmp.name), name=f"pcap-job-{job_id[:8]}")
    logger.info("PCAP job queued: id=%s filename=%s size=%d", job_id, file.filename, file_size)

    return PcapJob(**job)


# ── Background PCAP processor ──────────────────────────────────────────────

async def _run_pcap_job(job_id: str, pcap_path: str) -> None:
    job = _pcap_jobs.get(job_id)
    if not job:
        return

    job["status"] = "running"
    logger.info("PCAP job started: id=%s path=%s", job_id, pcap_path)

    try:
        from backend.detection.ml.model_loader import load_models
        from backend.detection.ml.signature_engine_runtime import SignatureEngine
        from backend.detection.ml.pipeline_runner import start_pipeline

        model_bundle = load_models()
        sig_engine = SignatureEngine()
        await start_pipeline(pcap_path, sig_engine, model_bundle)

        job["status"] = "complete"
        job["completed_at"] = datetime.now(timezone.utc).isoformat()
        logger.info("PCAP job complete: id=%s", job_id)
    except Exception as e:
        job["status"] = "failed"
        job["error_message"] = str(e)
        job["completed_at"] = datetime.now(timezone.utc).isoformat()
        logger.warning("PCAP job failed: id=%s error=%s", job_id, e)
    finally:
        try:
            os.unlink(pcap_path)
        except OSError:
            pass
