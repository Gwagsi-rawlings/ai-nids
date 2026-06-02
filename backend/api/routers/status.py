"""
AI-NIDS — System Status Router + WebSocket Alert Stream
app/routers/status.py

Endpoints:
    GET  /status            — per-pipeline-stage operational state (FR17.1)
    GET  /models            — ML model registry from DB (FR5.9)
    WS   /ws/alerts         — real-time alert stream for dashboard (FR10.5)

FR Traceability:
    FR17.1 — System health dashboard
    FR5.4  — ML models loaded at startup
    FR5.9  — Model versioning and active model tracking
    FR10.5 — Real-time dashboard updates via WebSocket
    NFR16.3 — Health check endpoints
April 5, 2026 | Sprint 1, Week 4
"""

import asyncio
import json
import logging
import os
import time
from typing import List

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from infrastructure.db.database import get_db
from infrastructure.db.redis_client import get_redis
from infrastructure.db.models import MLModel
from backend.api.schemas import MLModelRead

router = APIRouter(tags=["System"])
logger = logging.getLogger("ai-nids.router.status")

# ── Pipeline stage state (updated by detection workers at runtime) ─────────
_pipeline_state: dict = {
    "packet_capture": "ready",
    "flow_aggregator": "ready",
    "feature_extractor": "ready",
    "signature_engine": "unknown",
    "ml_inference": "unknown",
    "ensemble_correlator": "unknown",
    "alert_generator": "unknown",
}

_startup_time: float = time.time()


def update_pipeline_stage(stage: str, state: str) -> None:
    """Called by pipeline workers to update their reported health state."""
    _pipeline_state[stage] = state


# ── GET /status ────────────────────────────────────────────────────────────

@router.get("/status", summary="Detailed pipeline operational status (FR17.1)")
async def system_status():
    """
    Returns per-stage pipeline health, loaded rule count, and model registry.
    Consumed by the System Administration dashboard view (FR17.1).
    """
    uptime = round(time.time() - _startup_time, 1)

    # Count loaded rules from rules/ directory
    rules_dir = os.getenv("RULES_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "rules"))
    rule_count = 0
    if os.path.isdir(rules_dir):
        for f in os.listdir(rules_dir):
            if f.endswith(".rules"):
                try:
                    with open(os.path.join(rules_dir, f)) as fh:
                        rule_count += sum(
                            1 for line in fh
                            if line.strip() and not line.startswith("#") and "sid:" in line
                        )
                except OSError:
                    pass

    # Count model files
    models_dir = os.getenv("MODEL_DIR", "/app/models")
    model_files = []
    if os.path.isdir(models_dir):
        model_files = [f for f in os.listdir(models_dir) if f.endswith((".pkl", ".h5", ".pt"))]

    return {
        "status": "operational",
        "uptime_seconds": uptime,
        "pipeline_stages": _pipeline_state,
        "detection_engines": {
            "signature": {
                "status": "active" if rule_count > 0 else "no_rules",
                "rules_loaded": rule_count,
            },
            "random_forest": {
                "status": "active" if any("random_forest" in f for f in model_files) else "not_trained",
            },
            "isolation_forest": {
                "status": "active" if any("isolation_forest" in f for f in model_files) else "not_trained",
            },
            "lstm": {
                "status": "active" if any("lstm" in f for f in model_files) else "not_trained",
            },
        },
        "ensemble": {
            "weights": {
                "signature": 0.40,
                "random_forest": 0.35,
                "lstm": 0.15,
                "isolation_forest": 0.10,
            },
            "alert_threshold": 0.50,
        },
    }


# ── GET /models ────────────────────────────────────────────────────────────

@router.get("/models", response_model=List[MLModelRead], summary="ML model registry (FR5.9)")
async def list_models(db: AsyncSession = Depends(get_db)):
    """
    Return all versioned ML model records from the database (FR5.9).
    The active model per type has is_active=True.
    """
    result = await db.execute(
        select(MLModel).order_by(MLModel.model_type, MLModel.trained_at.desc())
    )
    models = result.scalars().all()
    return [MLModelRead.model_validate(m) for m in models]


# ── WebSocket /ws/alerts ───────────────────────────────────────────────────

class AlertConnectionManager:
    """
    Manages active WebSocket connections for the real-time alert stream.
    Subscribes to Redis Pub/Sub channel and fans events to all connected clients.
    FR10.5 — Real-time dashboard updates.
    """

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.active_connections.append(ws)
        logger.info("WebSocket client connected. Total: %d", len(self.active_connections))

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self.active_connections:
            self.active_connections.remove(ws)
        logger.info("WebSocket client disconnected. Total: %d", len(self.active_connections))

    async def broadcast(self, message: str) -> None:
        """Send a JSON string to all connected dashboard clients."""
        dead: list[WebSocket] = []
        for ws in self.active_connections:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = AlertConnectionManager()


async def _redis_listener() -> None:
    """
    Background task: subscribe to Redis alert channel and fan-out to WebSocket clients.
    Started once at application startup.
    """
    from infrastructure.db.redis_client import ALERT_PUBSUB_CHANNEL

    redis = await get_redis()
    pubsub = redis.pubsub()
    await pubsub.subscribe(ALERT_PUBSUB_CHANNEL)
    logger.info("Redis Pub/Sub listener started on channel: %s", ALERT_PUBSUB_CHANNEL)

    async for message in pubsub.listen():
        if message["type"] == "message":
            await manager.broadcast(message["data"])


async def start_redis_listener() -> None:
    """Called from FastAPI lifespan to start the background listener task."""
    asyncio.create_task(_redis_listener())


@router.websocket("/ws/alerts")
async def websocket_alerts(ws: WebSocket, token: str = ""):
    """
    Real-time alert stream for the React dashboard (FR10.5).
    Accepts a JWT via the ?token= query parameter.
    """
    import os
    from jose import JWTError
    from backend.api.security import decode_access_token

    secret_key = os.getenv("SECRET_KEY", "")
    if secret_key and token:
        try:
            decode_access_token(token, secret_key)
        except JWTError:
            await ws.close(code=4001)
            return
    elif secret_key and not token:
        await ws.close(code=4001)
        return

    await manager.connect(ws)
    try:
        while True:
            await asyncio.sleep(30)
            await ws.send_text(json.dumps({"type": "ping"}))
    except WebSocketDisconnect:
        manager.disconnect(ws)
    except Exception as e:
        logger.warning("WebSocket error: %s", e)
        manager.disconnect(ws)