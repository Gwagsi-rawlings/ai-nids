"""
AI-NIDS — FastAPI Application Entry Point (Updated)
app/main.py
 
Startup sequence:
  1. Connect PostgreSQL
  2. Connect Redis
  3. Load signature rule set
  4. Load ML models (RF, IF, LSTM)
  5. Start Redis Pub/Sub listener for WebSocket fan-out
  6. Register routers: /alerts, /rules, /status, /models, /ws/alerts
 
Data flow wiring:
    Detection Pipeline Worker
         ↓ (feature_q)
    Ensemble Correlator (ml/ensemble_correlator.py)
         ↓ DetectionEvent
    alert_service.process_detection_event()
         ↓ PostgreSQL INSERT
         ↓ Redis CACHE (TTL 300s)
         ↓ Redis PUBLISH → WebSocket fan-out to dashboard
 
FR Traceability:
    FR7.8  — PostgreSQL persistence
    FR5.4  — Models loaded at startup
    FR10.5 — Real-time WebSocket push
    NFR3   — Auto-restart, health check
    NFR16.3 — /health endpoint
April 6, 2026 | Sprint 1, Week 4
"""

import logging
import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("ai-nids")
 
_startup_time = time.time()

class AppState:
    db_connected: bool = False
    redis_connected: bool = False
    rules_loaded: int = 0
    models_loaded: list = []
    ws_clients: list = []

state = AppState()
 
 
# ── Lifespan ───────────────────────────────────────────────────────────────
 
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("AI-NIDS starting up...")
 
    # 1. PostgreSQL
    try:
        db_url = os.getenv("DATABASE_URL", "")
        if db_url:
            import asyncpg
            conn = await asyncpg.connect(
                db_url.replace("postgresql+asyncpg://", "postgresql://")
            )
            await conn.close()
            state.db_connected = True
            logger.info("PostgreSQL: connected")
        else:
            logger.warning("DATABASE_URL not set")
    except Exception as e:
        logger.warning("PostgreSQL connection failed: %s (non-fatal in dev)", e)

    # 2. Redis
    try:
        from infrastructure.db.redis_client import init_redis
        await init_redis()
        state.redis_connected = True
    except Exception as e:
        logger.warning("Redis connection failed: %s (non-fatal in dev)", e)

    # 3. Signature rules
    try:
        rules_dir = os.path.join(os.path.dirname(__file__), "..", "rules")
        if os.path.isdir(rules_dir):
            from backend.capture.rule_parser import RuleParser
            parser = RuleParser()
            records = parser.parse_directory(rules_dir)
            logger.info("Signature rules: %d rules loaded", len(records))
        else:
            logger.warning("Rules directory not found at %s", rules_dir)
    except Exception as e:
        logger.warning("Rule loading failed: %s", e)
 
    # 4. ML models
    models_dir = os.getenv("MODEL_DIR", "/app/models")
    if os.path.isdir(models_dir):
        model_files = [f for f in os.listdir(models_dir) if f.endswith((".pkl", ".h5", ".pt"))]
        logger.info("ML model files found: %s", model_files or "none — train Week 3")
    else:
        logger.info("MODEL_DIR not found — models train Week 3/6")
 
    # 5. Start Redis → WebSocket listener
    try:
        from backend.api.routers.status import start_redis_listener
        await start_redis_listener()
        logger.info("Redis Pub/Sub → WebSocket listener started")
    except Exception as e:
        logger.warning("WebSocket listener failed to start: %s", e)
 
    # 6. Load ML models and boot detection pipeline
    # ── This is where the full data flow wiring starts ──────────────────
    capture_mode = os.getenv("CAPTURE_MODE", "pcap").lower()
    pcap_path = os.getenv("PCAP_PATH", "")
 
    try:
        from backend.detection.ml.model_loader import load_models
        from backend.detection.ml.signature_engine_runtime import SignatureEngine
 
        model_bundle = load_models()
        sig_engine = SignatureEngine()
 
        from backend.api.routers.status import update_pipeline_stage
        update_pipeline_stage("signature_engine",
                               f"active ({sig_engine._rules.__len__()} rules)" if sig_engine._rules else "no_rules")
        update_pipeline_stage("ml_inference",
                               "active" if model_bundle.is_ml_ready else "not_trained")
        update_pipeline_stage("ensemble_correlator",
                               "active" if (sig_engine._rules or model_bundle.is_ml_ready) else "standby")
        update_pipeline_stage("alert_generator", "active")
 
        if capture_mode == "pcap" and pcap_path and os.path.exists(pcap_path):
            # PCAP replay — run as background task alongside the API
            from backend.detection.ml.pipeline_runner import start_pipeline
            asyncio.create_task(
                start_pipeline(pcap_path, sig_engine, model_bundle),
                name="pcap-pipeline",
            )
            logger.info("PCAP pipeline task started: %s", pcap_path)
 
        elif capture_mode == "live":
            interface = os.getenv("CAPTURE_INTERFACE", "eth0")
            from backend.detection.ml.pipeline_runner import start_live_pipeline
            asyncio.create_task(
                start_live_pipeline(interface, sig_engine, model_bundle),
                name="live-pipeline",
            )
            logger.info("Live capture pipeline task started on interface: %s", interface)
 
        else:
            logger.info(
                "Pipeline standby: CAPTURE_MODE=%s, PCAP_PATH='%s'. "
                "Set PCAP_PATH or CAPTURE_MODE=live to start detection.",
                capture_mode, pcap_path,
            )
 
    except Exception as e:
        logger.warning("Pipeline boot failed: %s — API will still serve endpoints", e)
 
    logger.info("AI-NIDS startup complete (%.2f s)", time.time() - _startup_time)
    yield
 
    # Shutdown
    logger.info("AI-NIDS shutting down...")
    try:
        from infrastructure.db.redis_client import close_redis
        await close_redis()
    except Exception:
        pass
 
 
# ── App ────────────────────────────────────────────────────────────────────
 
app = FastAPI(
    title="AI-NIDS",
    description=(
        "AI-Powered Network Intrusion Detection System — "
        "Hybrid signature + ML ensemble detection pipeline. "
        "Final Year Project | ICT University, Cameroon | 2024-2025"
    ),
    version="0.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)
 
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",   # React dev server (your current origin)
        "http://localhost:5173",   # Vite default
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
 
# ── Routers ────────────────────────────────────────────────────────────────
 
from backend.api.routers.alerts import router as alerts_router  # noqa: E402
from backend.api.routers.rules import router as rules_router    # noqa: E402
from backend.api.routers.status import router as status_router  # noqa: E402
from backend.api.routers.capture import router as capture_router  # noqa: E402
 
app.include_router(alerts_router, prefix="/api/v1")
app.include_router(rules_router, prefix="/api/v1")
app.include_router(status_router, prefix="/api/v1")
app.include_router(capture_router, prefix="/api/v1")
 
 
# ── Health (Docker HEALTHCHECK + monitoring — NFR16.3) ─────────────────────
 
@app.get("/health", tags=["System"])
async def health():
    return {
        "status": "ok",
        "system": "AI-NIDS",
        "version": "0.2.0",
        "uptime_seconds": round(time.time() - _startup_time, 1),
        "components": {
            "database": "connected" if state.db_connected else "disconnected",
            "redis": "connected" if state.redis_connected else "disconnected",
            "signature_rules": f"{state.rules_loaded} rules loaded",
            "ml_models": state.models_loaded or "not yet trained",
            "ws_clients": len(state.ws_clients),
        },
    }
 
# At the top, with other imports:
from backend.api.routers import auth as auth_router

# Inside your app definition, after middleware:
app.include_router(auth_router.router)
 
@app.get("/", include_in_schema=False)
async def root():
    return {"message": "AI-NIDS API v0.2.0 — visit /docs"}