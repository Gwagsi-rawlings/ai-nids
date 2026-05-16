"""
AI-NIDS — Alert Generator
app/services/alert_generator.py

Provides build_alert_generator() which returns the concrete async callable
injected into the Ensemble Correlator worker as alert_generator_fn.

This is the critical link that closes the data flow loop:

    Ensemble Correlator (DetectionEvent)
            ↓  alert_generator_fn(event)
    alert_generator_fn
            ↓  opens AsyncSession
    alert_service.process_detection_event(event, db)
            ↓  INSERT INTO alerts
    PostgreSQL
            ↓  SET nids:cache:alert:{id}  (TTL 300s)
    Redis cache (DB 1)
            ↓  PUBLISH nids:alerts:new
    Redis Pub/Sub (DB 0)
            ↓  WebSocket fan-out
    React Dashboard

The generator factory pattern is used so the function can be built once
at startup (with a stable AsyncSessionLocal reference) and called
thousands of times per second without re-opening the engine.

FR Traceability:
    FR7.1  — Generate alert when threat detected
    FR7.8  — Persist to PostgreSQL
    FR10.5 — Real-time WebSocket push via Redis Pub/Sub
    NFR1.4 — Alert generation <= 100 ms end-to-end
April 6, 2026 | Sprint 1, Week 4
"""

import logging
from typing import Callable, Coroutine

from infrastructure.db.database import AsyncSessionLocal
from backend.api.schemas import DetectionEvent
from app.services.alert_service import process_detection_event

logger = logging.getLogger("ai-nids.alert_generator")


def build_alert_generator() -> Callable[[DetectionEvent], Coroutine]:
    """
    Factory that returns the concrete alert_generator_fn.

    Called ONCE at pipeline startup (in pipeline_runner.py).
    The returned coroutine is passed to run_ensemble_worker() as
    the alert_generator_fn argument.

    Usage:
        alert_fn = build_alert_generator()
        asyncio.create_task(run_ensemble_worker(..., alert_generator_fn=alert_fn))
    """

    async def _generate_alert(event: DetectionEvent) -> None:
        """
        Opens a fresh AsyncSession, delegates to alert_service, commits.
        Any DB error is caught and logged — never crashes the pipeline worker.
        """
        try:
            async with AsyncSessionLocal() as session:
                result = await process_detection_event(event, session)
                await session.commit()

                if result is not None:
                    logger.info(
                        "Alert persisted: id=%s severity=%s type=%s score=%.3f",
                        result.id,
                        result.severity,
                        result.attack_type,
                        result.confidence_score,
                    )
                else:
                    logger.debug(
                        "Detection event suppressed (duplicate): %s → %s [%s]",
                        event.src_ip,
                        event.dst_ip,
                        event.attack_type,
                    )

        except Exception as exc:
            logger.exception(
                "Alert generation failed for event %s → %s [%s]: %s",
                event.src_ip,
                event.dst_ip,
                event.attack_type,
                exc,
            )

    return _generate_alert