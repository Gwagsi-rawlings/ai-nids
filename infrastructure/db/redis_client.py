"""
AI-NIDS — Redis Client Singleton
db/redis_client.py

Provides shared async Redis clients for:
  DB 0 — pipeline streams
  DB 1 — alert / stats cache
  DB 2 — session tokens

April 3, 2026 | Sprint 1, Week 4
"""

import os
import json
import logging
from typing import Optional

import redis.asyncio as aioredis

logger = logging.getLogger("ai-nids.redis")

# ── URLs from environment ─────────────────────────────────────
REDIS_STREAM_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_CACHE_URL = os.getenv("REDIS_CACHE_URL", "redis://localhost:6379/1")
REDIS_SESSION_URL = os.getenv("REDIS_SESSION_URL", "redis://localhost:6379/2")

# ── Singleton clients (initialised on startup) ────────────────
_stream_client: Optional[aioredis.Redis] = None
_cache_client: Optional[aioredis.Redis] = None
_session_client: Optional[aioredis.Redis] = None

# TTLs (seconds)
ALERT_CACHE_TTL = 300        # Alert detail cache — 5 minutes
STATS_CACHE_TTL = 10         # Live dashboard stats — 10 seconds
SESSION_TTL = 3600           # JWT session — 1 hour

async def get_redis() -> aioredis.Redis:
    """Returns the pipeline Redis client (DB 0)."""
    if _stream_client is None:
        raise RuntimeError("Redis stream client not initialised — call init_redis() first")
    return _stream_client

async def init_redis():
    """Connect all three Redis clients. Call from FastAPI lifespan."""
    global _stream_client, _cache_client, _session_client
    _stream_client = aioredis.from_url(REDIS_STREAM_URL, decode_responses=True)
    _cache_client = aioredis.from_url(REDIS_CACHE_URL, decode_responses=True)
    _session_client = aioredis.from_url(REDIS_SESSION_URL, decode_responses=True)

    await _stream_client.ping()
    await _cache_client.ping()
    await _session_client.ping()
    logger.info("Redis: all three clients connected (stream/cache/session)")


async def close_redis():
    """Close all Redis connections. Call from FastAPI shutdown."""
    for client in (_stream_client, _cache_client, _session_client):
        if client:
            await client.aclose()
    logger.info("Redis: connections closed")


def get_stream() -> aioredis.Redis:
    """Return pipeline stream client (DB 0)."""
    if _stream_client is None:
        raise RuntimeError("Redis stream client not initialised — call init_redis() first")
    return _stream_client


def get_cache() -> aioredis.Redis:
    """Return alert/stats cache client (DB 1)."""
    if _cache_client is None:
        raise RuntimeError("Redis cache client not initialised — call init_redis() first")
    return _cache_client


def get_session_store() -> aioredis.Redis:
    """Return session token client (DB 2)."""
    if _session_client is None:
        raise RuntimeError("Redis session client not initialised — call init_redis() first")
    return _session_client


# ── Helpers ───────────────────────────────────────────────────

async def cache_alert(alert_id: str, alert_data: dict):
    """Cache an alert dict by alert_id with ALERT_CACHE_TTL."""
    try:
        cache = get_cache()
        await cache.setex(
            f"nids:cache:alert:{alert_id}",
            ALERT_CACHE_TTL,
            json.dumps(alert_data, default=str),
        )
    except Exception as e:
        logger.warning(f"Redis cache_alert failed: {e}")


async def get_cached_alert(alert_id: str) -> Optional[dict]:
    """Retrieve a cached alert dict, or None if expired/missing."""
    try:
        cache = get_cache()
        raw = await cache.get(f"nids:cache:alert:{alert_id}")
        return json.loads(raw) if raw else None
    except Exception as e:
        logger.warning(f"Redis get_cached_alert failed: {e}")
        return None


async def publish_alert_event(alert_data: dict):
    """
    Publish a new-alert event to Redis Pub/Sub channel.
    FastAPI WebSocket handler subscribes and fans out to dashboard clients.
    """
    try:
        stream = get_stream()
        await stream.publish("nids:alerts:live", json.dumps(alert_data, default=str))
    except Exception as e:
        logger.warning(f"Redis publish_alert_event failed: {e}")


async def update_live_stats(stats: dict):
    """Refresh the live dashboard stats hash (TTL=10s)."""
    try:
        cache = get_cache()
        await cache.setex(
            "nids:cache:stats:live",
            STATS_CACHE_TTL,
            json.dumps(stats, default=str),
        )
    except Exception as e:
        logger.warning(f"Redis update_live_stats failed: {e}")


async def get_live_stats() -> Optional[dict]:
    """Return cached live stats, or None if stale."""
    try:
        cache = get_cache()
        raw = await cache.get("nids:cache:stats:live")
        return json.loads(raw) if raw else None
    except Exception as e:
        logger.warning(f"Redis get_live_stats failed: {e}")
        return None