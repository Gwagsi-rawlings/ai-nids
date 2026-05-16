"""
AI-NIDS — Redis Configuration & Key Schema
infrastructure/redis/redis_config.py

Implements the Redis key design specified in the Database Design
Document (Feb 26, 2026), Section 07.

Three DB separation (per docker-compose.yml):
    DB 0 → pipeline streams  (nids:stream:*)
    DB 1 → alert/stats cache (nids:cache:*)
    DB 2 → session tokens    (nids:session:*)

Provides:
  - Centralised key-name constants (no magic strings scattered in code)
  - RedisManager: thin async wrapper that opens the three DB connections
    and exposes helpers for each functional area
  - Alert cache read/write (TTL 300 s)
  - Live stats cache read/write (TTL 10 s)
  - Session token read/write/delete (TTL 3600 s)
  - Rate-limit counter helpers
  - Active rule-set cache invalidation

FR Traceability:
    FR9    — Real-time alert streaming to dashboard
    FR14   — Session token management (JWT + Redis)
    FR17   — System health / live stats
    NFR1.1 — Pipeline throughput via Redis Streams
    NFR1.6 — Dashboard loads < 3 s (stats served from cache)
    NFR3   — 99.9% uptime — Redis AOF persistence (docker-compose)

April 3, 2026 | Sprint 1, Week 4 | Developer: GWAGSI Rawlings Nshom
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional

import redis.asyncio as aioredis

logger = logging.getLogger("ai-nids.redis")

# ---------------------------------------------------------------------------
# Redis DB numbers (per docker-compose.yml comment block)
# ---------------------------------------------------------------------------

DB_STREAMS  = 0   # pipeline event streams
DB_CACHE    = 1   # alert details + live stats
DB_SESSIONS = 2   # JWT session tokens


# ---------------------------------------------------------------------------
# TTL constants (seconds)
# ---------------------------------------------------------------------------

TTL_ALERT_CACHE   = 300    # 5 minutes — recent alert detail
TTL_STATS_CACHE   = 10     # 10 seconds — live dashboard counters
TTL_SESSION       = 3_600  # 1 hour — JWT session
TTL_RATE_LIMIT    = 60     # 1 minute — API rate-limit window
TTL_RULES_CACHE   = 0      # no expiry — invalidated on rule change


# ---------------------------------------------------------------------------
# Key name helpers  (all return strings — no magic literals elsewhere)
# ---------------------------------------------------------------------------

class RedisKeys:
    """
    Centralised key-name factory.
    All keys follow the namespace pattern: nids:{area}:{identifier}
    Keys must not contain whitespace, slashes, or quotes (DB design §7).
    """

    # ── Pipeline streams (DB 0) ──────────────────────────────────────────
    STREAM_RAW_PACKETS  = "nids:stream:raw_packets"
    STREAM_FLOWS        = "nids:stream:flows"
    STREAM_FEATURES     = "nids:stream:features"
    STREAM_SIG_RESULTS  = "nids:stream:sig_results"
    STREAM_ML_RESULTS   = "nids:stream:ml_results"
    STREAM_DETECTIONS   = "nids:stream:detections"
    STREAM_ALERTS       = "nids:stream:alerts"

    # Max entries per stream before trimming (MAXLEN)
    STREAM_MAXLEN = 100_000

    # ── Alert cache (DB 1) ───────────────────────────────────────────────
    @staticmethod
    def alert_cache(alert_uuid: str) -> str:
        return f"nids:cache:alert:{alert_uuid}"

    # ── Live stats (DB 1) ────────────────────────────────────────────────
    STATS_LIVE = "nids:cache:stats:live"

    # ── Active rule set (DB 1) ───────────────────────────────────────────
    RULES_ACTIVE = "nids:cache:rules:active"

    # ── Session tokens (DB 2) ────────────────────────────────────────────
    @staticmethod
    def session(token: str) -> str:
        return f"nids:session:{token}"

    # ── Rate limiting (DB 1) ─────────────────────────────────────────────
    @staticmethod
    def rate_limit(user_id: str) -> str:
        return f"nids:rate:{user_id}"

    # ── Pub/Sub channel — real-time alert push to WebSocket clients ──────
    PUBSUB_ALERTS = "nids:pubsub:alerts"


# ---------------------------------------------------------------------------
# RedisManager
# ---------------------------------------------------------------------------

class RedisManager:
    """
    Manages the three Redis DB connections and exposes typed helper methods
    for each functional area.  Instantiate once at startup (FastAPI lifespan)
    and share as a dependency.

    Usage
    -----
    rm = RedisManager()
    await rm.connect()
    ...
    await rm.close()
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        cache_url: Optional[str] = None,
        session_url: Optional[str] = None,
    ):
        # Allow full URL override or fall back to env vars / Docker defaults
        self._base_url    = base_url    or os.getenv("REDIS_URL",         "redis://redis:6379/0")
        self._cache_url   = cache_url   or os.getenv("REDIS_CACHE_URL",   "redis://redis:6379/1")
        self._session_url = session_url or os.getenv("REDIS_SESSION_URL", "redis://redis:6379/2")

        self._streams:  Optional[aioredis.Redis] = None
        self._cache:    Optional[aioredis.Redis] = None
        self._sessions: Optional[aioredis.Redis] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Open connections to all three Redis databases."""
        self._streams  = aioredis.from_url(self._base_url,    decode_responses=True)
        self._cache    = aioredis.from_url(self._cache_url,   decode_responses=True)
        self._sessions = aioredis.from_url(self._session_url, decode_responses=True)

        # Verify connectivity
        for name, client in [
            ("DB0/streams", self._streams),
            ("DB1/cache",   self._cache),
            ("DB2/sessions", self._sessions),
        ]:
            try:
                await client.ping()
                logger.info("Redis %s: connected", name)
            except Exception as exc:
                logger.warning("Redis %s: ping failed — %s", name, exc)

    async def close(self) -> None:
        """Close all Redis connections gracefully."""
        for client in [self._streams, self._cache, self._sessions]:
            if client:
                await client.aclose()

    async def ping_all(self) -> dict:
        """Health check — returns status of each DB connection."""
        results = {}
        for name, client in [
            ("streams",  self._streams),
            ("cache",    self._cache),
            ("sessions", self._sessions),
        ]:
            try:
                ok = await client.ping() if client else False
                results[name] = "ok" if ok else "no_client"
            except Exception as exc:
                results[name] = f"error:{exc}"
        return results

    # ------------------------------------------------------------------
    # Properties (raw client access for advanced use)
    # ------------------------------------------------------------------

    @property
    def streams(self) -> aioredis.Redis:
        if self._streams is None:
            raise RuntimeError("RedisManager not connected. Call await connect() first.")
        return self._streams

    @property
    def cache(self) -> aioredis.Redis:
        if self._cache is None:
            raise RuntimeError("RedisManager not connected. Call await connect() first.")
        return self._cache

    @property
    def sessions(self) -> aioredis.Redis:
        if self._sessions is None:
            raise RuntimeError("RedisManager not connected. Call await connect() first.")
        return self._sessions

    # ------------------------------------------------------------------
    # Alert cache  (DB 1)  —  FR9 dashboard fast load
    # ------------------------------------------------------------------

    async def cache_alert(self, alert_uuid: str, alert_data: dict) -> None:
        """
        Store alert details in the cache.  The dashboard reads from here
        on alert-click to avoid hitting PostgreSQL on every request.
        TTL: 300 s (NFR1.6).
        """
        key = RedisKeys.alert_cache(alert_uuid)
        await self.cache.setex(key, TTL_ALERT_CACHE, json.dumps(alert_data))

    async def get_cached_alert(self, alert_uuid: str) -> Optional[dict]:
        """Retrieve alert from cache. Returns None on miss."""
        key = RedisKeys.alert_cache(alert_uuid)
        raw = await self.cache.get(key)
        return json.loads(raw) if raw else None

    async def invalidate_alert_cache(self, alert_uuid: str) -> None:
        """Delete a specific alert from cache (e.g. after acknowledge)."""
        await self.cache.delete(RedisKeys.alert_cache(alert_uuid))

    # ------------------------------------------------------------------
    # Live stats cache  (DB 1)  —  FR17 dashboard counters
    # ------------------------------------------------------------------

    async def set_live_stats(self, stats: dict) -> None:
        """
        Write live dashboard counters (packets/sec, alert counts, top IPs).
        Refreshed every 10 s by the Stats Worker.  TTL: 10 s (NFR1.6).
        """
        await self.cache.setex(
            RedisKeys.STATS_LIVE,
            TTL_STATS_CACHE,
            json.dumps(stats),
        )

    async def get_live_stats(self) -> Optional[dict]:
        """Retrieve live stats. Returns None if cache has expired."""
        raw = await self.cache.get(RedisKeys.STATS_LIVE)
        return json.loads(raw) if raw else None

    async def increment_alert_counter(self, severity: str) -> None:
        """
        Increment the per-severity alert counter used by the dashboard banner.
        Uses Redis HINCRBY for atomic increment.
        """
        await self.cache.hincrby(RedisKeys.STATS_LIVE + ":severity", severity, 1)

    # ------------------------------------------------------------------
    # Rule set cache  (DB 1)  —  Signature Engine fast reload
    # ------------------------------------------------------------------

    async def cache_active_rules(self, rules_json: str) -> None:
        """
        Store the serialised active rule set.  No TTL — invalidated
        explicitly on rule create/edit/delete.
        """
        await self.cache.set(RedisKeys.RULES_ACTIVE, rules_json)

    async def get_active_rules(self) -> Optional[str]:
        return await self.cache.get(RedisKeys.RULES_ACTIVE)

    async def invalidate_rules_cache(self) -> None:
        await self.cache.delete(RedisKeys.RULES_ACTIVE)

    # ------------------------------------------------------------------
    # Session tokens  (DB 2)  —  FR14 JWT management
    # ------------------------------------------------------------------

    async def store_session(
        self,
        token: str,
        user_id: str,
        role: str,
        username: str,
    ) -> None:
        """
        Store JWT session data.  TTL: 3600 s (1 hour).
        Payload stored as Redis Hash for field-level access.
        """
        key = RedisKeys.session(token)
        await self.sessions.hset(key, mapping={
            "user_id":  user_id,
            "role":     role,
            "username": username,
        })
        await self.sessions.expire(key, TTL_SESSION)

    async def get_session(self, token: str) -> Optional[dict]:
        """
        Retrieve session data.  Returns None if token does not exist
        or has expired.  Callers must treat None as "unauthenticated".
        """
        key = RedisKeys.session(token)
        data = await self.sessions.hgetall(key)
        return data if data else None

    async def delete_session(self, token: str) -> None:
        """Invalidate a session on logout."""
        await self.sessions.delete(RedisKeys.session(token))

    async def refresh_session(self, token: str) -> bool:
        """
        Reset TTL on an existing session (sliding expiry on activity).
        Returns False if the session no longer exists.
        """
        key = RedisKeys.session(token)
        result = await self.sessions.expire(key, TTL_SESSION)
        return bool(result)

    # ------------------------------------------------------------------
    # Rate limiting  (DB 1)  —  NFR API protection
    # ------------------------------------------------------------------

    async def check_rate_limit(
        self,
        user_id: str,
        limit: int = 100,
    ) -> tuple[bool, int]:
        """
        Increment and check the per-user request counter.
        Window: TTL_RATE_LIMIT seconds.

        Returns (allowed: bool, current_count: int).
        """
        key = RedisKeys.rate_limit(user_id)
        pipe = self.cache.pipeline()
        pipe.incr(key)
        pipe.ttl(key)
        count, ttl = await pipe.execute()

        if ttl == -1:
            # Key exists but has no TTL (first request missed EXPIRE) — fix it
            await self.cache.expire(key, TTL_RATE_LIMIT)
        elif ttl == -2:
            # Key doesn't exist yet — set TTL
            await self.cache.expire(key, TTL_RATE_LIMIT)

        return count <= limit, int(count)

    # ------------------------------------------------------------------
    # Alert pub/sub  —  real-time WebSocket push  (FR9, FR10)
    # ------------------------------------------------------------------

    async def publish_alert(self, alert_data: dict) -> None:
        """
        Publish a new alert to the pub/sub channel.
        FastAPI WebSocket handler subscribes and fans out to clients.
        """
        await self.cache.publish(
            RedisKeys.PUBSUB_ALERTS,
            json.dumps(alert_data),
        )

    def get_pubsub(self) -> aioredis.client.PubSub:
        """Return a PubSub object for the alert channel (used by WS handler)."""
        return self.cache.pubsub()

    # ------------------------------------------------------------------
    # Pipeline alert stream  (DB 0)  —  NFR1.1 high-throughput path
    # ------------------------------------------------------------------

    async def stream_add_alert(self, alert_data: dict) -> None:
        """
        Add an alert event to the Redis Stream (DB 0).
        Used when traffic volume exceeds asyncio queue capacity (>5K pps).
        Stream is capped at STREAM_MAXLEN entries (MAXLEN ~ 100_000).
        """
        # Redis Streams require string values — serialise nested dicts
        flat = {k: str(v) for k, v in alert_data.items()}
        await self.streams.xadd(
            RedisKeys.STREAM_ALERTS,
            flat,
            maxlen=RedisKeys.STREAM_MAXLEN,
            approximate=True,
        )

    async def stream_read_alerts(
        self,
        last_id: str = "0",
        count: int = 100,
    ) -> list[dict]:
        """
        Read alert events from the Redis Stream.
        last_id: start reading from this stream ID (exclusive).
        Returns list of dicts with stream 'id' and 'data' keys.
        """
        raw = await self.streams.xread(
            {RedisKeys.STREAM_ALERTS: last_id},
            count=count,
            block=0,
        )
        if not raw:
            return []
        results = []
        for _stream_name, messages in raw:
            for msg_id, fields in messages:
                results.append({"id": msg_id, "data": fields})
        return results


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_manager: Optional[RedisManager] = None


def get_redis_manager() -> RedisManager:
    """Return the module-level singleton. Raises if not initialised."""
    if _manager is None:
        raise RuntimeError(
            "RedisManager not initialised. "
            "Call infrastructure.redis.redis_config.init_redis() at startup."
        )
    return _manager


async def init_redis(
    base_url: Optional[str] = None,
    cache_url: Optional[str] = None,
    session_url: Optional[str] = None,
) -> RedisManager:
    """
    Initialise the module-level RedisManager singleton and open connections.
    Call once from the FastAPI lifespan (app/main.py).
    Returns the manager so the caller can store it as an app-state attribute.
    """
    global _manager
    _manager = RedisManager(
        base_url=base_url,
        cache_url=cache_url,
        session_url=session_url,
    )
    await _manager.connect()
    return _manager


async def close_redis() -> None:
    """Close all Redis connections. Call from FastAPI shutdown lifespan."""
    if _manager:
        await _manager.close()