# ============================================================
# AI-NIDS — Backend Dockerfile
# Captures + Signature Engine + FastAPI API layer
# March 25, 2026 | Sprint 1
# ============================================================

# ── Stage 1: Base image ──────────────────────────────────────
FROM python:3.11-slim AS base

LABEL maintainer="GWAGSI Rawlings Nshom"
LABEL description="AI-NIDS Backend — Packet Capture + Signature Engine + FastAPI"
LABEL version="0.1.0"

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# ── System dependencies ──────────────────────────────────────
# libpcap-dev  : required by Scapy for live packet capture
# libnet-dev   : optional low-level networking support
# build-essential : needed to compile some Python C extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    libnet-dev \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ── Stage 2: Dependencies ────────────────────────────────────
FROM base AS dependencies

COPY backend/requirements.txt .

RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# ── Stage 3: Application ─────────────────────────────────────
FROM dependencies AS app

# Copy application source
WORKDIR /app
COPY . .

# Create non-root user for security (NFR5)
RUN groupadd -r nids && useradd -r -g nids nids && \
    chown -R nids:nids /app

USER nids

# Expose FastAPI port
EXPOSE 8000

# Health check endpoint (NFR16.3 — system health check endpoints)
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command: start FastAPI with uvicorn
# Workers set to 1 for MVP; increase for production
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]