FROM python:3.10-slim

LABEL maintainer="GWAGSI Rawlings Nshom"
LABEL description="AI-NIDS Backend — FastAPI + ML detection pipeline"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# System dependencies required by Scapy for packet capture
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies — torch CPU-only wheels from PyTorch index
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --extra-index-url https://download.pytorch.org/whl/cpu \
        -r requirements.txt

COPY . .

# Non-root user for security
RUN groupadd -r nids && useradd -r -g nids nids && \
    chown -R nids:nids /app
USER nids

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
