# AI-NIDS — AI-Powered Network Intrusion Detection System

> **Final Year Project | ICT University, Cameroon | 2024–2025**
> 
> A hybrid intrusion detection system combining signature-based detection with a three-model ML ensemble (Random Forest + Isolation Forest + LSTM) for real-time network threat detection.

---

## CI Status

| Pipeline | Status |
|---|---|
| Backend (Python) | ![CI Backend](https://github.com/YOUR_USERNAME/ai-nids/actions/workflows/ci-backend.yml/badge.svg) |
| Frontend (React) | ![CI Frontend](https://github.com/YOUR_USERNAME/ai-nids/actions/workflows/ci-frontend.yml/badge.svg) |

---

## Project Overview

**Research Question:** Does a hybrid ensemble ML approach outperform single-method IDS systems in detection accuracy and false positive reduction?

**Detection Pipeline:**
```
Network Traffic (SPAN/TAP)
        │
        ▼
  Packet Capture (Scapy/libpcap)
        │
        ▼
  Flow Aggregation (5-tuple)
        │
        ▼
  Feature Extraction (41 features)
        │
  ┌─────┴──────┐
  ▼            ▼
Signature    ML Ensemble
Engine       ├─ Random Forest (0.35)
(0.40)       ├─ Isolation Forest (0.15)
             └─ LSTM (0.10)
  └─────┬──────┘
        ▼
  Ensemble Correlator (weighted vote)
        │
        ▼
  Alert Generation → React Dashboard / Mobile App
```

**Target Performance:**
- Detection accuracy: ≥ 95%
- False positive rate: ≤ 5%
- Throughput: ≥ 10,000 packets/second
- Alert latency: ≤ 100 ms end-to-end

---

## Repository Structure

```
ai-nids/
├── .github/
│   └── workflows/
│       ├── ci-backend.yml        # Python lint + test + Docker build
│       └── ci-frontend.yml       # TypeScript lint + test + build
│
├── backend/                      # FastAPI application
│   ├── capture/                  # Packet capture engine (Scapy)
│   ├── detection/
│   │   ├── signature/            # Snort-syntax rule matching
│   │   └── ml/                   # RF + IF + LSTM + ensemble
│   ├── api/                      # FastAPI routes + WebSocket
│   ├── models/                   # Trained .pkl / .h5 model files
│   ├── tests/                    # pytest test suite
│   ├── requirements.txt
│   └── Dockerfile
│
├── frontend/                     # React + TypeScript dashboard
│   ├── src/
│   │   ├── components/           # Reusable UI components
│   │   ├── pages/                # Dashboard, Alerts, Rules, Reports
│   │   └── hooks/                # WebSocket, API hooks
│   ├── package.json
│   └── Dockerfile
│
├── ml/                           # ML training notebooks & scripts
│   ├── notebooks/                # Google Colab training notebooks
│   ├── datasets/                 # Dataset download scripts (CICIDS2017, NSL-KDD)
│   └── evaluation/               # Model evaluation scripts
│
├── infrastructure/
│   ├── docker-compose.yml        # Local dev stack
│   ├── k8s/                      # Kubernetes manifests (Helm charts)
│   └── terraform/                # Cloud IaC (optional)
│
├── docs/                         # FYP documentation artifacts
│   └── design/
│
├── .gitignore
└── README.md
```

---

## Branch Strategy

| Branch | Purpose | Rules |
|---|---|---|
| `main` | Stable releases only | Protected. PR + review required. Tagged on merge. |
| `dev` | Integration branch | All features merge here. Must pass CI. |
| `feature/*` | Individual features | Branch off `dev`. PR back to `dev`. |
| `hotfix/*` | Emergency production fixes | Branch off `main`. Merge to `main` + `dev`. |

**Feature branch naming:**
```bash
git checkout dev
git checkout -b feature/packet-capture-engine
git checkout -b feature/random-forest-training
git checkout -b feature/react-dashboard-alerts
git checkout -b feature/fastapi-rbac-auth
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.11, FastAPI, Scapy |
| **ML** | scikit-learn (RF + IF), TensorFlow/Keras (LSTM) |
| **Frontend** | React, TypeScript, Recharts, Tailwind CSS |
| **Mobile** | React Native |
| **Database** | PostgreSQL 15 + TimescaleDB |
| **Queue** | Python asyncio queues (Kafka-ready interface) |
| **SIEM** | ELK Stack (Elasticsearch + Logstash + Kibana) |
| **Deployment** | Docker, Docker Compose, Kubernetes (Helm) |
| **CI/CD** | GitHub Actions |
| **Training** | Google Colab (GPU), CICIDS2017 + NSL-KDD datasets |

---

## Quick Start (Local Dev)

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/ai-nids.git
cd ai-nids
git checkout dev

# 2. Start full stack
docker-compose up --build

# 3. Access
#   Dashboard:  http://localhost:3000
#   API docs:   http://localhost:8000/docs
#   Kibana:     http://localhost:5601
```

---

## Running Tests

```bash
# Backend
cd backend
pip install -r requirements.txt
pytest tests/ -v --cov=.

# Frontend
cd frontend
npm ci
npm test
```

---

## Dataset Setup

Training datasets are NOT committed to this repo (large binary files).

```bash
# Download CICIDS2017 (primary dataset)
cd ml/datasets
python download_cicids2017.py   # Downloads to Google Drive or local /data

# Download NSL-KDD (secondary dataset)
python download_nslkdd.py
```

See `ml/notebooks/` for Google Colab training notebooks.

---

## Design Documents

All FYP design artifacts are in `/docs/design/`:

| Date | Document |
|---|---|
| Feb 17 | Stakeholder Analysis |
| Feb 18 | Functional Requirements (166 FRs) |
| Feb 19 | Non-Functional Requirements (103 NFRs) |
| Feb 20 | Use Case Diagrams |
| Feb 21 | User Stories & Acceptance Criteria |
| Feb 24 | Architecture Design |
| Feb 25 | Component Design |
| Feb 26 | Database Design (ERD) |
| Feb 27 | Sequence & Activity Diagrams |

---

## Author

**GWAGSI Rawlings Nshom**  
Information Systems and Network Engineering  
ICT University, Cameroon | 2024–2025
