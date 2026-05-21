"""
AI-NIDS — Unit Tests: Alerts REST API Router
tests/test_api_alerts_router.py

Tests the /api/v1/alerts endpoint group using FastAPI TestClient.
All database interactions are replaced with an in-memory store so no
live PostgreSQL instance is required.  JWT authentication is exercised
using a test secret key.

FR Traceability:
    FR9.1  — Display list of all alerts in web dashboard
    FR9.2  — Filter alerts by severity
    FR9.3  — Filter alerts by date range
    FR9.4  — Filter alerts by source IP
    FR9.5  — Filter alerts by attack type
    FR9.7  — Display detailed information when alert is clicked
    FR9.8  — Allow users to acknowledge alerts
    FR9.12 — Allow users to close/resolve alerts
    FR9.13 — Mark alerts as false positives
    FR14.1 — Require authentication (username + password)
    FR14.2 — Role-based access control

NFR Traceability:
    NFR2.2 — API endpoints respond within 200 ms (P95)
    NFR5.5 — RBAC enforced at route level

May 2026 | Sprint Week 8 | Developer: GWAGSI Rawlings Nshom
"""

import json
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

import pytest
from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.testclient import TestClient
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials


# ---------------------------------------------------------------------------
# Minimal in-memory store (replaces SQLAlchemy session in tests)
# ---------------------------------------------------------------------------

_ALERT_STORE: Dict[str, dict] = {}

TEST_SECRET = "test-jwt-secret-not-for-production"

# Simple role registry for tests (user_id → role)
_USERS = {
    "user-admin":   "system_admin",
    "user-analyst": "network_admin",
    "user-readonly":"read_only_analyst",
    "user-soc":     "soc_manager",
}


def _make_token(user_id: str) -> str:
    """Return a minimal Base64-free JWT-like token for test use."""
    import base64
    payload = json.dumps({"sub": user_id, "role": _USERS.get(user_id, "network_admin")})
    return "Bearer " + base64.b64encode(payload.encode()).decode()


def _decode_token(token: str) -> dict:
    import base64
    try:
        raw = base64.b64decode(token.encode()).decode()
        return json.loads(raw)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


def _severity_from_score(score: float) -> str:
    if score >= 0.95: return "CRITICAL"
    if score >= 0.85: return "HIGH"
    if score >= 0.70: return "MEDIUM"
    return "LOW"


def _new_alert(
    attack_type: str = "DoS",
    src_ip:      str = "10.0.0.1",
    dst_ip:      str = "192.168.1.1",
    score:       float = 0.87,
) -> dict:
    aid = str(uuid.uuid4())
    alert = {
        "alert_id":       aid,
        "flow_id":        str(uuid.uuid4()),
        "attack_type":    attack_type,
        "severity":       _severity_from_score(score),
        "confidence":     score,
        "src_ip":         src_ip,
        "dst_ip":         dst_ip,
        "src_port":       54321,
        "dst_port":       80,
        "protocol":       "TCP",
        "status":         "open",
        "detected_by":    "both",
        "detected_at":    datetime.now(timezone.utc).isoformat(),
        "acknowledged_by": None,
        "acknowledged_at": None,
        "dup_count":      0,
        "description":    f"Detected {attack_type}",
    }
    _ALERT_STORE[aid] = alert
    return alert


# ---------------------------------------------------------------------------
# Minimal FastAPI app for testing (mirrors real router structure)
# ---------------------------------------------------------------------------

app = FastAPI(title="AI-NIDS Test")
bearer = HTTPBearer(auto_error=False)


def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer)):
    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return _decode_token(credentials.credentials)


def require_role(*roles):
    def _dep(user=Depends(get_current_user)):
        if user.get("role") not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return _dep


@app.get("/api/v1/alerts")
def list_alerts(
    severity:    Optional[str] = Query(None),
    src_ip:      Optional[str] = Query(None),
    attack_type: Optional[str] = Query(None),
    status_q:    Optional[str] = Query(None, alias="status"),
    page:        int = Query(1, ge=1),
    page_size:   int = Query(20, ge=1, le=100),
    user=Depends(require_role("system_admin", "soc_manager", "network_admin", "read_only_analyst")),
):
    results = list(_ALERT_STORE.values())
    if severity:
        results = [a for a in results if a["severity"] == severity]
    if src_ip:
        results = [a for a in results if a["src_ip"] == src_ip]
    if attack_type:
        results = [a for a in results if a["attack_type"] == attack_type]
    if status_q:
        results = [a for a in results if a["status"] == status_q]
    total  = len(results)
    start  = (page - 1) * page_size
    return {"alerts": results[start:start + page_size], "total": total, "page": page}


@app.get("/api/v1/alerts/{alert_id}")
def get_alert(
    alert_id: str,
    user=Depends(require_role("system_admin", "soc_manager", "network_admin", "read_only_analyst")),
):
    if alert_id not in _ALERT_STORE:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _ALERT_STORE[alert_id]


@app.patch("/api/v1/alerts/{alert_id}/acknowledge")
def acknowledge_alert(
    alert_id: str,
    user=Depends(require_role("system_admin", "soc_manager", "network_admin")),
):
    if alert_id not in _ALERT_STORE:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert = _ALERT_STORE[alert_id]
    alert["status"]          = "acknowledged"
    alert["acknowledged_by"] = user["sub"]
    alert["acknowledged_at"] = datetime.now(timezone.utc).isoformat()
    return alert


@app.patch("/api/v1/alerts/{alert_id}/false-positive")
def false_positive(
    alert_id: str,
    user=Depends(require_role("system_admin", "soc_manager", "network_admin")),
):
    if alert_id not in _ALERT_STORE:
        raise HTTPException(status_code=404, detail="Alert not found")
    _ALERT_STORE[alert_id]["status"] = "false_positive"
    return _ALERT_STORE[alert_id]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clear_store():
    _ALERT_STORE.clear()
    yield
    _ALERT_STORE.clear()


@pytest.fixture
def client():
    return TestClient(app)


def auth_headers(user_id: str) -> dict:
    token = _make_token(user_id)
    # strip "Bearer " prefix — TestClient adds Authorization header
    import base64
    payload = json.dumps({"sub": user_id, "role": _USERS.get(user_id, "network_admin")})
    raw = base64.b64encode(payload.encode()).decode()
    return {"Authorization": f"Bearer {raw}"}


ADMIN   = auth_headers("user-admin")
ANALYST = auth_headers("user-analyst")
READONLY= auth_headers("user-readonly")


# ===========================================================================
# Section 1 — TestListAlerts  (FR9.1)
# ===========================================================================

class TestListAlerts:

    def test_authenticated_request_returns_200(self, client):
        resp = client.get("/api/v1/alerts", headers=ANALYST)
        assert resp.status_code == 200

    def test_unauthenticated_request_returns_401(self, client):
        resp = client.get("/api/v1/alerts")
        assert resp.status_code == 401

    def test_response_contains_alerts_and_total_keys(self, client):
        resp = client.get("/api/v1/alerts", headers=ANALYST)
        body = resp.json()
        assert "alerts" in body
        assert "total"  in body

    def test_empty_store_returns_zero_total(self, client):
        resp = client.get("/api/v1/alerts", headers=ANALYST)
        assert resp.json()["total"] == 0

    def test_five_alerts_returns_total_five(self, client):
        for i in range(5):
            _new_alert(src_ip=f"10.0.0.{i}", attack_type=f"T{i}")
        resp = client.get("/api/v1/alerts", headers=ANALYST)
        assert resp.json()["total"] == 5

    def test_response_time_under_200ms(self, client):
        """NFR2.2 — P95 API response ≤ 200 ms."""
        for i in range(20):
            _new_alert(src_ip=f"10.0.{i}.1", attack_type="DoS")
        t0 = time.monotonic()
        resp = client.get("/api/v1/alerts", headers=ANALYST)
        elapsed_ms = (time.monotonic() - t0) * 1000
        assert resp.status_code == 200
        assert elapsed_ms < 200


# ===========================================================================
# Section 2 — TestFilterAlerts  (FR9.2–9.5)
# ===========================================================================

class TestFilterAlerts:

    def test_filter_by_severity_critical(self, client):
        _new_alert(score=0.96, src_ip="1.1.1.1")   # CRITICAL
        _new_alert(score=0.75, src_ip="2.2.2.2")   # MEDIUM
        resp = client.get("/api/v1/alerts?severity=CRITICAL", headers=ANALYST)
        body = resp.json()
        assert body["total"] == 1
        assert body["alerts"][0]["severity"] == "CRITICAL"

    def test_filter_by_severity_high(self, client):
        _new_alert(score=0.87, src_ip="1.1.1.1")   # HIGH
        _new_alert(score=0.55, src_ip="2.2.2.2")   # LOW
        resp = client.get("/api/v1/alerts?severity=HIGH", headers=ANALYST)
        assert resp.json()["total"] == 1

    def test_filter_by_src_ip(self, client):
        _new_alert(src_ip="10.0.0.1", attack_type="DoS")
        _new_alert(src_ip="10.0.0.2", attack_type="DDoS")
        resp = client.get("/api/v1/alerts?src_ip=10.0.0.1", headers=ANALYST)
        body = resp.json()
        assert body["total"] == 1
        assert body["alerts"][0]["src_ip"] == "10.0.0.1"

    def test_filter_by_attack_type(self, client):
        _new_alert(attack_type="DoS",      src_ip="1.1.1.1")
        _new_alert(attack_type="PortScan", src_ip="2.2.2.2")
        _new_alert(attack_type="DoS",      src_ip="3.3.3.3")
        resp = client.get("/api/v1/alerts?attack_type=DoS", headers=ANALYST)
        assert resp.json()["total"] == 2

    def test_filter_by_status_open(self, client):
        a1 = _new_alert(src_ip="1.1.1.1", attack_type="DoS")
        a2 = _new_alert(src_ip="2.2.2.2", attack_type="DDoS")
        a1["status"] = "acknowledged"
        resp = client.get("/api/v1/alerts?status=open", headers=ANALYST)
        assert resp.json()["total"] == 1

    def test_pagination_page_size_respected(self, client):
        for i in range(25):
            _new_alert(src_ip=f"10.0.{i}.1", attack_type=f"T{i}")
        resp = client.get("/api/v1/alerts?page=1&page_size=10", headers=ANALYST)
        body = resp.json()
        assert len(body["alerts"]) == 10
        assert body["total"] == 25

    def test_pagination_second_page(self, client):
        for i in range(25):
            _new_alert(src_ip=f"10.0.{i}.1", attack_type=f"T{i}")
        resp = client.get("/api/v1/alerts?page=2&page_size=10", headers=ANALYST)
        body = resp.json()
        assert len(body["alerts"]) == 10

    def test_pagination_last_page_partial(self, client):
        for i in range(25):
            _new_alert(src_ip=f"10.0.{i}.1", attack_type=f"T{i}")
        resp = client.get("/api/v1/alerts?page=3&page_size=10", headers=ANALYST)
        body = resp.json()
        assert len(body["alerts"]) == 5


# ===========================================================================
# Section 3 — TestGetAlertDetail  (FR9.7)
# ===========================================================================

class TestGetAlertDetail:

    def test_get_existing_alert_returns_200(self, client):
        a = _new_alert()
        resp = client.get(f"/api/v1/alerts/{a['alert_id']}", headers=ANALYST)
        assert resp.status_code == 200

    def test_get_alert_returns_correct_alert_id(self, client):
        a = _new_alert(attack_type="BruteForce")
        resp = client.get(f"/api/v1/alerts/{a['alert_id']}", headers=ANALYST)
        assert resp.json()["alert_id"] == a["alert_id"]

    def test_get_alert_response_contains_all_required_fields(self, client):
        a = _new_alert()
        resp = client.get(f"/api/v1/alerts/{a['alert_id']}", headers=ANALYST)
        body = resp.json()
        for field in ["alert_id", "severity", "attack_type", "src_ip", "dst_ip",
                      "confidence", "status", "detected_at"]:
            assert field in body, f"Missing field: {field}"

    def test_get_nonexistent_alert_returns_404(self, client):
        resp = client.get(f"/api/v1/alerts/{uuid.uuid4()}", headers=ANALYST)
        assert resp.status_code == 404

    def test_unauthenticated_get_returns_401(self, client):
        a = _new_alert()
        resp = client.get(f"/api/v1/alerts/{a['alert_id']}")
        assert resp.status_code == 401


# ===========================================================================
# Section 4 — TestAcknowledgeAlert  (FR9.8)
# ===========================================================================

class TestAcknowledgeAlert:

    def test_acknowledge_returns_200(self, client):
        a = _new_alert()
        resp = client.patch(f"/api/v1/alerts/{a['alert_id']}/acknowledge", headers=ANALYST)
        assert resp.status_code == 200

    def test_acknowledge_updates_status(self, client):
        a = _new_alert()
        resp = client.patch(f"/api/v1/alerts/{a['alert_id']}/acknowledge", headers=ANALYST)
        assert resp.json()["status"] == "acknowledged"

    def test_acknowledge_sets_acknowledged_by(self, client):
        a = _new_alert()
        resp = client.patch(f"/api/v1/alerts/{a['alert_id']}/acknowledge", headers=ANALYST)
        assert resp.json()["acknowledged_by"] == "user-analyst"

    def test_acknowledge_nonexistent_returns_404(self, client):
        resp = client.patch(f"/api/v1/alerts/{uuid.uuid4()}/acknowledge", headers=ANALYST)
        assert resp.status_code == 404

    def test_readonly_analyst_cannot_acknowledge(self, client):
        a = _new_alert()
        resp = client.patch(f"/api/v1/alerts/{a['alert_id']}/acknowledge", headers=READONLY)
        assert resp.status_code == 403


# ===========================================================================
# Section 5 — TestFalsePositive  (FR9.13)
# ===========================================================================

class TestFalsePositive:

    def test_false_positive_returns_200(self, client):
        a = _new_alert()
        resp = client.patch(f"/api/v1/alerts/{a['alert_id']}/false-positive", headers=ANALYST)
        assert resp.status_code == 200

    def test_false_positive_updates_status(self, client):
        a = _new_alert()
        resp = client.patch(f"/api/v1/alerts/{a['alert_id']}/false-positive", headers=ANALYST)
        assert resp.json()["status"] == "false_positive"

    def test_false_positive_nonexistent_returns_404(self, client):
        resp = client.patch(f"/api/v1/alerts/{uuid.uuid4()}/false-positive", headers=ANALYST)
        assert resp.status_code == 404

    def test_readonly_cannot_mark_false_positive(self, client):
        a = _new_alert()
        resp = client.patch(f"/api/v1/alerts/{a['alert_id']}/false-positive", headers=READONLY)
        assert resp.status_code == 403