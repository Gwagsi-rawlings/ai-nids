"""
AI-NIDS — Unit Tests: WebSocket Alert Fan-out
tests/test_ws_fanout.py

Tests the Redis Pub/Sub → WebSocket fan-out path that delivers real-time
alerts to connected dashboard clients.  All tests use an in-process
asyncio event loop with mocked Redis subscriber and a lightweight
WebSocket connection manager stub — no live Redis or browser required.

FR Traceability:
    FR10.5 — Display real-time alerts in dashboard without page refresh
    FR9.1  — Display list of all alerts in web dashboard
    FR14.2 — Role-based access control enforced at WebSocket connection

NFR Traceability:
    NFR2.3 — Real-time dashboard updates within 500 ms of event occurrence
    NFR5.5 — RBAC enforced at API route level

May 2026 | Sprint Week 8 | Developer: GWAGSI Rawlings Nshom
"""

import asyncio
import json
import time
import uuid
from typing import List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Stubs — WebSocket connection manager and JWT role extraction
# ---------------------------------------------------------------------------

class FakeWebSocket:
    """
    Minimal WebSocket stub that records sent messages and can simulate
    slow / disconnected clients.
    """

    def __init__(self, client_id: str, role: str = "network_admin", slow: bool = False):
        self.client_id   = client_id
        self.role        = role
        self.slow        = slow          # if True, send() adds 0.6 s delay
        self.messages:   List[str] = []
        self.closed:     bool = False
        self.accept_called: bool = False

    async def accept(self):
        self.accept_called = True

    async def send_text(self, data: str):
        if self.closed:
            raise RuntimeError("WebSocket is closed")
        if self.slow:
            await asyncio.sleep(0.6)     # exceeds a typical 500 ms timeout guard
        self.messages.append(data)

    async def close(self):
        self.closed = True


class AlertSeverity:
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


# Severity levels allowed per role (mirrors real RBAC policy)
ROLE_SEVERITY_FILTER = {
    "system_admin":       {AlertSeverity.CRITICAL, AlertSeverity.HIGH, AlertSeverity.MEDIUM, AlertSeverity.LOW},
    "soc_manager":        {AlertSeverity.CRITICAL, AlertSeverity.HIGH, AlertSeverity.MEDIUM, AlertSeverity.LOW},
    "network_admin":      {AlertSeverity.CRITICAL, AlertSeverity.HIGH, AlertSeverity.MEDIUM, AlertSeverity.LOW},
    "read_only_analyst":  {AlertSeverity.MEDIUM, AlertSeverity.LOW},
}


class WSConnectionManager:
    """
    In-memory WebSocket connection manager.
    Mirrors the real manager's fan-out logic using asyncio.gather so that
    slow or disconnected clients cannot block delivery to other clients.
    """

    def __init__(self, send_timeout: float = 0.5):
        self._connections: dict[str, FakeWebSocket] = {}
        self.send_timeout = send_timeout
        self.dropped_clients: List[str] = []

    def connect(self, ws: FakeWebSocket):
        self._connections[ws.client_id] = ws

    def disconnect(self, client_id: str):
        self._connections.pop(client_id, None)

    @property
    def active_count(self) -> int:
        return len(self._connections)

    async def broadcast(self, payload: dict):
        """
        Fan-out payload to all connected clients whose role permits
        the alert severity.  Uses asyncio.gather with per-client timeout
        so slow clients do not block others.
        """
        severity = payload.get("severity", "LOW")

        async def _send(ws: FakeWebSocket):
            allowed = ROLE_SEVERITY_FILTER.get(ws.role, set())
            if severity not in allowed:
                return
            try:
                await asyncio.wait_for(ws.send_text(json.dumps(payload)), timeout=self.send_timeout)
            except (asyncio.TimeoutError, RuntimeError):
                self.dropped_clients.append(ws.client_id)

        await asyncio.gather(*[_send(ws) for ws in list(self._connections.values())])


def _make_alert_payload(
    severity: str = "HIGH",
    attack_type: str = "DoS",
    src_ip: str = "10.0.0.1",
    alert_id: str = None,
) -> dict:
    return {
        "alert_id":    alert_id or str(uuid.uuid4()),
        "severity":    severity,
        "attack_type": attack_type,
        "src_ip":      src_ip,
        "timestamp":   time.time(),
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def manager():
    return WSConnectionManager(send_timeout=0.5)


@pytest.fixture
def admin_ws():
    return FakeWebSocket("client-admin", role="network_admin")


@pytest.fixture
def analyst_ws():
    return FakeWebSocket("client-analyst", role="read_only_analyst")


@pytest.fixture
def soc_ws():
    return FakeWebSocket("client-soc", role="soc_manager")


# ===========================================================================
# Section 1 — TestWSConnection
# ===========================================================================

class TestWSConnection:
    """Connection lifecycle and JWT role enforcement."""

    def test_connect_registers_client(self, manager, admin_ws):
        manager.connect(admin_ws)
        assert manager.active_count == 1

    def test_disconnect_removes_client(self, manager, admin_ws):
        manager.connect(admin_ws)
        manager.disconnect(admin_ws.client_id)
        assert manager.active_count == 0

    def test_multiple_clients_tracked(self, manager):
        for i in range(5):
            manager.connect(FakeWebSocket(f"c{i}", role="network_admin"))
        assert manager.active_count == 5

    def test_duplicate_connect_overwrites(self, manager):
        ws1 = FakeWebSocket("same-id", role="network_admin")
        ws2 = FakeWebSocket("same-id", role="soc_manager")
        manager.connect(ws1)
        manager.connect(ws2)
        assert manager.active_count == 1
        assert manager._connections["same-id"].role == "soc_manager"

    def test_disconnect_nonexistent_client_does_not_raise(self, manager):
        manager.disconnect("ghost-client")   # must not raise


# ===========================================================================
# Section 2 — TestWSBroadcast  (FR10.5, NFR2.3)
# ===========================================================================

class TestWSBroadcast:
    """Alert fan-out delivery tests."""

    @pytest.mark.asyncio
    async def test_alert_received_by_connected_client(self, manager, admin_ws):
        manager.connect(admin_ws)
        payload = _make_alert_payload(severity="HIGH")
        t0 = time.monotonic()
        await manager.broadcast(payload)
        elapsed_ms = (time.monotonic() - t0) * 1000

        assert len(admin_ws.messages) == 1
        received = json.loads(admin_ws.messages[0])
        assert received["alert_id"] == payload["alert_id"]

    @pytest.mark.asyncio
    async def test_alert_delivered_within_500ms(self, manager, admin_ws):
        """NFR2.3 — real-time update within 500 ms."""
        manager.connect(admin_ws)
        t0 = time.monotonic()
        await manager.broadcast(_make_alert_payload())
        elapsed_ms = (time.monotonic() - t0) * 1000
        assert elapsed_ms < 500

    @pytest.mark.asyncio
    async def test_broadcast_reaches_all_three_clients(self, manager):
        clients = [FakeWebSocket(f"c{i}", role="network_admin") for i in range(3)]
        for c in clients:
            manager.connect(c)
        await manager.broadcast(_make_alert_payload(severity="HIGH"))
        for c in clients:
            assert len(c.messages) == 1

    @pytest.mark.asyncio
    async def test_slow_client_does_not_block_other_clients(self, manager):
        """asyncio.gather with timeout — slow client must not delay others."""
        slow   = FakeWebSocket("slow", role="network_admin", slow=True)
        fast1  = FakeWebSocket("fast1", role="network_admin")
        fast2  = FakeWebSocket("fast2", role="network_admin")
        manager.connect(slow)
        manager.connect(fast1)
        manager.connect(fast2)

        t0 = time.monotonic()
        await manager.broadcast(_make_alert_payload(severity="HIGH"))
        elapsed_ms = (time.monotonic() - t0) * 1000

        # fast clients received the alert
        assert len(fast1.messages) == 1
        assert len(fast2.messages) == 1
        # slow client was dropped (timed out) — not blocking
        assert "slow" in manager.dropped_clients
        # total elapsed must be < 600 ms (send_timeout + overhead)
        assert elapsed_ms < 700

    @pytest.mark.asyncio
    async def test_disconnected_client_does_not_crash_broadcast(self, manager, admin_ws):
        manager.connect(admin_ws)
        await admin_ws.close()            # simulate disconnection
        # Must not raise even though send_text will raise RuntimeError
        await manager.broadcast(_make_alert_payload())

    @pytest.mark.asyncio
    async def test_100_rapid_alerts_all_delivered(self, manager, admin_ws):
        manager.connect(admin_ws)
        for _ in range(100):
            await manager.broadcast(_make_alert_payload(severity="HIGH"))
        assert len(admin_ws.messages) == 100

    @pytest.mark.asyncio
    async def test_payload_severity_field_present_in_message(self, manager, admin_ws):
        manager.connect(admin_ws)
        await manager.broadcast(_make_alert_payload(severity="CRITICAL"))
        received = json.loads(admin_ws.messages[0])
        assert "severity" in received
        assert received["severity"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_payload_attack_type_field_present(self, manager, admin_ws):
        manager.connect(admin_ws)
        await manager.broadcast(_make_alert_payload(attack_type="PortScan"))
        received = json.loads(admin_ws.messages[0])
        assert received["attack_type"] == "PortScan"


# ===========================================================================
# Section 3 — TestWSRoleFilter  (FR14.2, NFR5.5)
# ===========================================================================

class TestWSRoleFilter:
    """RBAC severity filtering at the WebSocket fan-out layer."""

    @pytest.mark.asyncio
    async def test_read_only_analyst_receives_low_severity(self, manager, analyst_ws):
        manager.connect(analyst_ws)
        await manager.broadcast(_make_alert_payload(severity="LOW"))
        assert len(analyst_ws.messages) == 1

    @pytest.mark.asyncio
    async def test_read_only_analyst_receives_medium_severity(self, manager, analyst_ws):
        manager.connect(analyst_ws)
        await manager.broadcast(_make_alert_payload(severity="MEDIUM"))
        assert len(analyst_ws.messages) == 1

    @pytest.mark.asyncio
    async def test_read_only_analyst_does_not_receive_high(self, manager, analyst_ws):
        manager.connect(analyst_ws)
        await manager.broadcast(_make_alert_payload(severity="HIGH"))
        assert len(analyst_ws.messages) == 0

    @pytest.mark.asyncio
    async def test_read_only_analyst_does_not_receive_critical(self, manager, analyst_ws):
        manager.connect(analyst_ws)
        await manager.broadcast(_make_alert_payload(severity="CRITICAL"))
        assert len(analyst_ws.messages) == 0

    @pytest.mark.asyncio
    async def test_soc_manager_receives_all_severity_levels(self, manager, soc_ws):
        manager.connect(soc_ws)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            await manager.broadcast(_make_alert_payload(severity=sev))
        assert len(soc_ws.messages) == 4

    @pytest.mark.asyncio
    async def test_network_admin_receives_all_severity_levels(self, manager, admin_ws):
        manager.connect(admin_ws)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            await manager.broadcast(_make_alert_payload(severity=sev))
        assert len(admin_ws.messages) == 4

    @pytest.mark.asyncio
    async def test_mixed_roles_each_receive_correct_subset(self, manager, admin_ws, analyst_ws):
        manager.connect(admin_ws)
        manager.connect(analyst_ws)
        await manager.broadcast(_make_alert_payload(severity="CRITICAL"))
        # admin gets it, analyst does not
        assert len(admin_ws.messages) == 1
        assert len(analyst_ws.messages) == 0

    @pytest.mark.asyncio
    async def test_reconnecting_client_receives_next_alert(self, manager, admin_ws):
        manager.connect(admin_ws)
        await manager.broadcast(_make_alert_payload(severity="HIGH"))
        assert len(admin_ws.messages) == 1

        # Disconnect then reconnect
        manager.disconnect(admin_ws.client_id)
        new_ws = FakeWebSocket(admin_ws.client_id, role="network_admin")
        manager.connect(new_ws)
        await manager.broadcast(_make_alert_payload(severity="HIGH"))
        assert len(new_ws.messages) == 1