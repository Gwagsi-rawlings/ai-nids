"""
AI-NIDS — Notification Service
backend/api/services/notification_service.py

Dispatches notifications for HIGH and CRITICAL alerts via two channels:

  1. Email  (FR10.1, FR10.2)
     SMTP-based email to a configurable recipient list.
     Reads SMTP credentials from environment variables.
     Non-blocking: runs in a background thread via asyncio.to_thread().

  2. Webhook  (NFR19.4)
     HTTP POST to a configurable webhook URL (e.g. Slack, Teams, PagerDuty).
     Payload is JSON-serialised alert metadata in a standard envelope.
     Retried up to MAX_RETRIES times with exponential back-off.

Both channels are fire-and-forget from the perspective of the alert pipeline —
a notification failure NEVER blocks or delays alert persistence.

Environment variables consumed:
    SMTP_HOST          SMTP server hostname (default: localhost)
    SMTP_PORT          SMTP server port (default: 587)
    SMTP_USER          SMTP login username (optional)
    SMTP_PASSWORD      SMTP login password (optional)
    SMTP_FROM          Sender address (default: nids@localhost)
    SMTP_TO            Comma-separated recipient list
    SMTP_USE_TLS       "true" | "false" (default: true)
    WEBHOOK_URL        HTTP endpoint for webhook delivery (optional)
    WEBHOOK_SECRET     Optional shared secret sent in X-NIDS-Signature header

FR Traceability:
    FR10.1 — Push notifications for critical alerts
    FR10.2 — Email notifications for HIGH and CRITICAL alerts
    FR10.3 — Allow users to configure notification preferences
    US-3.3  — Alert Notification (Email): deliver within 2 minutes

NFR Traceability:
    NFR19.4 — Webhook integration for external notifications
    NFR9.3  — Queue alerts if DB temporarily unavailable (notification
               failures must not propagate upstream)

April 24, 2026 | Sprint Week 7 | Developer: GWAGSI Rawlings Nshom
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import smtplib
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, asdict
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List, Optional

logger = logging.getLogger("ai-nids.notification")

# ── Retry settings ────────────────────────────────────────────────────────────
MAX_RETRIES: int = 3
RETRY_BASE_DELAY: float = 2.0   # seconds; doubled on each retry (exp. back-off)

# ── Severity filter — only notify for these levels ────────────────────────────
NOTIFY_SEVERITIES = {"HIGH", "CRITICAL"}


# ─────────────────────────────────────────────────────────────────────────────
# Payload model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AlertNotificationPayload:
    """
    Canonical notification payload shared by email and webhook channels.
    Fields match FR7.3–FR7.7 (alert record fields).
    """
    alert_id: str
    severity: str
    attack_type: str
    src_ip: str
    dst_ip: str
    confidence: float
    detected_by: str
    timestamp: float
    group_id: Optional[str] = None
    attack_chain: bool = False
    chain_attack_types: List[str] = None
    # Set to True when the notification is triggered by an escalation action
    # rather than initial alert generation
    is_escalation: bool = False
    escalated_by: Optional[str] = None   # username who escalated

    def __post_init__(self):
        if self.chain_attack_types is None:
            self.chain_attack_types = []

    def to_dict(self) -> Dict:
        return asdict(self)

    def human_timestamp(self) -> str:
        import datetime
        return datetime.datetime.utcfromtimestamp(self.timestamp).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )


# ─────────────────────────────────────────────────────────────────────────────
# SMTP config helper
# ─────────────────────────────────────────────────────────────────────────────

def _smtp_config() -> Dict:
    return {
        "host": os.getenv("SMTP_HOST", "localhost"),
        "port": int(os.getenv("SMTP_PORT", "587")),
        "user": os.getenv("SMTP_USER", ""),
        "password": os.getenv("SMTP_PASSWORD", ""),
        "from_addr": os.getenv("SMTP_FROM", "nids@localhost"),
        "to_addrs": [
            addr.strip()
            for addr in os.getenv("SMTP_TO", "").split(",")
            if addr.strip()
        ],
        "use_tls": os.getenv("SMTP_USE_TLS", "true").lower() == "true",
    }


def _webhook_config() -> Dict:
    return {
        "url": os.getenv("WEBHOOK_URL", ""),
        "secret": os.getenv("WEBHOOK_SECRET", ""),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Email channel
# ─────────────────────────────────────────────────────────────────────────────

def _build_email_subject(payload: AlertNotificationPayload) -> str:
    prefix = "[ESCALATED] " if payload.is_escalation else ""
    chain_note = " ⚠ ATTACK CHAIN" if payload.attack_chain else ""
    return (
        f"{prefix}AI-NIDS {payload.severity} Alert: "
        f"{payload.attack_type} from {payload.src_ip}{chain_note}"
    )


def _build_email_body(payload: AlertNotificationPayload) -> str:
    chain_section = ""
    if payload.attack_chain:
        chain_section = (
            f"\n⚠  MULTI-STAGE ATTACK CHAIN DETECTED\n"
            f"   Attack types in this campaign: "
            f"{', '.join(payload.chain_attack_types)}\n"
        )

    escalation_section = ""
    if payload.is_escalation:
        escalation_section = (
            f"\n--- ESCALATION DETAILS ---\n"
            f"Escalated by : {payload.escalated_by or 'unknown'}\n"
        )

    return f"""
AI-NIDS Security Alert
======================
Alert ID     : {payload.alert_id}
Severity     : {payload.severity}
Attack Type  : {payload.attack_type}
Source IP    : {payload.src_ip}
Destination  : {payload.dst_ip}
Confidence   : {payload.confidence:.1%}
Detected by  : {payload.detected_by}
Timestamp    : {payload.human_timestamp()}
Group ID     : {payload.group_id or 'N/A'}
{chain_section}{escalation_section}
--- ACTION REQUIRED ---
Log in to the AI-NIDS dashboard to acknowledge and investigate this alert.

This is an automated notification from the AI-NIDS system.
""".strip()


def _send_email_sync(payload: AlertNotificationPayload) -> bool:
    """
    Blocking SMTP send.  Intended to be called via asyncio.to_thread().
    Returns True on success, False on failure after MAX_RETRIES attempts.
    """
    cfg = _smtp_config()
    if not cfg["to_addrs"]:
        logger.warning("Email notification skipped — SMTP_TO is not configured")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = _build_email_subject(payload)
    msg["From"] = cfg["from_addr"]
    msg["To"] = ", ".join(cfg["to_addrs"])
    msg.attach(MIMEText(_build_email_body(payload), "plain"))

    delay = RETRY_BASE_DELAY
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            if cfg["use_tls"]:
                server = smtplib.SMTP(cfg["host"], cfg["port"], timeout=10)
                server.starttls()
            else:
                server = smtplib.SMTP(cfg["host"], cfg["port"], timeout=10)

            if cfg["user"] and cfg["password"]:
                server.login(cfg["user"], cfg["password"])

            server.sendmail(cfg["from_addr"], cfg["to_addrs"], msg.as_string())
            server.quit()
            logger.info(
                "Email sent: alert_id=%s severity=%s to=%s",
                payload.alert_id, payload.severity, cfg["to_addrs"],
            )
            return True

        except Exception as exc:
            logger.warning(
                "Email attempt %d/%d failed: %s (alert_id=%s)",
                attempt, MAX_RETRIES, exc, payload.alert_id,
            )
            if attempt < MAX_RETRIES:
                time.sleep(delay)
                delay *= 2

    logger.error(
        "Email delivery failed after %d attempts: alert_id=%s",
        MAX_RETRIES, payload.alert_id,
    )
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Webhook channel
# ─────────────────────────────────────────────────────────────────────────────

def _sign_payload(body: bytes, secret: str) -> str:
    """HMAC-SHA256 signature for the webhook body."""
    return hmac.new(
        secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()


def _send_webhook_sync(payload: AlertNotificationPayload) -> bool:
    """
    Blocking HTTP POST to the configured WEBHOOK_URL.
    Intended to be called via asyncio.to_thread().
    Returns True on success, False on failure after MAX_RETRIES attempts.
    """
    cfg = _webhook_config()
    if not cfg["url"]:
        logger.debug("Webhook notification skipped — WEBHOOK_URL is not configured")
        return False

    body = json.dumps({
        "event": "alert.created" if not payload.is_escalation else "alert.escalated",
        "alert": payload.to_dict(),
    }).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "AI-NIDS/0.2.0",
    }
    if cfg["secret"]:
        headers["X-NIDS-Signature"] = f"sha256={_sign_payload(body, cfg['secret'])}"

    delay = RETRY_BASE_DELAY
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(
                cfg["url"], data=body, headers=headers, method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
            if 200 <= status < 300:
                logger.info(
                    "Webhook delivered: alert_id=%s status=%d url=%s",
                    payload.alert_id, status, cfg["url"],
                )
                return True
            else:
                logger.warning(
                    "Webhook attempt %d/%d non-2xx status=%d (alert_id=%s)",
                    attempt, MAX_RETRIES, status, payload.alert_id,
                )

        except urllib.error.URLError as exc:
            logger.warning(
                "Webhook attempt %d/%d failed: %s (alert_id=%s)",
                attempt, MAX_RETRIES, exc, payload.alert_id,
            )

        if attempt < MAX_RETRIES:
            time.sleep(delay)
            delay *= 2

    logger.error(
        "Webhook delivery failed after %d attempts: alert_id=%s url=%s",
        MAX_RETRIES, payload.alert_id, cfg["url"],
    )
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Public async API
# ─────────────────────────────────────────────────────────────────────────────

async def notify_alert(payload: AlertNotificationPayload) -> None:
    """
    Fire-and-forget notification for a new alert.

    Dispatches email and webhook concurrently via asyncio.to_thread()
    so neither channel blocks the alert pipeline.

    Only dispatches for HIGH and CRITICAL severity (FR10.2).
    """
    if payload.severity not in NOTIFY_SEVERITIES:
        logger.debug(
            "Notification skipped for severity=%s alert_id=%s",
            payload.severity, payload.alert_id,
        )
        return

    logger.info(
        "Dispatching notifications: alert_id=%s severity=%s attack_type=%s",
        payload.alert_id, payload.severity, payload.attack_type,
    )

    # Run both channels concurrently; swallow exceptions so a channel
    # failure never propagates to the caller (NFR9.3)
    tasks = [
        asyncio.to_thread(_send_email_sync, payload),
        asyncio.to_thread(_send_webhook_sync, payload),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for i, result in enumerate(results):
        channel = "email" if i == 0 else "webhook"
        if isinstance(result, Exception):
            logger.error(
                "Notification channel %s raised unexpected exception: %s (alert_id=%s)",
                channel, result, payload.alert_id,
            )


async def notify_escalation(
    payload: AlertNotificationPayload,
    escalated_by: str,
) -> None:
    """
    Notify for an analyst-triggered escalation action.
    Marks the payload as an escalation so the email subject and body
    reflect the escalation context.
    """
    payload.is_escalation = True
    payload.escalated_by = escalated_by
    await notify_alert(payload)