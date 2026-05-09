"""
Notification dispatcher — console log + Slack/Discord webhook + SMTP email.
Every channel fires in a background thread so it never blocks the pipeline.
"""
from __future__ import annotations

import smtplib
import threading
from datetime import datetime, timezone
from email.mime.text import MIMEText

import requests

from config.settings import (
    WEBHOOK_URL, ALERT_EMAIL_TO, ALERT_EMAIL_FROM,
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS,
    NOTIFY_MIN_SCORE, NOTIFY_SEVERITY_FILTER,
)
from utils.audit  import audit, EV_NOTIFICATION_SENT, EV_NOTIFICATION_FAIL
from utils.logger import get_logger

logger = get_logger("notifier")


def dispatch(event: dict) -> None:
    threading.Thread(target=_dispatch_all, args=(event,), daemon=True).start()


def dispatch_trending(trending_event: dict) -> None:
    event = {
        "type":          "trending_cve",
        "cve_id":        trending_event.get("cve_id"),
        "title":         (
            f"{trending_event['cve_id']} trending — "
            f"{trending_event['mention_count']} mentions in {trending_event['window_hours']}h"
        ),
        "platform":      ", ".join(trending_event.get("sources", [])),
        "url":           trending_event.get("latest_item", {}).get("url", ""),
        "signal_score":  trending_event.get("latest_item", {}).get("signal_score", 0),
        "severity":      "",
        "sources":       trending_event.get("sources", []),
        "mention_count": trending_event.get("mention_count", 0),
        "detected_at":   trending_event.get("detected_at", datetime.now(timezone.utc).isoformat()),
    }
    audit("trending_detected",
          cve_id=trending_event.get("cve_id"),
          mentions=trending_event.get("mention_count"),
          sources=trending_event.get("sources", []),
          window_hours=trending_event.get("window_hours"))
    dispatch(event)


def _should_notify(event: dict) -> bool:
    if event.get("type") == "trending_cve":
        return True
    if event.get("signal_score", 0) < NOTIFY_MIN_SCORE:
        return False
    severity = event.get("severity", "").upper()
    if NOTIFY_SEVERITY_FILTER and severity not in NOTIFY_SEVERITY_FILTER:
        return False
    return True


def _dispatch_all(event: dict) -> None:
    if not _should_notify(event):
        return
    _log_console(event)
    if WEBHOOK_URL:
        _send_webhook(event)
    if ALERT_EMAIL_TO and SMTP_HOST:
        _send_email(event)


def _log_console(event: dict) -> None:
    emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(
        event.get("severity", "").upper(), "⚪"
    )
    logger.info(
        "%s [%s] %s | score=%s severity=%s platform=%s | %s",
        emoji,
        event.get("type", "event").upper().replace("_", " "),
        event.get("cve_id") or "NO-CVE",
        event.get("signal_score", "?"),
        event.get("severity", "?"),
        event.get("platform", "?"),
        event.get("title", "")[:100],
    )


def _send_webhook(event: dict) -> None:
    emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(
        event.get("severity", "").upper(), "⚪"
    )
    try:
        payload = {
            "text": (
                f"{emoji} *{event.get('type', 'ALERT').replace('_', ' ').upper()}*\n"
                f"*{event.get('cve_id') or 'Zero-Day Candidate'}* — {event.get('title', '')[:120]}\n"
                f"Platform: `{event.get('platform', '?')}` | "
                f"Score: `{event.get('signal_score', '?')}` | "
                f"Severity: `{event.get('severity', '?')}`\n"
                f"{event.get('url', '')}"
            )
        }
        requests.post(WEBHOOK_URL, json=payload, timeout=10)
        audit(EV_NOTIFICATION_SENT, channel="webhook",
              cve_id=event.get("cve_id"), event_type=event.get("type"))
    except Exception as e:
        logger.error("Webhook failed: %s", e)
        audit(EV_NOTIFICATION_FAIL, channel="webhook", message=str(e))


def _send_email(event: dict) -> None:
    try:
        subject = (
            f"[EVVP] {event.get('type', 'ALERT').replace('_', ' ').title()} — "
            f"{event.get('cve_id') or 'Zero-Day'}"
        )
        body = (
            f"Type:     {event.get('type', '')}\n"
            f"CVE:      {event.get('cve_id') or 'None (zero-day candidate)'}\n"
            f"Title:    {event.get('title', '')}\n"
            f"Platform: {event.get('platform', '')}\n"
            f"Score:    {event.get('signal_score', '')}\n"
            f"Severity: {event.get('severity', '')}\n"
            f"URL:      {event.get('url', '')}\n"
            f"Time:     {event.get('detected_at', '')}\n"
        )
        msg            = MIMEText(body)
        msg["Subject"] = subject
        msg["From"]    = ALERT_EMAIL_FROM
        msg["To"]      = ALERT_EMAIL_TO
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            if SMTP_USER and SMTP_PASS:
                s.starttls()
                s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        audit(EV_NOTIFICATION_SENT, channel="email",
              cve_id=event.get("cve_id"), event_type=event.get("type"))
    except Exception as e:
        logger.error("Email failed: %s", e)
        audit(EV_NOTIFICATION_FAIL, channel="email", message=str(e))
