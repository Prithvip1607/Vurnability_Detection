"""Timestamp helpers. Source timestamps arrive in mixed formats (RFC-2822 from
RSS, ISO-8601 from NVD/GitHub); everything is normalised to aware UTC here."""
from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime


def parse_ts(value) -> datetime | None:
    """Parse an ISO-8601 or RFC-2822 timestamp into an aware UTC datetime.

    Returns None when the value is empty or unparseable -- callers must never
    fabricate a timestamp.
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        s = str(value).strip()
        dt = None
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            try:
                dt = parsedate_to_datetime(s)
            except (TypeError, ValueError, IndexError):
                return None
        if dt is None:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def format_duration(seconds: float | None) -> str | None:
    """7h 25m style duration; None stays None."""
    if seconds is None:
        return None
    sign = "-" if seconds < 0 else ""
    seconds = abs(int(seconds))
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    parts = []
    if d:
        parts.append(f"{d}d")
    if h or d:
        parts.append(f"{h}h")
    parts.append(f"{m}m")
    return sign + " ".join(parts)
