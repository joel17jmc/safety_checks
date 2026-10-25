"""Append-only JSONL security events with no request parameters or file data."""

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, TypedDict


AUDIT_LOG_PATH = Path(__file__).resolve().parent / "audit.jsonl"
_LOCK = threading.Lock()


class AuditEvent(TypedDict):
    timestamp: str
    action_type: str
    decision: Literal["ALLOW", "BLOCK"]
    reason: str


def record_event(
    action_type: str,
    decision: Literal["ALLOW", "BLOCK"],
    reason: str,
) -> AuditEvent:
    """Write only safe, fixed-format event fields to the audit file."""
    event: AuditEvent = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action_type": action_type,
        "decision": decision,
        "reason": reason,
    }
    line = json.dumps(event, ensure_ascii=True)
    with _LOCK:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG_PATH.open("a", encoding="utf-8") as audit_file:
            audit_file.write(line + "\n")
    return event


def recent_events(limit: int = 20) -> list[AuditEvent]:
    """Read the newest safe event records, newest first."""
    if not AUDIT_LOG_PATH.exists():
        return []

    with _LOCK:
        with AUDIT_LOG_PATH.open("r", encoding="utf-8") as audit_file:
            lines = audit_file.readlines()

    events: list[AuditEvent] = []
    for line in reversed(lines):
        if line.strip():
            raw_event = json.loads(line)
            events.append(
                {
                    "timestamp": raw_event["timestamp"],
                    "action_type": raw_event["action_type"],
                    "decision": raw_event["decision"],
                    "reason": raw_event["reason"],
                }
            )
            if len(events) == limit:
                break
    return events


def event_totals() -> tuple[int, int, int]:
    """Return total, allowed and blocked counts without exposing log details."""
    events = recent_events(limit=2**31 - 1)
    allowed = sum(event["decision"] == "ALLOW" for event in events)
    blocked = sum(event["decision"] == "BLOCK" for event in events)
    return len(events), allowed, blocked
