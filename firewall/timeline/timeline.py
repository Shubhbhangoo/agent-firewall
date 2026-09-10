"""The agent security timeline (v1.8).

A timeline turns an artifact's raw event chain into the security story
of a session: a flat, chronological, human-readable list where every
entry is inspectable and every entry links back to the exact event (and
from there to the authority chain, the decision, and the evidence) that
produced it.

Every entry is *derived* from recorded events. Nothing here interprets
beyond what the artifact says; the timeline is a projection, and its
source of truth is the hash chain.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional

from firewall.artifact import validate_manifest
from firewall.recorder.events import EventType, SecurityEvent


@dataclass(frozen=True)
class TimelineEntry:
    """One line of the security story, bound to one recorded event."""

    seq: int
    timestamp: float
    kind: str
    title: str
    detail: str
    event_type: str
    agent: Optional[str]
    severity: str
    refs: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "kind": self.kind,
            "title": self.title,
            "detail": self.detail,
            "event_type": self.event_type,
            "agent": self.agent,
            "severity": self.severity,
            "refs": dict(self.refs),
        }


def _fmt_time(timestamp: float) -> str:
    import datetime

    try:
        return datetime.datetime.fromtimestamp(
            timestamp
        ).strftime("%H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return f"{timestamp:.3f}"


def summarize_event(
    event: SecurityEvent,
) -> tuple[str, str, str, dict[str, Any], str]:
    """Return ``(kind, title, detail, refs, severity)`` for one event."""

    payload = event.payload or {}
    agent = event.agent or payload.get("agent") or "system"

    if event.type == EventType.SESSION_STARTED:
        return (
            "lifecycle",
            "Session started",
            f"Recording began for {agent}.",
            {},
            "info",
        )

    if event.type == EventType.SESSION_ENDED:
        return (
            "lifecycle",
            "Session ended",
            f"Recording closed for {agent}.",
            {},
            "info",
        )

    if event.type == EventType.AGENT_INITIALIZED:
        return (
            "lifecycle",
            "Agent initialized",
            f"{agent} came online.",
            {},
            "info",
        )

    if event.type == EventType.IDENTITY_BOUND:
        return (
            "lifecycle",
            "Identity bound",
            f"{agent} was bound to an identity.",
            {},
            "info",
        )

    if event.type == EventType.AUTHORITY_ISSUED:
        capability = payload.get("capability") or "?"
        issuer = payload.get("issuer") or "?"
        tool = payload.get("tool")
        detail = (
            f"{issuer} issued {capability} to {agent}."
            + (f" Bound to tool {tool}." if tool else "")
        )
        return (
            "authority",
            "Capability issued",
            detail,
            {"authority": [event.seq]},
            "notice",
        )

    if event.type == EventType.AUTHORITY_DELEGATED:
        capability = payload.get("capability") or "?"
        delegatee = payload.get("delegatee") or "?"
        return (
            "authority",
            "Authority delegated",
            f"{agent} delegated {capability} to {delegatee}.",
            {"authority": [event.seq]},
            "notice",
        )

    if event.type == EventType.AUTHORITY_ATTENUATED:
        capability = payload.get("capability") or "?"
        return (
            "authority",
            "Authority attenuated",
            f"{capability} was narrowed for {agent}.",
            {"authority": [event.seq]},
            "notice",
        )

    if event.type == EventType.AUTHORITY_REVOKED:
        capability = payload.get("capability") or (
            payload.get("fingerprint") or ""
        )[:12]
        reason = payload.get("reason") or "no reason recorded"
        return (
            "authority",
            "Capability revoked",
            f"{capability} was revoked from {agent}: {reason}.",
            {"authority": [event.seq]},
            "critical",
        )

    if event.type == EventType.POLICY_ACTIVE:
        name = payload.get("policy") or payload.get("name") or "?"
        return (
            "policy",
            "Policy active",
            f"Policy {name} was in force.",
            {"policy": [event.seq]},
            "info",
        )

    if event.type == EventType.AUTHORIZATION:
        action = payload.get("action") or "?"
        allowed = bool(payload.get("allowed"))
        reason = payload.get("reason") or "?"
        depth = payload.get("depth")
        capability = payload.get("capability") or "?"

        refs: dict[str, Any] = {
            "decision": event.seq,
            "authority": [],
            "evidence": [event.seq],
        }

        chain = payload.get("chain")

        if isinstance(chain, list):
            refs["authority"] = [
                event.seq - offset
                for offset in range(len(chain))
                if event.seq - offset >= 1
            ]

        if allowed:
            title = "Action allowed"
            severity = "info"
            detail = (
                f"{agent} was allowed to {action} "
                f"(capability {capability})"
                + (f", delegation depth {depth}" if depth else "")
                + "."
            )
        else:
            title = "Action denied"
            severity = "warning"
            detail = f"{agent} was denied {action}: {reason}."

        return (
            "authorization",
            title,
            detail,
            refs,
            severity,
        )

    if event.type == EventType.TOOL_RESULT:
        tool = payload.get("tool") or "?"
        return (
            "tool",
            "Tool result",
            f"{agent} received a result from {tool}.",
            {"evidence": [event.seq]},
            "info",
        )

    if event.type == EventType.SECURITY_STATE:
        change = payload.get("change") or "state change"
        return (
            "state",
            "Security state changed",
            f"{agent}: {change}.",
            {"evidence": [event.seq]},
            "warning",
        )

    if event.type == EventType.CONTAINMENT:
        action = payload.get("action") or "?"
        state = payload.get("state") or "?"
        reason = payload.get("reason") or ""
        detail = (
            f"Containment {action} -> {state} for {agent}."
            + (f" {reason}" if reason else "")
        )
        return (
            "containment",
            f"Containment: {action}",
            detail,
            {"evidence": [event.seq]},
            "critical",
        )

    if event.type == EventType.RISK_CHANGED:
        level = payload.get("level") or "?"
        return (
            "state",
            "Risk changed",
            f"Risk for {agent} is now {level}.",
            {"evidence": [event.seq]},
            "warning",
        )

    if event.type == EventType.NOTE:
        return (
            "note",
            "Note",
            str(payload.get("text") or "..."),
            {},
            "info",
        )

    return (
        "lifecycle",
        event_type.replace("_", " ").title(),
        str(payload or ""),
        {},
        "info",
    )


def build_timeline(
    artifact: dict[str, Any],
) -> tuple[TimelineEntry, ...]:
    """Build the security timeline for an artifact."""

    validate_manifest(artifact)

    entries: list[TimelineEntry] = []

    for entry in artifact.get("events", []):
        try:
            event = SecurityEvent.from_dict(entry)
        except Exception:
            # A malformed event is a verifier problem; the timeline
            # still renders the events that are well-formed.
            continue

        kind, title, detail, refs, severity = summarize_event(
            event
        )

        entries.append(
            TimelineEntry(
                seq=event.seq,
                timestamp=event.timestamp,
                kind=kind,
                title=title,
                detail=detail,
                event_type=event.type.value,
                agent=event.agent,
                severity=severity,
                refs=refs,
            )
        )

    return tuple(entries)


def timeline_to_text(
    entries: Iterable[TimelineEntry],
) -> str:
    """Render a timeline as plain text lines."""

    lines = []

    for entry in entries:
        lines.append(
            f"{_fmt_time(entry.timestamp)}  "
            f"{entry.severity.upper():8} "
            f"{entry.title}: {entry.detail}"
        )

    return "\n".join(lines)
