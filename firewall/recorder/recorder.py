"""The Agent Security Flight Recorder.

A :class:`FlightRecorder` captures the security-relevant lifecycle of an
agent as an ordered chain of :class:`~firewall.recorder.events.SecurityEvent`
records, periodically anchored by signed
:class:`~firewall.recorder.checkpoint.Checkpoint` commitments, and
exports the result as a portable, independently verifiable artifact.

The recorder is *observational by construction*: it records facts it is
handed after the fact and never makes an authorization decision. Wiring
it into :class:`~firewall.sdk.FirewallSDK` records decisions *after*
they exist, so enabling recording cannot change an outcome.

Design properties:

* **Append-only.** Events are immutable once recorded; the chain hash
  makes any later edit, deletion, or reorder detectable.
* **Secrets stay out.** Callers project material security facts. The
  :func:`~firewall.recorder.redact.redact_payload` safety net replaces
  credential-shaped values before hashing, and records what it removed.
* **Bounded work.** Recording is O(1) per event (one hash, an append),
  auto-checkpoint every ``checkpoint_every`` events, and a thread lock so
  concurrent agents can share one recorder.
* **Explicit lifecycle.** A session is started, records accumulate, and
  ``finalize()`` writes the terminal ``session_ended`` event plus a final
  signed checkpoint. An artifact that was never finalized verifies as
  *incomplete* -- never as trustworthy.
"""

from __future__ import annotations

import threading
import time
import uuid
from pathlib import Path
from typing import Any, Iterable, Optional

from firewall.recorder.checkpoint import (
    Checkpoint,
    sign_checkpoint,
)
from firewall.recorder.encoding import canonical_bytes
from firewall.recorder.events import (
    EventType,
    GENESIS_HASH,
    RecorderError,
    SecurityEvent,
    compute_event_hash,
)
from firewall.recorder.identity import (
    RecorderIdentity,
)
from firewall.recorder.redact import (
    REDACTED_PLACEHOLDER,
    redact_payload,
)

#: Default checkpoint cadence: one signed commitment every N events.
DEFAULT_CHECKPOINT_EVERY = 100

#: Ceiling on in-memory events. A recorder is a session capture, not an
#: archive; the durable store for long histories is the artifact itself.
#: ``None`` disables the ceiling.
DEFAULT_MAX_EVENTS = 100_000

#: Label the recorder stamps on itself inside the artifact.
GENERATOR_NAME = "agent-firewall"

#: Human label for the recorded session, kept separate from the agent.
DEFAULT_SESSION_PREFIX = "session"


def _package_version() -> str:
    try:
        from importlib.metadata import version

        return version("agent-firewall-security")
    except Exception:
        return "1.8.0"


class FlightRecorder:
    """Append-only, checkpointed security history for one agent session."""

    def __init__(
        self,
        *,
        session_id: Optional[str] = None,
        agent: Optional[str] = None,
        clock: Any = None,
        identity: Optional[RecorderIdentity] = None,
        checkpoint_every: int = DEFAULT_CHECKPOINT_EVERY,
        max_events: Optional[int] = DEFAULT_MAX_EVENTS,
        generator_version: Optional[str] = None,
    ) -> None:
        if checkpoint_every is not None:
            if isinstance(checkpoint_every, bool) or not isinstance(
                checkpoint_every, int
            ):
                raise RecorderError(
                    "checkpoint_every must be an integer"
                )
            if checkpoint_every <= 0:
                raise RecorderError(
                    "checkpoint_every must be positive"
                )

        if max_events is not None:
            if isinstance(max_events, bool) or not isinstance(
                max_events, int
            ):
                raise RecorderError(
                    "max_events must be an integer"
                )
            if max_events <= 0:
                raise RecorderError(
                    "max_events must be positive"
                )

        self._session_id = (
            session_id
            if session_id is not None
            else f"{DEFAULT_SESSION_PREFIX}-{uuid.uuid4().hex[:12]}"
        )

        if not isinstance(self._session_id, str) or not self._session_id.strip():
            raise RecorderError(
                "session_id must be a non-empty string"
            )

        self._agent = agent
        self._clock = clock if clock is not None else time.time
        self._identity = (
            identity
            if identity is not None
            else RecorderIdentity.generate()
        )
        self._checkpoint_every = checkpoint_every
        self._max_events = max_events
        self._generator_version = (
            generator_version
            if generator_version is not None
            else _package_version()
        )

        self._lock = threading.RLock()
        self._events: list[SecurityEvent] = []
        self._checkpoints: list[Checkpoint] = []
        self._redactions: list[dict[str, Any]] = []
        self._finalized = False
        self._meta: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def agent(self) -> Optional[str]:
        return self._agent

    @property
    def identity(self) -> RecorderIdentity:
        return self._identity

    @property
    def identity_fingerprint(self) -> str:
        return self._identity.fingerprint

    @property
    def finalized(self) -> bool:
        with self._lock:
            return self._finalized

    @property
    def event_count(self) -> int:
        with self._lock:
            return len(self._events)

    @property
    def checkpoint_count(self) -> int:
        with self._lock:
            return len(self._checkpoints)

    def set_meta(self, key: str, value: Any) -> None:
        """Attach safe, un-hashed metadata to the artifact manifest.

        Metadata is *not* part of the hash chain; treat it as labels,
        not evidence.
        """

        from firewall.recorder.encoding import validate_artifact_value

        if not isinstance(key, str) or not key.strip():
            raise RecorderError(
                "meta key must be a non-empty string"
            )

        validate_artifact_value(value)

        with self._lock:
            self._meta[key] = value

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def start(
        self,
        *,
        agent: Optional[str] = None,
        note: Optional[str] = None,
    ) -> SecurityEvent:
        """Begin the session. Returns the ``session_started`` event."""

        with self._lock:
            if self._events:
                raise RecorderError(
                    "session already started"
                )

            if agent is not None:
                self._agent = agent

            payload: dict[str, Any] = {
                "session": self._session_id,
            }
            if note is not None:
                payload["note"] = note

            return self._append(
                EventType.SESSION_STARTED,
                payload,
                agent=self._agent,
            )

    def record(
        self,
        event_type: EventType,
        payload: Optional[dict[str, Any]] = None,
        *,
        agent: Optional[str] = None,
        redact: bool = True,
        redaction_reason: str = "sensitive value",
    ) -> SecurityEvent:
        """Record one event, chaining it to the previous event's hash.

        ``payload`` must be a JSON-serializable mapping of material
        security facts. When ``redact`` is true (default), values under
        credential-shaped key names are replaced with a placeholder
        *before* hashing and the replacements are listed in the artifact
        manifest.

        The session starts automatically on the first record if it has
        not been started explicitly.
        """

        with self._lock:
            if not self._events:
                self._append(
                    EventType.SESSION_STARTED,
                    {"session": self._session_id},
                    agent=self._agent,
                )

            clean = dict(payload or {})

            recorded: dict[str, Any]
            if redact:
                recorded, redactions = redact_payload(
                    clean,
                    reason=redaction_reason,
                )
                for entry in redactions:
                    self._redactions.append(
                        {
                            "seq": len(self._events) + 1,
                            **entry,
                        }
                    )
            else:
                recorded = clean

            event_agent = (
                agent
                if agent is not None
                else self._agent
            )

            return self._append(
                event_type,
                recorded,
                agent=event_agent,
            )

    def checkpoint(self) -> Checkpoint:
        """Force a signed checkpoint at the current chain head.

        Called automatically every ``checkpoint_every`` events; expose it
        so callers can anchor important boundaries (before a finalize,
        before an incident export, after a containment action).
        """

        with self._lock:
            if not self._events:
                raise RecorderError(
                    "cannot checkpoint an empty session"
                )

            last = self._events[-1]

            checkpoint = sign_checkpoint(
                self._identity,
                seq=last.seq,
                event_hash=last.hash,
                event_count=len(self._events),
                timestamp=float(self._clock()),
            )

            self._checkpoints.append(checkpoint)
            return checkpoint

    def finalize(
        self,
        *,
        note: Optional[str] = None,
    ) -> dict[str, Any]:
        """Close the session and return the finished artifact.

        Records the terminal ``session_ended`` event, writes a final
        signed checkpoint, and marks the artifact finalized. After this,
        no more events may be recorded.
        """

        with self._lock:
            if self._finalized:
                raise RecorderError(
                    "session already finalized"
                )

            payload: dict[str, Any] = {
                "session": self._session_id,
            }
            if note is not None:
                payload["note"] = note

            self._append(
                EventType.SESSION_ENDED,
                payload,
                agent=self._agent,
            )

            if (
                not self._checkpoints
                or self._checkpoints[-1].event_count
                != len(self._events)
            ):
                self.checkpoint()

            self._finalized = True
            return self.artifact()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _append(
        self,
        event_type: EventType,
        payload: dict[str, Any],
        agent: Optional[str],
    ) -> SecurityEvent:
        if self._finalized:
            raise RecorderError(
                "cannot record after finalize"
            )

        if (
            self._max_events is not None
            and len(self._events) >= self._max_events
        ):
            raise RecorderError(
                "recorder event ceiling reached"
            )

        prev_hash = (
            self._events[-1].hash
            if self._events
            else GENESIS_HASH
        )

        seq = len(self._events) + 1

        timestamp = float(self._clock())

        event_hash = compute_event_hash(
            seq=seq,
            type=event_type.value,
            timestamp=timestamp,
            session=self._session_id,
            agent=agent,
            payload=payload,
            prev_hash=prev_hash,
        )

        event = SecurityEvent(
            seq=seq,
            type=event_type,
            timestamp=timestamp,
            session=self._session_id,
            agent=agent,
            payload=dict(payload),
            prev_hash=prev_hash,
            hash=event_hash,
        )

        self._events.append(event)

        if (
            self._checkpoint_every is not None
            and seq % self._checkpoint_every == 0
        ):
            self.checkpoint()

        return event

    # ------------------------------------------------------------------
    # Access
    # ------------------------------------------------------------------

    def events(self) -> tuple[SecurityEvent, ...]:
        with self._lock:
            return tuple(self._events)

    def checkpoints(self) -> tuple[Checkpoint, ...]:
        with self._lock:
            return tuple(self._checkpoints)

    def redactions(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(
                dict(entry) for entry in self._redactions
            )

    # ------------------------------------------------------------------
    # Artifact export
    # ------------------------------------------------------------------

    def artifact(self) -> dict[str, Any]:
        """The portable, verifiable artifact for this session.

        Deterministic: the same events always produce the same bytes.
        Contains the full event chain, every signed checkpoint, the
        recorder's public identity (never its private key), session
        metadata, and the redaction manifest.
        """

        with self._lock:
            events = tuple(self._events)

            started_at = (
                events[0].timestamp if events else None
            )
            ended_at = (
                events[-1].timestamp
                if events
                and events[-1].type == EventType.SESSION_ENDED
                else None
            )

            session = {
                "id": self._session_id,
                "agent": self._agent,
                "started_at": started_at,
                "ended_at": ended_at,
                "finalized": self._finalized,
            }

            recorder = {
                "algorithm": "Ed25519",
                "public_key": self._identity.public_b64,
                "fingerprint": self._identity.fingerprint,
            }

            artifact = {
                "afw": 1,
                "format": "agent-firewall-security-artifact",
                "format_version": 1,
                "canonical": "afw-json-1",
                "generator": {
                    "name": GENERATOR_NAME,
                    "version": self._generator_version,
                },
                "session": session,
                "recorder": recorder,
                "events": [
                    event.to_dict() for event in events
                ],
                "checkpoints": [
                    checkpoint.to_dict()
                    for checkpoint in self._checkpoints
                ],
                "redactions": [
                    dict(entry) for entry in self._redactions
                ],
                "meta": dict(self._meta),
            }

            return artifact

    def write(self, path: str | Path) -> Path:
        """Write the artifact to ``path`` with deterministic formatting."""

        import json

        target = Path(path)

        if target.parent and str(target.parent) != ".":
            target.parent.mkdir(parents=True, exist_ok=True)

        data = canonical_bytes(self.artifact())

        # Deterministic pretty-print: sorted keys, fixed indent. The
        # *parsed* document is what verification hashes, so formatting is
        # cosmetic -- but deterministic output keeps diffs reviewable.
        text = json.dumps(
            json.loads(data.decode("utf-8")),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        target.write_text(text + "\n", encoding="utf-8")
        return target

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        return self.event_count

    def __enter__(self) -> "FlightRecorder":
        return self

    def __exit__(
        self,
        exc_type,
        exc,
        traceback,
    ) -> None:
        if not self._finalized:
            try:
                self.finalize()
            except RecorderError:
                pass


def session_from_events(
    events: Iterable[SecurityEvent],
) -> dict[str, Any]:
    """Derive a minimal session summary from recorded events."""

    ordered = tuple(events)
    if not ordered:
        return {
            "id": "",
            "agent": None,
            "started_at": None,
            "ended_at": None,
            "finalized": False,
        }

    return {
        "id": ordered[0].session,
        "agent": ordered[0].agent,
        "started_at": ordered[0].timestamp,
        "ended_at": (
            ordered[-1].timestamp
            if ordered[-1].type == EventType.SESSION_ENDED
            else None
        ),
        "finalized": (
            ordered[-1].type == EventType.SESSION_ENDED
        ),
    }
