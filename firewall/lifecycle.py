from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import time
from typing import Any, Optional


class LifecycleEventType(str, Enum):
    ISSUED = "issued"
    DELEGATED = "delegated"
    ATTENUATED = "attenuated"
    USED = "used"
    DENIED = "denied"
    REPLAYED = "replayed"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass(frozen=True)
class LifecycleEvent:
    event_type: LifecycleEventType
    fingerprint: str
    timestamp: float
    agent_id: Optional[str] = None
    capability: Optional[str] = None
    issuer: Optional[str] = None
    reason: str = ""
    request_id: str = ""
    details: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type.value,
            "fingerprint": self.fingerprint,
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "capability": self.capability,
            "issuer": self.issuer,
            "reason": self.reason,
            "request_id": self.request_id,
            "details": (
                None
                if self.details is None
                else dict(self.details)
            ),
        }


class LifecycleRecorder:
    """
    Append-only lifecycle recorder.

    Without a store, events live in memory.

    With a store, every event is persisted immediately
    and can survive recorder/process restart.
    """

    def __init__(
        self,
        *,
        clock=None,
        store=None,
    ):
        self._clock = (
            clock
            if clock is not None
            else time.time
        )

        self._store = store

        self._events: list[
            LifecycleEvent
        ] = []

        # When using persistence, restore existing
        # events so the recorder exposes the complete
        # lifecycle history after restart.
        if self._store is not None:
            self._events.extend(
                self._store.events()
            )

    # ========================================================
    # Record
    # ========================================================

    def record(
        self,
        event_type: LifecycleEventType,
        fingerprint: str,
        *,
        agent_id: Optional[str] = None,
        capability: Optional[str] = None,
        issuer: Optional[str] = None,
        reason: str = "",
        request_id: str = "",
        details: Optional[dict[str, Any]] = None,
    ) -> LifecycleEvent:

        if not isinstance(
            event_type,
            LifecycleEventType,
        ):
            raise TypeError(
                "event_type must be a LifecycleEventType"
            )

        if not isinstance(
            fingerprint,
            str,
        ):
            raise TypeError(
                "fingerprint must be a string"
            )

        fingerprint = fingerprint.strip()

        if not fingerprint:
            raise ValueError(
                "fingerprint cannot be empty"
            )

        if details is not None:

            if not isinstance(
                details,
                dict,
            ):
                raise TypeError(
                    "details must be a dictionary"
                )

            details = dict(details)

        event = LifecycleEvent(
            event_type=event_type,
            fingerprint=fingerprint,
            timestamp=float(
                self._clock()
            ),
            agent_id=agent_id,
            capability=capability,
            issuer=issuer,
            reason=str(reason),
            request_id=request_id,
            details=details,
        )

        # Persist first. If persistence fails, the
        # event must not appear successful in memory.
        if self._store is not None:
            self._store.append(
                event
            )

        self._events.append(
            event
        )

        return event

    # ========================================================
    # Snapshot
    # ========================================================

    def events(
        self,
    ) -> tuple[LifecycleEvent, ...]:
        return tuple(
            self._events
        )

    # ========================================================
    # Filtering
    # ========================================================

    def for_fingerprint(
        self,
        fingerprint: str,
    ) -> tuple[LifecycleEvent, ...]:
        return tuple(
            event
            for event in self._events
            if event.fingerprint
            == fingerprint
        )

    def of_type(
        self,
        event_type: LifecycleEventType,
    ) -> tuple[LifecycleEvent, ...]:
        if not isinstance(
            event_type,
            LifecycleEventType,
        ):
            raise TypeError(
                "event_type must be a LifecycleEventType"
            )

        return tuple(
            event
            for event in self._events
            if event.event_type
            == event_type
        )

    # ========================================================
    # Size
    # ========================================================

    def size(self) -> int:
        return len(
            self._events
        )

    # ========================================================
    # Persistence
    # ========================================================

    @property
    def store(self):
        return self._store

    def close(self) -> None:
        if self._store is not None:
            self._store.close()

    # ========================================================
    # Context manager
    # ========================================================

    def __enter__(self):
        return self

    def __exit__(
        self,
        exc_type,
        exc,
        traceback,
    ):
        self.close()