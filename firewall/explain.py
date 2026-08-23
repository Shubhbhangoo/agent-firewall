from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from firewall.lifecycle import (
    LifecycleEvent,
    LifecycleEventType,
    LifecycleRecorder,
)


@dataclass(frozen=True)
class LifecycleExplanation:
    fingerprint: str
    events: tuple[LifecycleEvent, ...]

    @property
    def exists(self) -> bool:
        return bool(self.events)

    @property
    def latest(self) -> Optional[LifecycleEvent]:
        if not self.events:
            return None
        return self.events[-1]

    @property
    def latest_type(
        self,
    ) -> Optional[LifecycleEventType]:
        latest = self.latest
        if latest is None:
            return None
        return latest.event_type

    @property
    def revoked(self) -> bool:
        return any(
            event.event_type
            == LifecycleEventType.REVOKED
            for event in self.events
        )

    @property
    def expired(self) -> bool:
        return any(
            event.event_type
            == LifecycleEventType.EXPIRED
            for event in self.events
        )

    @property
    def denied(self) -> bool:
        return any(
            event.event_type
            == LifecycleEventType.DENIED
            for event in self.events
        )

    @property
    def used(self) -> bool:
        return any(
            event.event_type
            == LifecycleEventType.USED
            for event in self.events
        )

    @property
    def replayed(self) -> bool:
        return any(
            event.event_type
            == LifecycleEventType.REPLAYED
            for event in self.events
        )

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "exists": self.exists,
            "latest_type": (
                None
                if self.latest_type is None
                else self.latest_type.value
            ),
            "revoked": self.revoked,
            "expired": self.expired,
            "denied": self.denied,
            "used": self.used,
            "replayed": self.replayed,
            "events": [
                event.to_dict()
                for event in self.events
            ],
        }


def explain(
    recorder: LifecycleRecorder,
    fingerprint: str,
) -> LifecycleExplanation:
    if not isinstance(
        recorder,
        LifecycleRecorder,
    ):
        raise TypeError(
            "recorder must be a LifecycleRecorder"
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

    return LifecycleExplanation(
        fingerprint=fingerprint,
        events=recorder.for_fingerprint(
            fingerprint
        ),
    )


def explain_request(
    recorder: LifecycleRecorder,
    request_id: str,
) -> tuple[LifecycleEvent, ...]:
    if not isinstance(
        recorder,
        LifecycleRecorder,
    ):
        raise TypeError(
            "recorder must be a LifecycleRecorder"
        )

    if not isinstance(
        request_id,
        str,
    ):
        raise TypeError(
            "request_id must be a string"
        )

    request_id = request_id.strip()

    if not request_id:
        raise ValueError(
            "request_id cannot be empty"
        )

    return tuple(
        event
        for event in recorder.events()
        if event.request_id
        == request_id
    )