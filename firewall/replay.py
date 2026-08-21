from __future__ import annotations

import hashlib
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ReplayKey:
    agent_id: str
    capability_fingerprint: str
    nonce: str

    def as_string(self) -> str:
        return (
            f"{self.agent_id}:"
            f"{self.capability_fingerprint}:"
            f"{self.nonce}"
        )


class ReplayProtector:
    """
    In-memory replay protection for capability/request use.

    A nonce can only be consumed once during its validity window.
    """

    def __init__(self, clock=None):
        self._clock = clock or time.time
        self._lock = threading.RLock()
        self._seen = {}

    def _now(self) -> float:
        return float(self._clock())

    def cleanup(self) -> None:
        now = self._now()

        with self._lock:
            expired = [
                key
                for key, expires_at in self._seen.items()
                if expires_at <= now
            ]

            for key in expired:
                del self._seen[key]

    def check_and_consume(
        self,
        key: ReplayKey,
        expires_at: float,
    ) -> bool:
        """
        Return True only for first use.

        False means the same replay key has already been consumed.
        """

        if not isinstance(key, ReplayKey):
            raise TypeError(
                "key must be a ReplayKey"
            )

        now = self._now()

        if expires_at <= now:
            return False

        self.cleanup()

        with self._lock:
            if key in self._seen:
                return False

            self._seen[key] = float(
                expires_at
            )

            return True

    def seen(
        self,
        key: ReplayKey,
    ) -> bool:
        self.cleanup()

        with self._lock:
            return key in self._seen

    def size(self) -> int:
        self.cleanup()

        with self._lock:
            return len(self._seen)

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()


def generate_nonce() -> str:
    return uuid.uuid4().hex


def capability_replay_fingerprint(
    capability,
) -> str:
    """
    Produce a stable fingerprint from the signed capability.
    """

    payload = capability.signing_payload()

    return hashlib.sha256(
        payload
    ).hexdigest()


def make_replay_key(
    agent_id: str,
    capability,
    nonce: str,
) -> ReplayKey:
    if not isinstance(
        agent_id,
        str,
    ) or not agent_id:
        raise ValueError(
            "agent_id must be a non-empty string"
        )

    if not isinstance(
        nonce,
        str,
    ) or not nonce:
        raise ValueError(
            "nonce must be a non-empty string"
        )

    fingerprint = capability_replay_fingerprint(
        capability
    )

    return ReplayKey(
        agent_id=agent_id,
        capability_fingerprint=fingerprint,
        nonce=nonce,
    )


def is_replay(
    protector: ReplayProtector,
    key: ReplayKey,
) -> bool:
    return protector.seen(key)