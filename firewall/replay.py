from __future__ import annotations

import hashlib
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Optional

from firewall.replay_store import (
    SQLiteReplayStore,
)


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
    Replay protection for capability/request use.

    Without a store, state is kept in memory.

    With a SQLiteReplayStore, the persistent store is the
    source of truth and replay state survives SDK restart.
    """

    def __init__(
        self,
        clock=None,
        *,
        store: Optional[
            SQLiteReplayStore
        ] = None,
    ):
        self._clock = (
            clock
            if clock is not None
            else time.time
        )

        self._store = store
        self._lock = threading.RLock()

        self._seen: dict[
            ReplayKey,
            float,
        ] = {}

    def _now(self) -> float:
        return float(
            self._clock()
        )

    def cleanup(self) -> None:
        now = self._now()

        if self._store is not None:
            # The persistent store performs expiry cleanup
            # during consume/lookup. There is no in-memory
            # authority to clean up here.
            with self._lock:
                expired = [
                    key
                    for key, expires_at
                    in self._seen.items()
                    if expires_at <= now
                ]

                for key in expired:
                    del self._seen[key]

            return

        with self._lock:
            expired = [
                key
                for key, expires_at
                in self._seen.items()
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

        False means the replay key has already been consumed
        or the capability validity window has ended.
        """

        if not isinstance(
            key,
            ReplayKey,
        ):
            raise TypeError(
                "key must be a ReplayKey"
            )

        try:
            expires_at = float(
                expires_at
            )
        except (
            TypeError,
            ValueError,
        ) as exc:
            raise TypeError(
                "expires_at must be numeric"
            ) from exc

        now = self._now()

        if expires_at <= now:
            return False

        # ====================================================
        # Persistent mode
        # ====================================================

        if self._store is not None:
            replay_key = key.as_string()

            return self._store.consume(
                replay_key,
                expires_at,
            )

        # ====================================================
        # In-memory mode
        # ====================================================

        self.cleanup()

        with self._lock:
            if key in self._seen:
                return False

            self._seen[key] = (
                expires_at
            )

            return True

    def seen(
        self,
        key: ReplayKey,
    ) -> bool:
        if not isinstance(
            key,
            ReplayKey,
        ):
            raise TypeError(
                "key must be a ReplayKey"
            )

        now = self._now()

        if self._store is not None:
            return self._store.contains(
                key.as_string()
            )

        self.cleanup()

        with self._lock:
            expires_at = self._seen.get(
                key
            )

            if expires_at is None:
                return False

            if expires_at <= now:
                del self._seen[key]
                return False

            return True

    def size(self) -> int:
        if self._store is not None:
            return self._store.size()

        self.cleanup()

        with self._lock:
            return len(
                self._seen
            )

    def clear(self) -> None:
        """
        Clear only in-memory replay state.

        Persistent replay state is intentionally not cleared
        because replay history is security-sensitive and the
        persistent store has no unsafe global reset operation.
        """

        if self._store is not None:
            return

        with self._lock:
            self._seen.clear()

    @property
    def store(
        self,
    ) -> Optional[
        SQLiteReplayStore
    ]:
        return self._store


def generate_nonce() -> str:
    return uuid.uuid4().hex


def capability_replay_fingerprint(
    capability,
) -> str:
    """
    Produce a stable fingerprint from the signed capability.
    """

    payload = (
        capability.signing_payload()
    )

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

    fingerprint = (
        capability_replay_fingerprint(
            capability
        )
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
    return protector.seen(
        key
    )