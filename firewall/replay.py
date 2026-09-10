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
from firewall.temporal import (
    TEMPORAL_ANOMALY_PREFIX,
    TemporalError,
    sample_temporal,
)


@dataclass(frozen=True)
class _Consumed:
    """One in-memory replay entry, bounded in both time bases.

    ``expires_at`` is the absolute wall deadline the caller supplied, which
    is the right bound for a deadline and the manipulable one for a
    duration: set the clock back and the entry looks live again. ``ttl`` is
    the same window expressed as elapsed time -- ``expires_at`` minus the
    reading at consumption -- and ``monotonic`` / ``generation`` anchor it,
    so the entry expires when *either* bound is reached. With an honest
    clock the two agree; with a rolled-back one, elapsed time is what
    closes the window.

    ``generation`` matters because a monotonic reading from another boot
    cannot be subtracted from this one; an entry whose generation is not
    the current generation is bounded by its wall deadline alone.
    """

    expires_at: float
    ttl: float
    monotonic: Optional[float]
    generation: Optional[str]

    def closed(
        self,
        now: float,
        monotonic: Optional[float],
        generation: Optional[str],
    ) -> bool:
        """Whether either bound has been reached."""

        if now >= self.expires_at:
            return True

        if (
            monotonic is None
            or generation is None
            or self.monotonic is None
            or self.generation is None
            or generation != self.generation
        ):
            return False

        elapsed = monotonic - self.monotonic

        if elapsed < 0:
            # The monotonic clock went backwards inside one generation.
            # The guard refuses such a reading outright; treating it as
            # "no time has passed" here would be the one reading that
            # extends a nonce's life, so the entry is closed instead.
            return True

        return elapsed >= self.ttl


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
            _Consumed,
        ] = {}

    def _now(self) -> float:
        return float(
            self._clock()
        )

    def temporal_context(self):
        """A validated context for this protector's clock.

        Bound to a guard (v3.2) the reading is audited, so a wall clock that
        moved backwards is refused rather than believed; unbound the context
        is marked unprovable, which is how a standalone protector keeps
        working exactly as it did before -- with the wall deadline as its
        only bound, and no claim to a monotonic one it never measured.
        """

        return sample_temporal(
            self,
            name="replay",
            fallback=self._clock,
        )

    def _monotonic_anchor(self):
        """``(monotonic, generation)`` when a guard can supply them.

        ``(None, None)`` for an unguarded protector or an anomalous
        reading: a nonce whose window cannot be measured in the trustworthy
        base keeps the wall bound alone, and the anomalous reading itself is
        refused by the caller before this is consulted.
        """

        try:
            context = self.temporal_context()
        except TemporalError:
            return None, None

        if context.unguarded or not context.provable:
            return None, None

        return context.monotonic, context.generation

    def _context_for_read(self):
        """The context a read is evaluated in, or a refusal reason.

        Returns ``(context, refusal)``. A refusal reason means the clock
        cannot be trusted, and every caller treats that as "not a first
        use": the ledger is consulted for exactly one purpose, and the
        reading that would answer it is the one known to be wrong.
        """

        try:
            context = self.temporal_context()
        except TemporalError:
            return None, "clock_unavailable"

        if not context.unguarded and not context.provable:
            return None, f"{TEMPORAL_ANOMALY_PREFIX}:{context.anomaly}"

        return context, None

    def cleanup(self) -> None:
        """Drop entries whose window has closed in either time base.

        An unreadable clock drops nothing: the entries are refusals, and a
        ledger that empties itself because the clock failed would turn a
        clock fault into a replay hole. They are re-examined on the next
        sweep that can read a clock.
        """

        try:
            context = self.temporal_context()
        except TemporalError:
            return

        monotonic = None
        generation = None

        if context.provable and not context.unguarded:
            monotonic = context.monotonic
            generation = context.generation

        with self._lock:
            expired = [
                key
                for key, entry in self._seen.items()
                if entry.closed(context.wall, monotonic, generation)
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

        # The window is read inside an audited context (v3.2). A clock that
        # cannot be read, or one that just moved backwards, is a refusal
        # here rather than a comparison: this method's only job is to answer
        # "is this nonce's window live?", and a reading known to be wrong
        # cannot answer it. The refusal is reported as *not* a first use,
        # which is the direction that cannot widen anything.
        context, refusal = self._context_for_read()

        if refusal is not None:
            return False

        now = context.wall

        if expires_at <= now:
            return False

        # ====================================================
        # Persistent mode
        # ====================================================

        if self._store is not None:
            replay_key = key.as_string()

            # The durable ledger owns the window once one is wired: its row
            # carries the wall deadline and its primary key is what makes
            # the exactly-once property survive a restart. The guard still
            # audits the clock above, so a regression refuses here rather
            # than being compared against.
            return self._store.consume(
                replay_key,
                expires_at,
            )

        # ====================================================
        # In-memory mode
        # ====================================================

        self.cleanup()

        monotonic, generation = (
            (context.monotonic, context.generation)
            if context.provable and not context.unguarded
            else (None, None)
        )

        with self._lock:
            if key in self._seen:
                return False

            self._seen[key] = _Consumed(
                expires_at=expires_at,
                ttl=max(0.0, expires_at - now),
                monotonic=monotonic,
                generation=generation,
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

        context, refusal = self._context_for_read()

        if refusal is not None:
            # An untrustworthy clock is reported as "already seen": the
            # caller uses this to refuse a request, and a refusal is the
            # only answer this method may give when it cannot read the
            # window it is asked about.
            return True

        if self._store is not None:
            return self._store.contains(
                key.as_string()
            )

        self.cleanup()

        monotonic = None
        generation = None

        if context.provable and not context.unguarded:
            monotonic = context.monotonic
            generation = context.generation

        with self._lock:
            entry = self._seen.get(
                key
            )

            if entry is None:
                return False

            if entry.closed(context.wall, monotonic, generation):
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