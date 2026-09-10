"""Temporal security integrity: the time base a verdict is valid in.

Every release before this one bounded *what* a decision may rest on --
authority, provenance, evidence, verification, external attestation, the
coherence of the security state -- and none of them bounded *when*. A
capability window was compared against whatever ``time.time()`` said; a
lease deadline was stamped from a clock the firewall does not own; an
attestation's maximum age was measured in wall seconds; a replay ledger
entry expired when wall time passed its recorded deadline. Those are all
the same weakness reached through different doors:

    a decision that was valid when it was made can be made to look valid
    again by moving the clock the decision is compared against.

v3.2 states the property and builds the layer that establishes it:

    A security decision is valid only within a provable temporal context.

**Two kinds of time, and only one of them is trustworthy for each job.**
The distinction is the whole design, and getting it wrong is the classic
bug this module exists to make impossible:

* **Absolute instants are wall-clock facts.** A capability's
  ``expires_at`` was signed by an issuer at some instant in calendar time;
  it can only be compared against calendar time. Nothing here changes
  that, and nothing could -- an issuer's deadline is not the firewall's to
  re-base.
* **Relative durations are monotonic facts.** "This lease is good for 60
  seconds", "this attestation is no older than 300 seconds", "this nonce
  is replayable for the capability's remaining lifetime" are statements
  about *elapsed* time. Measuring them against wall time is the defect:
  elapsed time read from a clock an attacker can set backwards makes a
  60-second lease outlive any wall deadline it is compared against.

So :class:`TemporalGuard` samples both, keeps both, and every window it
builds is anchored in both. A window is *covered* when the context is
inside the wall deadline **and** inside the monotonic budget, and the
monotonic budget is what survives a wall clock that moves backwards.

**An anomaly is a refusal.** The guard records, per named time source,
the highest wall reading and the highest monotonic reading it has ever
seen, and compares each new sample against them:

* a **monotonic regression** is impossible from a real monotonic clock,
  so seeing one means the time source itself is not what it claims;
* a **wall regression** past the tolerance means either a clock that was
  set backwards or a store file from the future, and either way every
  window measured against that clock is longer than the deployment
  asked for -- so the sample is marked anomalous;
* a **forward jump** is *not* an anomaly. Time moving forward can only
  expire things, and this layer's job is to make refusals possible, never
  to avoid them;
* a **cross-restart regression** is the durable form of the same: when
  the guard has a store, the previous process generation's highest wall
  reading is a floor, and a boot below it marks every sample anomalous
  until an operator reconciles the clock. A restarted process that
  believes it is earlier than the process it replaced is exactly the
  time-machine attack, one generation wide.

Denying is not merely the safe reading of a regression; it is the only
reading that preserves the property. A firewall that decides inside a
rolled-back clock has authorized an action against a temporal context
that never existed.

**Per-source history, because there are several clocks.** The SDK owns a
clock, each store may own one, and a deployment may inject others. The
guard keys its watermarks by a *name* the caller supplies, so a test
clock at 3000 and a real platform clock at 1.7e9 never compare against
each other -- comparing them would produce an anomaly out of arithmetic
rather than out of an attack, which is how a security check becomes noise
people turn off. Each named source is audited on its own terms, and every
`TemporalContext` records which source produced it, so a window's
authority is attributable after the fact.

**Restart semantics, stated rather than implied.** A monotonic clock is
per-boot: on Windows it starts near zero, on Linux it counts since boot.
A window that spans a restart therefore cannot use its monotonic half,
and the guard says so instead of pretending otherwise -- the wall
deadline and the persisted wall floor govern, and the monotonic budget is
skipped *only* for a window whose recorded generation is a different
process generation. Within one generation the monotonic budget always
applies, and it can only shorten a window.

**What this layer cannot do.** It cannot make an untrusted clock
trustworthy, and it cannot see the world. A deployment whose host clock is
under an attacker's control before the firewall starts has handed over
the absolute half of every window; the durable floor raises that bar from
"restart the process" to "rewrite the watermark store too, and never let
the real time catch up". A monotonic clock is not signed, so a process
that can rewrite both its own memory and the platform's monotonic source
is outside every defence in this package. And this module grants nothing:
it constructs no ``AuthorizationResult``, it is not on the ALLOW path as
an authority, and every one of its verdicts is a *refusal*. Time is a
constraint on decisions that other layers already made.

Nothing here may weaken fail-closed behaviour. Temporal authority is
read-only: an unreadable clock, an unreadable watermark or an anomaly
produces a named denial at every call site, never a pass and never a
silent fallback to wall time.
"""

from __future__ import annotations

import hashlib
import math
import threading
import time
import uuid
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Iterator, Optional

#: The generation label a context carries when the component that produced
#: it is bound to no guard.
#:
#: It exists so "nobody measured this" is distinguishable from "this reading
#: is suspect". A standalone store constructed without an SDK is not inside
#: anybody's temporal boundary -- that is the pre-v3.2 behaviour, honestly
#: labelled -- while a store bound to a guard whose clock regressed is a
#: refusal. Collapsing the two would either break every standalone store or
#: silently treat a manipulated clock as unmeasured.
UNGUARDED_GENERATION = "unguarded"

#: The denial-reason prefix the boundary uses when the temporal context is
#: not provable. Declared here so callers partitioning verdicts by cause
#: can ask ``reason.startswith(TEMPORAL_ANOMALY_PREFIX)`` instead of
#: embedding the literal, and so the adversarial suite can assert on it
#: without duplicating a string that must not drift.
TEMPORAL_ANOMALY_PREFIX = "temporal_anomaly"

#: The reason a window that has closed reports.
TEMPORAL_WINDOW_CLOSED = "temporal_window_expired"

#: How much regression is tolerated before a sample is anomalous, in
#: seconds. ``None`` -- the default -- means "one quantum of the platform's
#: own clocks", resolved by :func:`platform_clock_quantum`.
#:
#: The quantum rather than zero, and the reason is a measurement rather than
#: a preference. A clock cannot differ from itself by less than its own
#: granularity, so a sub-quantum movement carries no information: it is two
#: readings of the same tick, not a clock that moved. On this development
#: platform `time.time()` is quantised at 15.6 ms and 1192 of 320 000
#: readings taken by eight threads landed *below* a strict high-water mark of
#: the same clock (largest 10.2 ms), while `time.monotonic()` did the same in
#: 754 of 320 000 (largest 16.0 ms). A zero default therefore classified an
#: unmanipulated platform clock as an attack and refused legitimate requests
#: -- the failure mode this package refuses to ship, because a security check
#: that cries wolf is one people turn off.
#:
#: What it tolerates is bounded and stated: on this platform one quantum
#: (15.6 ms); on a platform whose clocks have nanosecond resolution it
#: resolves to nanoseconds. A real rollback -- seconds, minutes, or the
#: time-machine restart the durable watermark exists for -- is orders of
#: magnitude larger and is always an anomaly. A deployment whose platform
#: steps its clock with NTP passes an explicit number, which is a decision
#: with a value attached rather than a default nobody read.
#:
#: Note what it does *not* affect: a window's relative budget is never
#: relaxed by tolerance, because the budget is measured against elapsed time
#: and tolerance applies to the *comparison* of readings, not to the length
#: of a window.
DEFAULT_REGRESSION_TOLERANCE_SECONDS: Optional[float] = None

#: The clock used for elapsed time when the caller names none.
#:
#: ``perf_counter`` rather than ``monotonic``, because it is the platform's
#: highest-resolution monotone clock and the difference is measurable: on
#: this machine ``monotonic`` is quantised at 15.6 ms and jitters below a
#: strict high-water mark under concurrency, while ``perf_counter`` measured
#: zero backward readings at 1e-07 resolution. Elapsed budgets are the one
#: place where resolution is the whole point, so the finer clock is the
#: default and ``monotonic`` is the fallback.
MONOTONIC_CLOCK_FALLBACK = "monotonic"


def _resolution(name: str) -> float:
    """The platform's reported resolution for one clock, or ``0.0``."""

    try:
        value = float(time.get_clock_info(name).resolution)
    except Exception:  # noqa: BLE001 - an unknown clock is no resolution
        return 0.0

    if not math.isfinite(value) or value < 0:
        return 0.0

    return value


def platform_clock_quantum() -> float:
    """One quantum of the platform clocks this layer may compare.

    The largest resolution among the wall clock and the monotone clocks,
    because a comparison is only as precise as its coarsest reading. Used as
    the default regression tolerance: see
    :data:`DEFAULT_REGRESSION_TOLERANCE_SECONDS`.
    """

    return max(
        _resolution("time"),
        _resolution(MONOTONIC_CLOCK_FALLBACK),
        _resolution("perf_counter"),
    )


def default_monotonic_clock() -> Callable[[], float]:
    """The highest-resolution monotone clock this platform offers."""

    counter = getattr(time, "perf_counter", None)

    if callable(counter):
        return counter

    return time.monotonic

#: The helper name the census recognises at a call site, mirroring
#: :data:`firewall.authority_epoch.EPOCH_BRACKET_HELPERS` and
#: :data:`firewall.state_commit.STATE_COMMIT_HELPER`.
TEMPORAL_SAMPLE_HELPER = "observe_temporal"

#: Every function that evaluates a validity window, and therefore must do
#: it through the guard.
#:
#: A census, not a description: ``TEMPORAL_SECURITY_INTEGRITY`` checks it
#: in **both** directions. A function listed here that evaluates no window
#: through the guard is a violation, and an evaluation anywhere else in
#: the package is also one. The second direction is the one that matters
#: over time -- a later change cannot quietly add a window comparison
#: somewhere the temporal context is not established, because the census
#: literal is where the sentence "these are all of them" is recorded.
TEMPORAL_WINDOW_SITES = frozenset(
    {
        # Authorization: the capability window, evaluated against a
        # guard-validated context, and re-evaluated at the commit.
        ("firewall/sdk.py", "FirewallSDK._gate_time"),
        ("firewall/sdk.py", "FirewallSDK._gate_transaction"),
        # Execution: the lease's wall deadline and its monotonic budget.
        ("firewall/sdk.py", "FirewallSDK._continuity_failure"),
        # Execution: the lapse sweep, which decides nothing else.
        ("firewall/execution_lease.py", "ExecutionLeaseStore.expire_lapsed"),
        # Side effects: the durable intent's window before an attempt.
        ("firewall/effect.py", "EffectJournal.expire_lapsed"),
        # Attestation: the issuer's window and the deployment's max age.
        ("firewall/external_attestation.py", "AttestationJournal.check_window"),
    }
)

#: Names that may not appear in a source label, because labels are part of
#: the persisted watermark key and of every recorded context.
_RESERVED_LABEL_CHARS = frozenset("=;\x00\x1f\n")


class TemporalError(Exception):
    """The temporal context could not be established.

    Raised by :meth:`TemporalGuard.sample` when a time source cannot be
    read or returns a non-finite value. Every enforcement call site turns
    it into a named denial -- an unreadable clock is not a permissive
    one -- so it is never a verdict and never propagates to a caller as a
    decision.
    """


def _validate_label(name: Any, what: str) -> str:
    if not isinstance(name, str) or not name.strip():
        raise ValueError(f"a temporal {what} must be a non-empty string")

    if _RESERVED_LABEL_CHARS & set(name):
        raise ValueError(
            f"a temporal {what} may not contain any of "
            f"{sorted(_RESERVED_LABEL_CHARS)}"
        )

    return name


# =====================================================================
# Observations
# =====================================================================


@dataclass(frozen=True)
class TemporalContext:
    """One validated reading of one named time source.

    ``wall`` is calendar time, ``monotonic`` is elapsed-time-since-boot,
    and ``sequence`` is this source's sample counter within the process
    generation. ``generation`` names the process generation the monotonic
    reading belongs to: two contexts from different generations cannot be
    subtracted, and the guard refuses to pretend otherwise.

    ``anomaly`` is the guard's verdict on *this* sample -- ``None`` when
    the reading agreed with the source's own history, otherwise a reason
    such as ``wall_regression``. Carrying it on the observation rather
    than in a side channel means a caller cannot hold a context and be
    unaware that it was anomalous; every window evaluation checks it, and
    a context that was anomalous never covers a window.
    """

    wall: float
    monotonic: float
    sequence: int
    generation: str
    source: str
    anomaly: Optional[str] = None

    @property
    def provable(self) -> bool:
        """True only when this reading is a temporal context at all."""

        return self.anomaly is None

    @property
    def unguarded(self) -> bool:
        """True when no guard produced this reading.

        A component with no guard has no temporal boundary: there is no
        watermark to compare against and no generation to subtract a
        monotonic reading within. That is a fact about the *configuration*,
        not a suspicion about the clock, and the distinction is
        load-bearing -- a caller must be able to answer "is this untrusted
        or unmeasured?" differently, because one is an operator's
        reconcile-the-clock problem and the other is a wiring choice.
        """

        return self.generation == UNGUARDED_GENERATION

    def to_dict(self) -> dict[str, Any]:
        return {
            "wall": self.wall,
            "monotonic": self.monotonic,
            "sequence": self.sequence,
            "generation": self.generation,
            "source": self.source,
            "anomaly": self.anomaly,
        }


@dataclass(frozen=True)
class TemporalWindow:
    """A validity window anchored in both wall and monotonic time.

    Built by the guard, never by hand, so it cannot be anchored at an
    instant the guard never validated. Two anchors, because the two
    questions a window answers are different questions:

    * ``deadline_wall`` -- the absolute instant the window closes, when
      the window has one that came from outside (an issuer-signed
      ``expires_at``, a store row written by an earlier generation). It is
      compared against a *validated* wall reading.
    * ``opened_monotonic`` + ``ttl`` -- the relative budget the window was
      created with. It is compared against elapsed monotonic time, so a
      wall clock that moves backwards cannot extend it.

    ``covers`` requires both, and the monotonic half is skipped only when
    the window's generation is not the current one -- which is exactly the
    restart case, where a monotonic reading from another boot means
    nothing at all.
    """

    source: str
    generation: str
    opened_wall: float
    opened_monotonic: float
    ttl: Optional[float] = None
    deadline_wall: Optional[float] = None

    def elapsed(self, context: TemporalContext) -> Optional[float]:
        """Monotonic seconds since the window opened; ``None`` across a
        generation boundary, where the question has no answer."""

        if context.generation != self.generation:
            return None
        return context.monotonic - self.opened_monotonic

    def age(self, context: TemporalContext) -> Optional[float]:
        """Wall seconds since the window opened; ``None`` if incomparable."""

        if not isinstance(context.wall, (int, float)):
            return None
        return context.wall - self.opened_wall

    def close_reason(
        self,
        context: TemporalContext,
        *,
        tolerance: float = 0.0,
    ) -> Optional[str]:
        """Why ``context`` is outside this window, or ``None``.

        Ordered so the most specific and most dangerous answer comes
        first: an anomalous context never covers a window, whatever the
        arithmetic says. Then the monotonic budget -- the half that a
        wall clock cannot move -- and only then the absolute deadline.
        The order matters for the reason it is recorded: a
        ``wall_regression`` refusal says the clock is not trustworthy,
        while a ``temporal_window_expired`` says it is and the window
        simply closed, and an operator fixes those differently.
        """

        if not context.provable:
            return context.anomaly or "temporal_context_unprovable"

        elapsed = self.elapsed(context)

        if self.ttl is not None and elapsed is not None:
            if elapsed > self.ttl + tolerance:
                return TEMPORAL_WINDOW_CLOSED

        if self.deadline_wall is not None:
            if context.wall - tolerance > self.deadline_wall:
                return TEMPORAL_WINDOW_CLOSED

        return None

    def covers(
        self,
        context: TemporalContext,
        *,
        tolerance: float = 0.0,
    ) -> bool:
        return self.close_reason(context, tolerance=tolerance) is None

    def remaining(self, context: TemporalContext) -> Optional[float]:
        """Monotonic seconds left on the relative budget, when there is
        one and the generations agree. Never negative-widening: an expired
        budget reports ``0.0`` rather than a negative number a caller
        might add back."""

        if self.ttl is None:
            return None

        elapsed = self.elapsed(context)

        if elapsed is None:
            return None

        return max(0.0, self.ttl - elapsed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "generation": self.generation,
            "opened_wall": self.opened_wall,
            "opened_monotonic": self.opened_monotonic,
            "ttl": self.ttl,
            "deadline_wall": self.deadline_wall,
        }

    @classmethod
    def from_dict(cls, payload: Any) -> "TemporalWindow":
        """Reconstruct a window, refusing anything malformed.

        Every failure here is a :class:`TemporalError`, including a bad
        label: a window that cannot be reconstructed is a window whose
        validity cannot be established, and callers have one refusal for
        that rather than two.
        """

        if not isinstance(payload, dict):
            raise TemporalError("a temporal window must be an object")

        def _number(key: str, *, optional: bool = False):
            value = payload.get(key)
            if value is None and optional:
                return None
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TemporalError(
                    f"temporal window field {key!r} must be numeric"
                )
            result = float(value)
            if not math.isfinite(result):
                raise TemporalError(
                    f"temporal window field {key!r} must be finite"
                )
            return result

        try:
            source = _validate_label(
                payload.get("source"), "source label"
            )
            generation = _validate_label(
                payload.get("generation"), "generation label"
            )
        except ValueError as exc:
            raise TemporalError(str(exc)) from exc

        return cls(
            source=source,
            generation=generation,
            opened_wall=_number("opened_wall"),
            opened_monotonic=_number("opened_monotonic"),
            ttl=_number("ttl", optional=True),
            deadline_wall=_number("deadline_wall", optional=True),
        )


@dataclass
class _Source:
    """One named time source's audit history.

    ``wall_high_water`` / ``monotonic_high_water`` are the highest
    readings ever observed, and they are what make a regression detectable
    inside one process. ``anomalies`` is the audit trail an operator
    reads: a firewalled request that reports ``temporal_anomaly`` also
    leaves the concrete readings behind it.
    """

    name: str
    samples: int = 0
    wall_high_water: Optional[float] = None
    monotonic_high_water: Optional[float] = None
    anomalies: list[tuple[float, str]] = field(default_factory=list)
    last: Optional[TemporalContext] = None

    def suspect(self) -> Optional[str]:
        """The most recent anomaly reason, if the source is suspect.

        A source that regressed once stays suspect: the anomaly is a
        statement about the time base, and a later reading that happens to
        look fine does not retract it. Clearing it is an operator act --
        ``TemporalGuard.clear`` -- which is why it is not cleared here.
        """

        return self.anomalies[-1][1] if self.anomalies else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "samples": self.samples,
            "wall_high_water": self.wall_high_water,
            "monotonic_high_water": self.monotonic_high_water,
            "suspect": self.suspect(),
            "anomalies": [
                {"wall": at, "reason": reason}
                for at, reason in self.anomalies
            ],
        }


# =====================================================================
# The guard
# =====================================================================


class TemporalGuard:
    """The authority on what "now" is, and whether it can be trusted.

    One guard per SDK, holding a per-source audit history, an optional
    durable watermark store, and a process-generation id. It is the only
    thing in the package that may turn two clock readings into a verdict
    about a validity window, and it is deliberately incapable of widening
    anything: every answer it produces is either a context a caller may
    compare against, or a refusal reason.

    The guard does not own the clocks. Callers pass the reading in --
    ``sample(source=some_clock, name="execution-lease")`` -- which is what
    lets each store keep using the clock that stamped its own deadlines
    while still being audited on its own terms. That is not a convenience:
    the alternative is a guard that substitutes its own clock for the one
    a deadline was measured in, and two clocks disagreeing is not
    evidence about anything except that they disagree.
    """

    __slots__ = (
        "_lock",
        "_monotonic",
        "_tolerance",
        "_tolerance_source",
        "_store",
        "_generation",
        "_sources",
        "_restored",
        "_boot_anomaly",
    )

    def __init__(
        self,
        *,
        monotonic: Optional[Callable[[], float]] = None,
        tolerance: Optional[float] = DEFAULT_REGRESSION_TOLERANCE_SECONDS,
        store: Any = None,
        generation: Optional[str] = None,
    ) -> None:
        if tolerance is None:
            # One quantum of the platform's own clocks -- see the constant.
            tolerance = platform_clock_quantum()
            self._tolerance_source = "platform quantum"
        else:
            self._tolerance_source = "configured"

        if isinstance(tolerance, bool) or not isinstance(tolerance, (int, float)):
            raise TypeError("tolerance must be numeric or None")

        tolerance = float(tolerance)

        if not math.isfinite(tolerance) or tolerance < 0:
            raise ValueError(
                "tolerance must be a finite non-negative number, or None "
                "for the platform's own clock quantum"
            )

        if monotonic is not None and not callable(monotonic):
            raise TypeError("monotonic must be callable")

        self._lock = threading.RLock()
        self._monotonic = (
            monotonic if monotonic is not None else default_monotonic_clock()
        )
        self._tolerance = tolerance
        self._store = store
        self._generation = (
            generation
            if isinstance(generation, str) and generation
            else uuid.uuid4().hex
        )
        self._sources: dict[str, _Source] = {}
        self._restored: dict[str, dict[str, Any]] = {}
        self._boot_anomaly: Optional[str] = None

        if store is not None:
            self._restore()

    # ========================================================
    # Construction state
    # ========================================================

    def _restore(self) -> None:
        """Load the previous generation's watermarks, or record why not.

        An unreadable watermark store is a boot anomaly rather than an
        exception, for the same reason every other unreadable security
        dependency in this package is a denial rather than a crash: the
        process can still be useful, it just cannot prove a temporal
        context, and every sample will say so.
        """

        try:
            restored = self._store.load_watermarks()
        except Exception as exc:  # noqa: BLE001 - unreadable is a denial
            self._boot_anomaly = (
                f"temporal_watermark_unavailable:{type(exc).__name__}"
            )
            return

        for entry in restored:
            if not isinstance(entry, dict):
                self._boot_anomaly = "temporal_watermark_malformed"
                continue

            name = entry.get("name")

            if not isinstance(name, str) or not name:
                self._boot_anomaly = "temporal_watermark_malformed"
                continue

            self._restored[name] = dict(entry)

    # ========================================================
    # Properties
    # ========================================================

    @property
    def generation(self) -> str:
        """This process generation's id.

        Recorded on every context and on every window anchored here, so a
        window that crosses a restart is *known* to cross one instead of
        silently subtracting a monotonic reading from another boot.
        """

        return self._generation

    @property
    def tolerance(self) -> float:
        return self._tolerance

    @property
    def tolerance_source(self) -> str:
        """Whether the tolerance was configured or derived from the clock.

        Reported because the two mean different things: a configured number
        is a deployment's decision about how much regression to accept, while
        a derived one is the hardware's own granularity -- the strictest
        bound the platform can express.
        """

        return self._tolerance_source

    @property
    def store(self) -> Any:
        return self._store

    @property
    def boot_anomaly(self) -> Optional[str]:
        """Why this generation could not establish its starting point."""

        return self._boot_anomaly

    def suspect(self) -> Optional[str]:
        """The reason this guard cannot currently prove a temporal context.

        ``None`` means every source it has sampled agreed with its own
        history. Anything else is a reason the boundary must refuse: a
        boot that could not read its watermark, or a source that regressed.
        """

        with self._lock:
            if self._boot_anomaly is not None:
                return self._boot_anomaly

            for name in sorted(self._sources):
                reason = self._sources[name].suspect()

                if reason is not None:
                    return f"{reason}@{name}"

        return None

    # ========================================================
    # Sampling
    # ========================================================

    def monotonic(self) -> float:
        """One raw monotonic reading. ``TemporalError`` if unreadable.

        Public because a caller that only needs elapsed time -- the
        lapse sweeps, the freshness comparison -- should not have to
        invent a wall clock to obtain it.
        """

        try:
            reading = float(self._monotonic())
        except Exception as exc:  # noqa: BLE001 - unreadable is failure
            raise TemporalError(
                "the monotonic clock could not be read"
            ) from exc

        if not math.isfinite(reading):
            raise TemporalError("the monotonic clock is not finite")

        return reading

    def sample(
        self,
        *,
        source: Optional[Callable[[], float]] = None,
        name: str = "default",
    ) -> TemporalContext:
        """Read one named source and validate it against its own history.

        ``source`` is the wall-clock callable the caller would otherwise
        have used directly. A missing or unreadable source is a
        :class:`TemporalError` -- not a context with an anomaly, because
        there is no reading to have an opinion about -- and every
        enforcement call site already has a denial for that case.

        The returned context carries its own verdict in ``anomaly``. A
        sample is *always* returned when the clocks are readable: the
        guard's job is to say whether the reading can be trusted, and
        hiding an untrustworthy reading would leave a caller unable to
        record why it refused.
        """

        name = _validate_label(name, "source label")

        reading_source = source if source is not None else time.time

        if not callable(reading_source):
            raise TemporalError("the wall clock is not callable")

        # Both readings are taken *under the lock*, and that is
        # load-bearing rather than tidy. A reading is only comparable
        # against a history if the reading and the comparison are one step:
        # two threads that read 100.0 and 100.5 and then update the
        # high-water mark in the opposite order would have the second one's
        # honest reading classified as a regression. The clock callables
        # must therefore be leaves -- a clock that re-entered the guard
        # would deadlock, and no clock in this package does.
        with self._lock:
            try:
                wall = float(reading_source())
            except Exception as exc:  # noqa: BLE001 - unreadable is failure
                raise TemporalError(
                    "the wall clock could not be read"
                ) from exc

            if not math.isfinite(wall):
                raise TemporalError("the wall clock is not finite")

            monotonic = self.monotonic()

            entry = self._sources.get(name)

            if entry is None:
                entry = _Source(name=name)
                self._sources[name] = entry

            anomaly = self._classify(entry, name, wall, monotonic)

            entry.samples += 1
            entry.last = None

            context = TemporalContext(
                wall=wall,
                monotonic=monotonic,
                sequence=entry.samples,
                generation=self._generation,
                source=name,
                anomaly=anomaly,
            )

            if entry.wall_high_water is None or wall > entry.wall_high_water:
                entry.wall_high_water = wall

            if (
                entry.monotonic_high_water is None
                or monotonic > entry.monotonic_high_water
            ):
                entry.monotonic_high_water = monotonic

            if anomaly is not None:
                entry.anomalies.append((wall, anomaly))

            entry.last = context

            self._persist(entry, context)

        return context

    def observe_reading(
        self,
        wall: float,
        *,
        name: str = "default",
    ) -> TemporalContext:
        """Audit a wall reading the caller already holds.

        The companion to :meth:`sample`, for call sites that must obtain
        their own reading -- every gate on the authorization path reads its
        clock through ``_read_security_state`` so that an unreadable clock
        produces a denial reason instead of an exception, and that contract
        is not this release's to change.

        Same audit, same per-source history, same anomaly reasons: the only
        difference is who read the wall clock. The monotonic half is still
        taken here -- under the lock, for ``sample``'s reason -- because it
        is the half a caller cannot supply honestly: an elapsed-time reading
        the *caller* chose would be no more trustworthy than the wall
        reading it is meant to check.
        """

        name = _validate_label(name, "source label")

        if isinstance(wall, bool) or not isinstance(wall, (int, float)):
            raise TemporalError("a wall reading must be numeric")

        wall = float(wall)

        if not math.isfinite(wall):
            raise TemporalError("a wall reading must be finite")

        with self._lock:
            try:
                monotonic = self.monotonic()
            except TemporalError:
                # The wall reading is in hand and the caller needs a reason
                # to record, so an unreadable monotonic clock is an anomaly
                # rather than an exception: no window can be measured
                # without it, and a context that cannot measure a window
                # never covers one.
                return self._record_unavailable(name, wall)

            entry = self._sources.get(name)

            if entry is None:
                entry = _Source(name=name)
                self._sources[name] = entry

            anomaly = self._classify(entry, name, wall, monotonic)

            entry.samples += 1

            context = TemporalContext(
                wall=wall,
                monotonic=monotonic,
                sequence=entry.samples,
                generation=self._generation,
                source=name,
                anomaly=anomaly,
            )

            if entry.wall_high_water is None or wall > entry.wall_high_water:
                entry.wall_high_water = wall

            if (
                entry.monotonic_high_water is None
                or monotonic > entry.monotonic_high_water
            ):
                entry.monotonic_high_water = monotonic

            if anomaly is not None:
                entry.anomalies.append((wall, anomaly))

            entry.last = context

            self._persist(entry, context)

        return context

    def _record_unavailable(
        self,
        name: str,
        wall: float,
    ) -> TemporalContext:
        """Record a sample whose monotonic half could not be read.

        Called with the lock held. The context is returned in the anomalous
        state -- never raised -- because the wall reading is in hand and the
        caller's job is to produce a refusal with a reason, not to handle an
        exception where a denial belongs.
        """

        entry = self._sources.get(name)

        if entry is None:
            entry = _Source(name=name)
            self._sources[name] = entry

        entry.samples += 1

        if not entry.anomalies or entry.anomalies[-1][1] != (
            "monotonic_unavailable"
        ):
            entry.anomalies.append((wall, "monotonic_unavailable"))

        context = TemporalContext(
            wall=wall,
            monotonic=0.0,
            sequence=entry.samples,
            generation=self._generation,
            source=name,
            anomaly="monotonic_unavailable",
        )

        if entry.wall_high_water is None or wall > entry.wall_high_water:
            entry.wall_high_water = wall

        entry.last = context

        return context

    def _classify(
        self,
        entry: _Source,
        name: str,
        wall: float,
        monotonic: float,
    ) -> Optional[str]:
        """The anomaly reason for one reading, or ``None``.

        Four checks, in the order that makes the result most specific.
        The monotonic check comes first because a monotonic clock that
        regressed invalidates the arithmetic the wall check would use.
        """

        if self._boot_anomaly is not None:
            return self._boot_anomaly

        if (
            entry.monotonic_high_water is not None
            and monotonic < entry.monotonic_high_water
        ):
            return "monotonic_regression"

        if (
            entry.wall_high_water is not None
            and wall < entry.wall_high_water - self._tolerance
        ):
            return "wall_regression"

        restored = self._restored.get(name)

        if restored is not None and entry.samples == 0:
            previous = restored.get("wall_high_water")

            if isinstance(previous, (int, float)) and not isinstance(
                previous, bool
            ):
                if wall < float(previous) - self._tolerance:
                    return "cross_restart_regression"

        return None

    def _persist(self, entry: _Source, context: TemporalContext) -> None:
        """Record the watermark durably, or mark the source suspect.

        A watermark that cannot be written is exactly the state in which
        the *next* generation cannot detect a regression, so failing to
        write it cannot be a silent success. The sample is still returned
        -- with the anomaly attached -- because the caller needs a reason
        to record.
        """

        if self._store is None:
            return

        try:
            self._store.save_watermark(
                name=entry.name,
                wall_high_water=entry.wall_high_water,
                monotonic_high_water=entry.monotonic_high_water,
                generation=self._generation,
                sequence=context.sequence,
            )
        except Exception:  # noqa: BLE001 - unwritable is a denial
            # The source is marked by appending to its audit trail: the
            # next sample refuses, and the sample that could not be
            # recorded says why. Mutating the frozen context is not an
            # option, so the reason is recorded against the source and
            # surfaces on the following observation.
            if not entry.anomalies or entry.anomalies[-1][1] != (
                "watermark_unwritable"
            ):
                entry.anomalies.append(
                    (context.wall, "watermark_unwritable")
                )

    # ========================================================
    # Windows
    # ========================================================

    def window(
        self,
        *,
        context: TemporalContext,
        ttl: Optional[float] = None,
        deadline_wall: Optional[float] = None,
        source: Optional[str] = None,
    ) -> TemporalWindow:
        """Anchor a new window at a validated context.

        Refuses a context that is not provable: anchoring a window at an
        anomalous instant would create a window whose own opening moment
        is untrustworthy, and every later comparison against it would
        inherit that. A caller with an anomalous context has a denial to
        build, not a window.
        """

        if not isinstance(context, TemporalContext):
            raise TypeError("context must be a TemporalContext")

        if not context.provable:
            raise TemporalError(
                "a window cannot be anchored at an anomalous context: "
                f"{context.anomaly}"
            )

        if ttl is not None:
            if isinstance(ttl, bool) or not isinstance(ttl, (int, float)):
                raise TypeError("ttl must be numeric")
            ttl = float(ttl)
            if not math.isfinite(ttl) or ttl <= 0:
                raise ValueError("ttl must be a finite positive number")

        if deadline_wall is not None:
            if isinstance(deadline_wall, bool) or not isinstance(
                deadline_wall, (int, float)
            ):
                raise TypeError("deadline_wall must be numeric")
            deadline_wall = float(deadline_wall)
            if not math.isfinite(deadline_wall):
                raise ValueError("deadline_wall must be finite")

        return TemporalWindow(
            source=_validate_label(
                source if source is not None else context.source,
                "source label",
            ),
            generation=context.generation,
            opened_wall=context.wall,
            opened_monotonic=context.monotonic,
            ttl=ttl,
            deadline_wall=deadline_wall,
        )

    def close_reason(
        self,
        window: TemporalWindow,
        context: TemporalContext,
    ) -> Optional[str]:
        """Why ``context`` is outside ``window``, or ``None``.

        One definition of the comparison, used by every enforcement call
        site and by the invariant, so a window can never be evaluated two
        ways in two places.
        """

        if not isinstance(window, TemporalWindow):
            raise TypeError("window must be a TemporalWindow")

        if not isinstance(context, TemporalContext):
            raise TypeError("context must be a TemporalContext")

        return window.close_reason(context, tolerance=self._tolerance)

    # ========================================================
    # Auditing
    # ========================================================

    def context_of(
        self,
        name: str,
    ) -> Optional[TemporalContext]:
        with self._lock:
            entry = self._sources.get(name)
            return entry.last if entry is not None else None

    def sources(self) -> tuple[str, ...]:
        with self._lock:
            known = set(self._sources) | set(self._restored)
            return tuple(sorted(known))

    def snapshot(self) -> dict[str, Any]:
        """Comparable summary of the guard's whole audit state."""

        with self._lock:
            return {
                "generation": self._generation,
                "tolerance": self._tolerance,
                "tolerance_source": self._tolerance_source,
                "boot_anomaly": self._boot_anomaly,
                "suspect": self.suspect(),
                "sources": {
                    name: entry.to_dict()
                    for name, entry in sorted(self._sources.items())
                },
                "restored": sorted(self._restored),
            }

    def anomalies(self) -> tuple[tuple[str, float, str], ...]:
        with self._lock:
            return tuple(
                (name, at, reason)
                for name in sorted(self._sources)
                for at, reason in self._sources[name].anomalies
            )

    def clear(self) -> None:
        """Forget the recorded anomalies. An operator act, never automatic.

        Called after a clock has been reconciled. It does **not** move the
        wall or monotonic high-water marks: those are the history that
        makes the next regression detectable, and a reset that also cleared
        them would turn "reconcile the clock" into "erase the evidence".
        """

        with self._lock:
            for entry in self._sources.values():
                entry.anomalies.clear()
            self._boot_anomaly = None

    def close(self) -> None:
        if self._store is not None:
            self._store.close()


# =====================================================================
# Binding, for components the SDK owns
# =====================================================================


_ATTRIBUTE = "_temporal_guard"


def bind_temporal(component: Any, guard: TemporalGuard) -> bool:
    """Attach ``guard`` to ``component``, so its own clock reads are audited.

    The same shape as :func:`firewall.authority_epoch.bind_epoch` and
    :func:`firewall.state_commit.bind_state_commit`, and for the same
    reason: a store constructed standalone has no SDK and must keep
    working, so binding is how the SDK makes an existing store part of its
    temporal boundary without the store depending on an SDK. Returns
    whether the binding landed; a component that refuses attribute writes
    is reported rather than silenced.
    """

    if not isinstance(guard, TemporalGuard):
        raise TypeError("guard must be a TemporalGuard")

    try:
        setattr(component, _ATTRIBUTE, guard)
    except Exception:  # noqa: BLE001 - a refusing component is reported
        return False

    return getattr(component, _ATTRIBUTE, None) is guard


def temporal_of(component: Any) -> Optional[TemporalGuard]:
    """The guard bound to ``component``, or ``None`` if it is unbound."""

    guard = getattr(component, _ATTRIBUTE, None)

    return guard if isinstance(guard, TemporalGuard) else None


def sample_temporal(
    component: Any,
    *,
    name: str,
    source: Optional[Callable[[], float]] = None,
    fallback: Optional[Callable[[], float]] = None,
) -> TemporalContext:
    """A validated context for a component's own clock.

    The single call shape every bound component uses, and the helper the
    census recognises. A component with no guard builds a context from an
    unguarded reading of its own clock, marked ``unguarded`` -- which is
    honest: an unbound store is not inside anybody's temporal boundary,
    and the reason says so rather than pretending the reading was
    validated. A context that is not ``provable`` never covers a window,
    so an unguarded store refuses windows rather than measuring them
    against a reading nobody checked.

    Everything else -- an unreadable clock, a non-finite reading -- is a
    :class:`TemporalError`, which callers turn into a refusal.
    """

    guard = temporal_of(component)

    # The component's own clock is the one its deadlines were stamped in,
    # so it is the one the guard must audit. Passing ``None`` through to
    # ``guard.sample`` would substitute the platform clock for a
    # deployment's -- and comparing a deadline measured in one clock
    # against another is not a temporal check, it is two numbers
    # disagreeing.
    reading_source = source if source is not None else fallback

    if not callable(reading_source):
        raise TemporalError(
            "no clock is available for this component, so no temporal "
            "context can be established for it"
        )

    if guard is not None:
        return guard.sample(source=reading_source, name=name)

    try:
        wall = float(reading_source())
    except Exception as exc:  # noqa: BLE001 - unreadable is failure
        raise TemporalError(
            "the wall clock could not be read"
        ) from exc

    if not math.isfinite(wall):
        raise TemporalError("the wall clock is not finite")

    # An unbound component has no monotonic history to compare against and
    # no generation of its own, so it cannot claim one: the context is
    # marked unprovable, which is the only reading that cannot be widened.
    return TemporalContext(
        wall=wall,
        monotonic=0.0,
        sequence=0,
        generation=UNGUARDED_GENERATION,
        source=name,
        anomaly="temporal_context_unprovable:unguarded",
    )


def observe_temporal(
    guard: Optional[TemporalGuard],
    *,
    name: str,
    source: Optional[Callable[[], float]] = None,
) -> Iterator[Optional[TemporalContext]]:
    """Context manager yielding a validated context, or ``None``.

    The bracket form, mirroring ``record_widening`` and
    ``record_state_commit``: a caller that opens one is declaring that the
    region between the two halves is measured in a temporal context. A
    ``None`` yield means the context could not be established, and the
    caller must refuse -- there is no path through this helper that turns
    an unprovable context into a pass.
    """

    if guard is None:
        yield None
        return

    try:
        context = guard.sample(source=source, name=name)
    except TemporalError:
        yield None
        return

    yield context


__all__ = [
    "DEFAULT_REGRESSION_TOLERANCE_SECONDS",
    "MONOTONIC_CLOCK_FALLBACK",
    "UNGUARDED_GENERATION",
    "default_monotonic_clock",
    "platform_clock_quantum",
    "TEMPORAL_ANOMALY_PREFIX",
    "TEMPORAL_SAMPLE_HELPER",
    "TEMPORAL_WINDOW_CLOSED",
    "TEMPORAL_WINDOW_SITES",
    "TemporalContext",
    "TemporalError",
    "TemporalGuard",
    "TemporalWindow",
    "bind_temporal",
    "observe_temporal",
    "sample_temporal",
    "temporal_of",
]
