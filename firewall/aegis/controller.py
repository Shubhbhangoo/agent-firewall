"""The controller: the one object the SDK holds, and the only one it needs.

Everything else in ``firewall.aegis`` is a pure function or an immutable
record. The controller is where the mutable state lives -- one grant
registry, one restriction store, one map of decay schedules -- and it is
deliberately the only place, so there is exactly one answer to "what does
Aegis currently believe".

What the controller may and may not do
--------------------------------------

It may: register a grant, move its state, write and lift restrictions,
classify a change, and hand the authorization boundary a reason to deny.

It may not, and structurally cannot: produce an
:class:`~firewall.authorization.AuthorizationResult`, call
``authorize()`` and return the answer as its own, or move a grant up the
residual-authority order without a canonical allow that the boundary
produced. The first is machine-checked by AUTHORIZATION_UNIQUENESS -- this
file is not in ``AUTHORIZATION_RESULT_OWNERS``. The second is visible in
the imports: the controller imports nothing from ``firewall.sdk``, so it
has no boundary to call. The third is
:meth:`~firewall.aegis.state.AegisGrant.transition`'s evidenced-edge rule,
and :meth:`AegisController.observe_authorization` is the only method that
supplies evidence -- from a result the caller already has, never one the
controller made.

Consuming, not producing
------------------------

:meth:`observe_authorization` is the hinge of the whole design. The SDK
calls it *after* ``authorize()`` has decided, passing the
:class:`~firewall.authorization.AuthorizationResult` it produced. Aegis
reads it, checks it is a canonical allow for that exact fingerprint, and
uses it as evidence for ``REVALIDATING -> ACTIVE``. The direction of the
dependency is the security property: authority flows from the boundary
into Aegis and never the other way.

State is not an enforcement channel
-----------------------------------

A grant's :class:`~firewall.aegis.state.AegisState` records what Aegis
believes; a :class:`~firewall.aegis.restriction.Restriction` is what the
boundary enforces. They are deliberately not the same channel, and the
reason is ``REVALIDATING``: if the state itself denied, a revalidating
grant could never be re-authorized, ``REVALIDATING -> ACTIVE`` would be
unreachable, and the state machine would deadlock at the one edge that
exists to restore standing. So ``SUSPENDED`` denies because
:meth:`suspend` writes a suspending restriction -- not because the state
is ``SUSPENDED`` -- and every method here that moves a grant into a
restricted state writes the matching restriction in the same call.

Lock discipline
---------------

The controller takes its own ``RLock`` for the grant registry and decay
map; :class:`~firewall.aegis.restriction.RestrictionStore` takes its own
for restrictions. The order is always controller-then-store and the store
never calls back into the controller, so the pair cannot deadlock.
:meth:`restriction_reason` -- the method the authorization gate calls --
takes only the store's lock, so a slow classification cannot stall an
authorization.

Failing closed
--------------

Every method that the authorization path can reach is total: it returns a
reason or ``None`` and does not raise. A controller that raised into
``_gate_aegis`` would force the gate to choose between propagating (an
exception out of ``authorize()``) and swallowing (an unenforced
restriction); making the controller total removes the choice. Methods on
the *operator* path -- ``register``, ``narrow``, ``suspend`` -- do raise,
because an operator who thinks they suspended a grant must not carry on
believing it.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Optional

from firewall.aegis.blast import BlastRadius, blast_radius
from firewall.aegis.decay import DecaySchedule, DecayStage
from firewall.aegis.explain import Explanation, explain
from firewall.aegis.preflight import Preflight, preflight
from firewall.aegis.response import (
    AdaptiveResponse,
    Classification,
    classify,
)
from firewall.aegis.restriction import (
    Restriction,
    RestrictionStore,
    narrow as build_narrow,
    suspend as build_suspend,
)
from firewall.aegis.state import (
    AegisGrant,
    AegisState,
    IllegalTransition,
    canonical_allow_for,
    history_violations,
)

#: Restriction key an executed ``NARROW`` writes, suffixed with the
#: trigger so two different triggers do not overwrite each other.
NARROW_KEY_PREFIX = "aegis:narrow"
#: Restriction key an executed ``SUSPEND`` writes.
SUSPEND_KEY_PREFIX = "aegis:suspend"


@dataclass(frozen=True)
class ExecutionRecord:
    """What the executor actually did. Reports outcomes, not intentions.

    ``revoked`` is ``False`` whenever the revoke hook was absent or
    raised, even though the classification called for a revocation, and
    ``failures`` says so. An executor that reported a revocation it did
    not perform would be worse than one that could not perform it.
    """

    fingerprint: str
    response: AdaptiveResponse
    applied: tuple[Restriction, ...] = ()
    state_before: Optional[AegisState] = None
    state_after: Optional[AegisState] = None
    revoked: bool = False
    revalidation_requested: bool = False
    failures: tuple[str, ...] = ()

    @property
    def acted(self) -> bool:
        return (
            bool(self.applied)
            or self.revoked
            or self.state_before is not self.state_after
        )

    def describe(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "response": self.response.value,
            "applied": [item.describe() for item in self.applied],
            "state_before": None if self.state_before is None else self.state_before.value,
            "state_after": None if self.state_after is None else self.state_after.value,
            "revoked": self.revoked,
            "revalidation_requested": self.revalidation_requested,
            "failures": list(self.failures),
        }
class AegisController:
    """Aegis's mutable state, and the operations that change it."""

    def __init__(
        self,
        *,
        store: Optional[RestrictionStore] = None,
        revoke_hook: Optional[Callable[[str], Any]] = None,
        revalidate_hook: Optional[Callable[[str], Any]] = None,
        narrow_constraints: Optional[Mapping[str, Any]] = None,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._store = store if store is not None else RestrictionStore()
        self._grants: dict[str, AegisGrant] = {}
        self._schedules: dict[str, DecaySchedule] = {}
        self._revoke_hook = revoke_hook
        self._revalidate_hook = revalidate_hook
        #: What an executed ``NARROW`` narrows to when the caller does not
        #: say. Empty means a ``NARROW`` with no explicit constraints
        #: escalates to a suspension rather than writing a restriction
        #: that restricts nothing -- see :meth:`execute`.
        self._narrow_constraints = dict(narrow_constraints or {})
        self._clock = clock if clock is not None else time.time

    # -- registration -------------------------------------------------

    @property
    def store(self) -> RestrictionStore:
        """The restriction store. Exposed because the gate reads it."""

        return self._store

    def attach_hooks(
        self,
        *,
        revoke: Optional[Callable[[str], Any]] = None,
        revalidate: Optional[Callable[[str], Any]] = None,
    ) -> None:
        """Wire the hooks a host supplies after construction.

        Fills only what is missing, so a caller who passed an explicit
        hook keeps it. Exists because ``FirewallSDK`` wants to wire its own
        ``revoke`` into a controller the caller may have built before the
        SDK existed, and reaching into a private attribute to do it would
        make the coupling invisible.
        """

        with self._lock:
            if revoke is not None and self._revoke_hook is None:
                self._revoke_hook = revoke

            if revalidate is not None and self._revalidate_hook is None:
                self._revalidate_hook = revalidate

    def register(
        self,
        fingerprint: str,
        *,
        agent_id: str,
        capability: str,
        schedule: Optional[DecaySchedule] = None,
    ) -> AegisGrant:
        """Register a grant in ``ISSUED``. Idempotent on a known grant.

        Re-registering does not reset state: a revoked grant that could be
        re-registered into ``ISSUED`` would be an authority resurrection
        with extra steps.
        """

        if not isinstance(fingerprint, str) or not fingerprint:
            raise ValueError("register requires a fingerprint")

        with self._lock:
            existing = self._grants.get(fingerprint)

            if schedule is not None:
                if not isinstance(schedule, DecaySchedule):
                    raise TypeError("schedule must be a DecaySchedule")

                self._schedules[fingerprint] = schedule

            if existing is not None:
                return existing

            grant = AegisGrant(
                fingerprint=fingerprint,
                agent_id=agent_id,
                capability=capability,
                created_at=self._clock(),
            )
            self._grants[fingerprint] = grant

            return grant

    def grant(self, fingerprint: str) -> Optional[AegisGrant]:
        """The tracked grant, or ``None`` if there is not one.

        Total, like the rest of the read path: an unhashable argument is
        "not tracked" rather than a ``TypeError``. The console and
        ``explain`` reach this with fingerprints derived from whatever a
        caller handed the boundary, and a read that raises there turns a
        malformed request into a crashed operator tool. The write path
        (:meth:`register`) still refuses loudly -- an operator naming a
        grant wrongly wants to hear about it.
        """

        if not isinstance(fingerprint, str):
            return None

        with self._lock:
            return self._grants.get(fingerprint)

    def grants(self) -> Mapping[str, AegisGrant]:
        with self._lock:
            return dict(self._grants)

    def tracked(self) -> bool:
        """Does Aegis know about anything at all?

        The gate uses this to abstain cheaply: a deployment that never
        registered a grant and never wrote a restriction gets the v2.3
        decision sequence unchanged.
        """

        with self._lock:
            if self._grants or self._schedules:
                return True

        return bool(self._store.fingerprints())

    def schedule_for(self, fingerprint: str) -> Optional[DecaySchedule]:
        with self._lock:
            return self._schedules.get(fingerprint)
    # -- the authorization path (total, never raises) ------------------

    def restriction_reason(
        self,
        fingerprints: Iterable[str],
        action: str,
        request: Any,
    ) -> Optional[str]:
        """Why an active restriction refuses, or ``None``.

        This is what ``_gate_aegis`` calls. ``None`` is not an allow: it
        means Aegis has no objection and the remaining gates still run.

        Total. An unreadable store produces ``aegis_state_unavailable``
        rather than an exception, because a gate that cannot read Aegis
        state must deny rather than skip Aegis.
        """

        try:
            names = tuple(
                name for name in fingerprints if isinstance(name, str) and name
            )
        except TypeError:
            return "aegis_state_unavailable:fingerprints_unreadable"

        if not names:
            return None

        try:
            hit = self._store.excludes(names, action, request)
        except Exception as error:  # noqa: BLE001 - fail closed, never raise
            return f"aegis_state_unavailable:{type(error).__name__}"

        if hit is None:
            return None

        _, reason = hit

        return reason

    def suspended_in(self, fingerprints: Iterable[str]) -> Optional[str]:
        """The first suspended fingerprint in the chain, or ``None``.

        Used by the commit-time re-check, which needs the cheapest
        question and must not raise inside the transaction gate.
        """

        try:
            names = tuple(
                name for name in fingerprints if isinstance(name, str) and name
            )

            return self._store.any_suspended(names)
        except Exception:  # noqa: BLE001 - fail closed
            return "aegis_state_unavailable"

    def observe_authorization(
        self,
        fingerprint: str,
        result: Any,
    ) -> Optional[AegisGrant]:
        """Record what the boundary decided. The only evidenced path.

        Aegis consumes ``result``; it never makes one. A canonical allow
        moves ``ISSUED -> ACTIVE`` (a relabelling: equal residual
        authority) or ``REVALIDATING -> ACTIVE`` (the single edge that
        increases residual authority, and the reason the evidence rule
        exists).

        A denial records nothing. It is tempting to suspend on a denial,
        and wrong: an ordinary denial -- an amount over a ceiling -- is
        the system working, not a change in the grant's standing.

        Both moves are checked against
        :func:`~firewall.aegis.state.canonical_allow_for` here, not left to
        :meth:`~firewall.aegis.state.AegisGrant.transition`. ``transition``
        demands evidence only on an edge that *widens*, so
        ``ISSUED -> ACTIVE`` -- equal residual authority, therefore legal
        unconditionally -- would accept any object at all, including a
        genuine denial: the SDK observes every outcome, not only allows. The
        residual order is not the whole guarantee, because ``ACTIVE`` is a
        *claim* as well as a level. ``state.py`` defines it as "at least one
        canonical allow observed", and an ``ACTIVE`` grant that was never
        allowed makes both the explanation (§17) and the recorded history
        false. Checking here is strictly narrowing -- it can only refuse a
        move -- and it subsumes the non-verdict, the denial, another
        capability's allow, and an allow carrying some other reason.

        Total, because it runs inside the authorization path. A transition
        that turns out to be illegal is skipped, not raised: the grant
        stays where it is, which is the conservative reading.
        """

        if not isinstance(fingerprint, str) or not fingerprint:
            return None

        if not canonical_allow_for(fingerprint, result):
            return self.grant(fingerprint)

        with self._lock:
            grant = self._grants.get(fingerprint)

            if grant is None:
                return None

            if grant.state not in (AegisState.ISSUED, AegisState.REVALIDATING):
                return grant

            try:
                moved = grant.transition(
                    AegisState.ACTIVE,
                    "canonical allow observed at the authorization boundary",
                    at=self._clock(),
                    evidence=result,
                )
            except IllegalTransition:
                return grant

            self._grants[fingerprint] = moved

            return moved
    # -- the operator path (raises on misuse) --------------------------

    def narrow(
        self,
        fingerprint: str,
        *,
        key: str,
        reason: str,
        constraints: Optional[Mapping] = None,
        patterns: Iterable[str] = (),
        trigger: Optional[str] = None,
    ) -> Restriction:
        """Write a narrowing and move the grant to ``NARROWED``.

        The restriction is written first. If the state transition then
        turns out to be illegal -- the grant is already suspended, or
        terminal -- the restriction stays: it can only subtract, and
        removing it to keep the state tidy would widen authority to
        preserve bookkeeping.
        """

        restriction = build_narrow(
            fingerprint,
            key=key,
            reason=reason,
            constraints=constraints,
            patterns=patterns,
            trigger=trigger,
            at=self._clock(),
        )

        self._store.apply(restriction)
        self._move(fingerprint, AegisState.NARROWED, reason, trigger)

        return restriction

    def suspend(
        self,
        fingerprint: str,
        *,
        key: str,
        reason: str,
        trigger: Optional[str] = None,
    ) -> Restriction:
        """Write a suspension and move the grant to ``SUSPENDED``."""

        restriction = build_suspend(
            fingerprint,
            key=key,
            reason=reason,
            trigger=trigger,
            at=self._clock(),
        )

        self._store.apply(restriction)
        self._move(fingerprint, AegisState.SUSPENDED, reason, trigger)

        return restriction

    def lift(
        self,
        fingerprint: str,
        key: str,
        *,
        reason: str = "restriction lifted",
    ) -> tuple[Restriction, ...]:
        """Remove restrictions under ``key`` and enter ``REVALIDATING``.

        The grant does not return to ``ACTIVE`` here and cannot: only
        :meth:`observe_authorization` supplies the evidence that edge
        requires. Lifting a restriction removes an obstacle; it does not
        restore standing.

        Two conditions gate the move, and both read the store rather than
        trusting the caller's key:

        * **Something was actually removed.**
          :meth:`~firewall.aegis.restriction.RestrictionStore.lift` returns
          an empty tuple when nothing carried ``key``, and ``state.py``
          requires a lift edge to name the restriction being cleared
          precisely "so a caller cannot clear a restriction it does not know
          exists". Moving anyway recorded ``lifted=key`` for a key that
          never existed -- a lift edge whose own justification was false,
          which is the §17 false explanation again.
        * **Nothing is left to lift.** ``REVALIDATING`` is the launch pad
          for the one edge that widens, and ``state.py`` defines ``ACTIVE``
          as a canonical allow with *no restriction*. A grant carrying a
          surviving narrowing can still be allowed *inside* that narrowing,
          so entering ``REVALIDATING`` while one stands is a route to an
          ``ACTIVE`` grant that is still restricted.

        When a restriction survives, the state follows the store instead: a
        surviving suspension puts a merely ``NARROWED`` grant into
        ``SUSPENDED``, which is a reduction. The opposite correction cannot
        happen -- ``SUSPENDED -> NARROWED`` widens and the machine refuses
        it -- so a partial lift never raises a grant's standing.
        """

        with self._lock:
            removed = self._store.lift(fingerprint, key)

            if not removed:
                return removed

            grant = self._grants.get(fingerprint)

            if grant is None:
                return removed

            if grant.state not in (AegisState.NARROWED, AegisState.SUSPENDED):
                return removed

            remaining = self._store.restrictions_for(fingerprint)

            if remaining:
                if any(item.suspends for item in remaining):
                    self._settle(
                        fingerprint,
                        grant,
                        AegisState.SUSPENDED,
                        f"{key} lifted; a suspension remains in force",
                    )

                return removed

            self._settle(
                fingerprint,
                grant,
                AegisState.REVALIDATING,
                reason,
                lifted=key,
            )

        return removed

    def begin_revalidation(
        self,
        fingerprint: str,
        *,
        reason: str = "revalidation in flight",
        trigger: Optional[str] = None,
    ) -> Optional[AegisGrant]:
        """Move to ``REVALIDATING``: Aegis's knowledge is now in flight.

        From ``NARROWED`` or ``SUSPENDED`` this needs a lift key, so use
        :meth:`lift` for those. From ``ISSUED`` or ``ACTIVE`` it is a
        plain reduction to the bottom of the order.
        """

        return self._move(fingerprint, AegisState.REVALIDATING, reason, trigger)

    def expire(
        self,
        fingerprint: str,
        *,
        reason: str = "observed expired",
    ) -> Optional[AegisGrant]:
        """Latch ``EXPIRED``. Terminal, and never re-derived from a clock."""

        return self._move(fingerprint, AegisState.EXPIRED, reason, "time")

    def mark_revoked(
        self,
        fingerprint: str,
        *,
        reason: str = "revoked",
        trigger: Optional[str] = None,
    ) -> Optional[AegisGrant]:
        """Latch ``REVOKED``.

        Named ``mark_revoked`` rather than ``revoke`` because it records a
        revocation the revocation registry owns; it does not perform one.
        The registry remains the authority, and ``_gate_revocation`` keeps
        reading it.
        """

        return self._move(fingerprint, AegisState.REVOKED, reason, trigger)

    def _move(
        self,
        fingerprint: str,
        to_state: AegisState,
        reason: str,
        trigger: Optional[str],
        *,
        lifted: Optional[str] = None,
    ) -> Optional[AegisGrant]:
        """Caller-facing transitions. Raises on an illegal move."""

        with self._lock:
            grant = self._grants.get(fingerprint)

            if grant is None:
                return None

            if grant.state is to_state:
                return grant

            moved = grant.transition(
                to_state,
                reason,
                at=self._clock(),
                trigger=trigger,
                lifted=lifted,
            )
            self._grants[fingerprint] = moved

            return moved

    def _settle(
        self,
        fingerprint: str,
        grant: AegisGrant,
        to_state: AegisState,
        reason: str,
        *,
        lifted: Optional[str] = None,
    ) -> None:
        """Record a state the restrictions already imply. Never raises.

        Call with ``self._lock`` held and with ``grant`` read under it.

        Used by :meth:`lift`, where the store is the enforcement and the
        state is a label following it. A label that cannot be reached
        legally is left alone rather than raised: the enforcement is already
        correct without it, and an exception here would abandon a lift that
        the store has already committed.
        """

        if grant.state is to_state:
            return

        try:
            self._grants[fingerprint] = grant.transition(
                to_state,
                reason,
                at=self._clock(),
                lifted=lifted,
            )
        except IllegalTransition:
            pass
    # -- classification and execution ---------------------------------

    def classify(
        self,
        trigger: Any,
        *,
        before: Any = None,
        after: Any = None,
    ) -> Classification:
        """Delegate to the pure classifier. Analysis only, no state change."""

        return classify(trigger, before=before, after=after)

    def execute(
        self,
        fingerprint: str,
        classification: Classification,
        *,
        constraints: Optional[Mapping] = None,
        patterns: Iterable[str] = (),
    ) -> ExecutionRecord:
        """Act on a classification. A separate call, on purpose.

        Classification and execution are different methods because
        "analysis" and "action" must be different call sites -- a caller
        that only wants to know what changed must not be able to change
        authority by asking.

        ``KEEP`` does nothing at all. ``REVALIDATE`` moves the grant to
        ``REVALIDATING`` and calls the revalidate hook if one is wired;
        it writes no restriction, because re-asking the boundary is not a
        narrowing. ``NARROW`` and ``SUSPEND`` write restrictions.
        ``REVOKE`` calls the revoke hook and latches ``REVOKED``.

        A ``NARROW`` with nothing to narrow to escalates to ``SUSPEND``.
        The alternative -- writing a restriction that restricts nothing --
        would record a narrowing that does not exist, which is the
        failure mode §17 exists to prevent.

        An argument that is not a :class:`Classification` at all suspends
        too, for the same reason: see :meth:`_execute_unreadable`.

        Total. Every failure is recorded in
        :attr:`ExecutionRecord.failures` rather than raised, because this
        runs on the monitor path where an exception would abandon the
        remaining response.
        """

        if not isinstance(classification, Classification):
            return self._execute_unreadable(fingerprint)

        response = classification.response
        before = self.grant(fingerprint)
        state_before = None if before is None else before.state
        applied: list[Restriction] = []
        failures: list[str] = []
        revoked = False
        revalidation_requested = False

        merged = dict(self._narrow_constraints)
        merged.update(dict(constraints or {}))
        limits = tuple(patterns)

        if response is AdaptiveResponse.NARROW and not (merged or limits):
            response = AdaptiveResponse.SUSPEND
            failures.append(
                "NARROW had no constraints or patterns to narrow to; escalated "
                "to SUSPEND rather than recording a narrowing that does not "
                "restrict anything"
            )

        try:
            if response is AdaptiveResponse.REVALIDATE:
                revalidation_requested = True
                self._execute_revalidate(fingerprint, classification, failures)
            elif response in (AdaptiveResponse.NARROW, AdaptiveResponse.SUSPEND):
                # Written before the transition is attempted, and recorded
                # in ``applied`` before it is attempted too. A restriction
                # that lands while the state move is refused is still
                # enforced, and a record that omitted it would understate
                # what Aegis did.
                if response is AdaptiveResponse.NARROW:
                    restriction = build_narrow(
                        fingerprint,
                        key=f"{NARROW_KEY_PREFIX}:{classification.trigger or 'change'}",
                        reason=self._reason_for(classification),
                        constraints=merged,
                        patterns=limits,
                        trigger=classification.trigger,
                        at=self._clock(),
                    )
                    target = AegisState.NARROWED
                else:
                    restriction = build_suspend(
                        fingerprint,
                        key=f"{SUSPEND_KEY_PREFIX}:{classification.trigger or 'change'}",
                        reason=self._reason_for(classification),
                        trigger=classification.trigger,
                        at=self._clock(),
                    )
                    target = AegisState.SUSPENDED

                self._store.apply(restriction)
                applied.append(restriction)

                try:
                    self._move(
                        fingerprint,
                        target,
                        restriction.reason,
                        classification.trigger,
                    )
                except IllegalTransition as error:
                    failures.append(
                        f"restriction {restriction.key} is enforced but the "
                        f"state is unchanged: {error}"
                    )
            elif response is AdaptiveResponse.REVOKE:
                revoked = self._execute_revoke(fingerprint, classification, failures)
        except Exception as error:  # noqa: BLE001 - recorded, never raised
            failures.append(f"{type(error).__name__} executing {response.value}")

        after = self.grant(fingerprint)

        return ExecutionRecord(
            fingerprint=fingerprint,
            response=response,
            applied=tuple(applied),
            state_before=state_before,
            state_after=None if after is None else after.state,
            revoked=revoked,
            revalidation_requested=revalidation_requested,
            failures=tuple(failures),
        )

    def _execute_unreadable(self, fingerprint: str) -> ExecutionRecord:
        """Suspend on a classification the executor could not read.

        Every other unreadable input in Aegis writes a restriction: an
        unreadable store denies, a decay schedule that cannot be positioned
        in time applies its strongest stage, a change with no observable
        *after* classifies as ``SUSPEND``, and a revocation that could not
        be executed suspends. A response the caller could not describe is
        the same kind of unknown, and leaving authority intact here would
        make this the one unreadable input in Aegis that costs nothing.

        Reporting ``SUSPEND`` without applying one would be worse than
        either reading. :class:`ExecutionRecord` reports outcomes, so a
        record naming a suspension nobody wrote is exactly the explanation
        §17 exists to prevent -- and a caller reading ``response`` would
        believe authority had been withdrawn when it had not.

        Total, like the rest of the executor: a hostile fingerprint or an
        unwritable store is recorded, not raised.
        """

        failures = ["execute requires a Classification"]
        before = self.grant(fingerprint)
        applied: list[Restriction] = []

        try:
            restriction = build_suspend(
                fingerprint,
                key=f"{SUSPEND_KEY_PREFIX}:unreadable_classification",
                reason=(
                    "a response was called for but the classification could "
                    "not be read; denying until one is supplied"
                ),
                at=self._clock(),
            )
            self._store.apply(restriction)
            applied.append(restriction)

            try:
                self._move(
                    fingerprint,
                    AegisState.SUSPENDED,
                    restriction.reason,
                    None,
                )
            except IllegalTransition as error:
                failures.append(
                    f"restriction {restriction.key} is enforced but the state "
                    f"is unchanged: {error}"
                )
        except Exception as error:  # noqa: BLE001 - recorded, never raised
            failures.append(
                f"{type(error).__name__} suspending after an unreadable "
                f"classification"
            )

        after = self.grant(fingerprint)

        return ExecutionRecord(
            fingerprint=fingerprint,
            response=AdaptiveResponse.SUSPEND,
            applied=tuple(applied),
            state_before=None if before is None else before.state,
            state_after=None if after is None else after.state,
            failures=tuple(failures),
        )

    def _reason_for(self, classification: Classification) -> str:
        strongest = [

            item
            for item in classification.contributions
            if item.response is classification.response
        ]

        if strongest:
            return strongest[0].detail

        return f"classified as {classification.response.value}"

    def _execute_revalidate(
        self,
        fingerprint: str,
        classification: Classification,
        failures: list[str],
    ) -> None:
        grant = self.grant(fingerprint)

        if grant is not None and grant.state in (
            AegisState.NARROWED,
            AegisState.SUSPENDED,
        ):
            # Reaching REVALIDATING from a restricted state requires
            # naming what is being lifted, and a revalidation triggered by
            # an environmental change is not a decision to lift anything.
            # The grant stays restricted; the revalidation still runs.
            failures.append(
                f"grant is {grant.state.value}; revalidation was requested "
                f"without lifting a restriction, so the state is unchanged"
            )
        else:
            try:
                self.begin_revalidation(
                    fingerprint,
                    reason=self._reason_for(classification),
                    trigger=classification.trigger,
                )
            except IllegalTransition as error:
                failures.append(f"could not enter REVALIDATING: {error}")

        if self._revalidate_hook is None:
            failures.append(
                "no revalidation hook is wired, so the boundary was not "
                "re-asked eagerly; the grant stays in REVALIDATING until an "
                "authorization is observed. REVALIDATING is not itself a "
                "denial -- the gate enforces restrictions, and a revalidation "
                "wrote none"
            )
            return

        try:
            self._revalidate_hook(fingerprint)
        except Exception as error:  # noqa: BLE001 - recorded, never raised
            failures.append(f"{type(error).__name__} calling the revalidation hook")

    def _execute_revoke(
        self,
        fingerprint: str,
        classification: Classification,
        failures: list[str],
    ) -> bool:
        performed = False

        if self._revoke_hook is None:
            failures.append(
                "no revoke hook is wired, so the revocation registry was not "
                "updated; suspending instead"
            )
        else:
            try:
                self._revoke_hook(fingerprint)
                performed = True
            except Exception as error:  # noqa: BLE001 - recorded, never raised
                failures.append(f"{type(error).__name__} calling the revoke hook")

        if not performed:
            # The registry is the authority on revocation. If it was not
            # updated, Aegis must not latch REVOKED -- that would record a
            # finality the system does not actually enforce. Suspend
            # instead: reversible, and it denies now.
            try:
                self.suspend(
                    fingerprint,
                    key=f"{SUSPEND_KEY_PREFIX}:revocation_unexecuted",
                    reason=(
                        "a revocation was called for but could not be executed; "
                        "denying until the registry is updated"
                    ),
                    trigger=classification.trigger,
                )
            except IllegalTransition as error:
                failures.append(f"could not suspend after a failed revoke: {error}")

            return False

        self._store.apply(
            build_suspend(
                fingerprint,
                key=f"{SUSPEND_KEY_PREFIX}:revoked",
                reason="revoked",
                trigger=classification.trigger,
                at=self._clock(),
            )
        )

        try:
            self.mark_revoked(
                fingerprint,
                reason=self._reason_for(classification),
                trigger=classification.trigger,
            )
        except IllegalTransition as error:
            failures.append(f"could not latch REVOKED: {error}")

        return True
    # -- decay ---------------------------------------------------------

    def apply_decay(
        self,
        *,
        now: Optional[float] = None,
    ) -> tuple[ExecutionRecord, ...]:
        """Apply every scheduled decay that is due. Idempotent.

        Idempotent because the store deduplicates on the restriction's
        content and a decay restriction's content is a pure function of
        its stage: running the sweep twice in the same stage writes one
        entry. Running it after the stage advances writes the stronger one
        and leaves the weaker in place, which is the direction that
        cannot widen.
        """

        moment = self._clock() if now is None else float(now)
        records: list[ExecutionRecord] = []

        with self._lock:
            pairs = tuple(self._schedules.items())
            created = {
                name: grant.created_at for name, grant in self._grants.items()
            }

        for fingerprint, schedule in pairs:
            start = created.get(fingerprint)

            if start is None:
                # A schedule for a grant Aegis does not track cannot be
                # positioned in time. The schedule's strongest stage is
                # the reading that does not assume the permissive phase.
                elapsed = float("nan")
            else:
                elapsed = moment - start

            restriction = schedule.restriction_at(fingerprint, elapsed, at=moment)

            if restriction is None:
                continue

            failures: list[str] = []
            before = self.grant(fingerprint)
            self._store.apply(restriction)

            target = (
                AegisState.SUSPENDED
                if restriction.suspends
                else AegisState.NARROWED
            )

            try:
                self._move(
                    fingerprint,
                    target,
                    restriction.reason,
                    "time",
                )
            except IllegalTransition as error:
                failures.append(f"state unchanged: {error}")

            after = self.grant(fingerprint)
            records.append(
                ExecutionRecord(
                    fingerprint=fingerprint,
                    response=(
                        AdaptiveResponse.SUSPEND
                        if restriction.suspends
                        else AdaptiveResponse.NARROW
                    ),
                    applied=(restriction,),
                    state_before=None if before is None else before.state,
                    state_after=None if after is None else after.state,
                    failures=tuple(failures),
                )
            )

        return tuple(records)

    def decay_stage(
        self,
        fingerprint: str,
        *,
        now: Optional[float] = None,
    ) -> Optional[DecayStage]:
        schedule = self.schedule_for(fingerprint)

        if schedule is None:
            return None

        grant = self.grant(fingerprint)
        moment = self._clock() if now is None else float(now)

        if grant is None:
            return schedule.stage_at(float("nan"))

        return schedule.stage_at(moment - grant.created_at)

    # -- analysis ------------------------------------------------------

    def blast_radius(
        self,
        fingerprint: str,
        *,
        lineage_edges: Iterable[Any] = (),
        graph: Any = None,
    ) -> BlastRadius:
        """Bounded blast radius over the grants Aegis tracks."""

        return blast_radius(
            fingerprint,
            lineage_edges=lineage_edges,
            grants=self.grants(),
            graph=graph,
        )

    def preflight(
        self,
        action: str,
        request: Any,
        *,
        fingerprints: Iterable[str] = (),
        envelope: Any = None,
        now: Optional[float] = None,
        chain_resolved: Optional[bool] = None,
        depth: Optional[int] = None,
        depth_ceiling: Optional[int] = None,
        blast: Optional[BlastRadius] = None,
        simulation: Any = None,
        evidence_findings: Optional[Iterable[str]] = None,
    ) -> Preflight:
        """Run the §7 pipeline, filling in the restriction stage."""

        return preflight(
            action,
            request,
            envelope=envelope,
            now=now,
            restriction_reason=self.restriction_reason(fingerprints, action, request),
            chain_resolved=chain_resolved,
            depth=depth,
            depth_ceiling=depth_ceiling,
            blast=blast,
            simulation=simulation,
            evidence_findings=evidence_findings,
        )

    def explain(
        self,
        fingerprint: str,
        *,
        action: Optional[str] = None,
        classification: Optional[Classification] = None,
        envelope: Any = None,
        blast: Optional[BlastRadius] = None,
        preflight_result: Optional[Preflight] = None,
        lifecycle: Any = None,
    ) -> Explanation:
        """Answer §17's six questions for one grant."""

        return explain(
            action=action,
            classification=classification,
            restrictions=self._store.restrictions_for(fingerprint),
            grant=self.grant(fingerprint),
            envelope=envelope,
            blast=blast,
            preflight=preflight_result,
            lifecycle=lifecycle,
        )

    # -- audit ---------------------------------------------------------

    def history_findings(self) -> tuple[str, ...]:
        """Every recorded history that violates the machine's own rules.

        Empty in a correct build. Read by AEGIS_STATE_TRANSITIONS, which
        audits the recorded histories as data rather than by re-running
        the transition code that produced them.
        """

        findings: list[str] = []

        for fingerprint, grant in self.grants().items():
            for finding in history_violations(grant):
                findings.append(f"{fingerprint}: {finding}")

        return tuple(findings)

    def describe(self) -> dict:
        with self._lock:
            grants = {
                name: grant.describe() for name, grant in self._grants.items()
            }
            schedules = {
                name: schedule.describe()
                for name, schedule in self._schedules.items()
            }

        return {
            "grants": grants,
            "schedules": schedules,
            "restrictions": self._store.describe(),
            "hooks": {
                "revoke": self._revoke_hook is not None,
                "revalidate": self._revalidate_hook is not None,
            },
            "history_findings": list(self.history_findings()),
        }
