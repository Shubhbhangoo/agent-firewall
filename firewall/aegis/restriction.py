"""Restrictions: the only Aegis state the authorization boundary reads.

A restriction subtracts. That is the whole design, and it is what makes
Aegis structurally incapable of granting authority: the store holds
*additional conjuncts*, and ``_gate_aegis`` can only deny on them. There
is no representation in this module for "also allow" -- not a flag, not a
field, not a code path.

Reduce-only by construction, not by validation
----------------------------------------------

An earlier sketch had the store compare a new restriction against the one
it replaced and refuse a widening. That is a validation rule, and a
validation rule can be wrong. Instead the store *accumulates*: the
restrictions on a grant are a tuple, the gate evaluates every one of
them, and any failure denies. Adding a conjunct to a conjunction cannot
widen it, whatever the conjunct says. The property holds without anyone
having to compare two restrictions for permissiveness.

Two consequences follow, and both are deliberate:

* **Repeated identical findings do not accumulate.** Entries are
  deduplicated on ``(key, kind, patterns, canonical constraints)``, so a
  posture engine that reports the same change every second writes one
  entry, not 86,400.
* **Growth is capped, and the cap escalates rather than drops.** A grant
  that reaches :data:`MAX_RESTRICTIONS_PER_GRANT` distinct restrictions
  has its whole set replaced by a single ``SUSPEND``. Dropping the new
  restriction would be the fail-open direction; refusing everything is
  the fail-closed one. The cost is stated rather than hidden: an actor
  that can apply restrictions can force a suspension by applying enough
  of them. Applying restrictions is an operator/executor capability, not
  an agent one, and the outcome is refusal, so the trade is bounded
  memory against an availability effect that is already available to
  anyone holding that capability.

Lifting is the one widening operation, and it is explicit
--------------------------------------------------------

:meth:`RestrictionStore.lift` removes entries by key. Nothing else in the
module removes anything. It exists because a narrowing that can never be
undone is not a narrowing but a revocation, and the two must stay
distinguishable. The state machine pairs it with the ``NARROWED |
SUSPENDED -> REVALIDATING`` lift edge, which requires *naming* the
restriction being cleared, and then requires a canonical allow to reach
``ACTIVE`` again -- so a lift alone restores nothing.

Chain binding
-------------

:meth:`RestrictionStore.excludes` takes every fingerprint in the resolved
delegation chain, not just the requested capability's. A restriction on a
parent therefore binds every descendant automatically, which is the same
direction the envelope meet runs in: authority flows down, restrictions
flow down with it.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Optional

from firewall.authorization import _check_constraints
from firewall.authority_epoch import record_widening
from firewall.namespace import matches

#: Distinct restrictions retained per grant before the store escalates to
#: a single ``SUSPEND``. Sixteen is chosen to be far above what any
#: classifier rule set produces (the classifier has five responses over
#: fifteen triggers) and far below anything that costs memory.
MAX_RESTRICTIONS_PER_GRANT = 16

#: The key the store writes when the cap escalates. Reserved: a caller
#: cannot apply a restriction under it, so an escalation is always the
#: store's own and never forgeable by the thing that caused it.
CAP_ESCALATION_KEY = "aegis:restriction_cap"


class RestrictionKind(str, Enum):
    """What a restriction does. There is no third member on purpose."""

    #: Admits nothing. The grant retains registration and history but no
    #: usable authority until the restriction is lifted.
    SUSPEND = "suspend"

    #: Admits a subset: the request must satisfy additional constraints,
    #: and/or the action must match one of a set of patterns.
    NARROW = "narrow"


def _canonical(value: Any) -> str:
    """A stable string for deduplication, never for a security decision.

    ``json.dumps`` with sorted keys handles the shapes constraints
    actually take. Anything it cannot serialise falls back to ``repr``,
    which is weaker for dedup (two equal values may stringify
    differently) and harmless: a dedup miss stores one extra conjunct,
    which cannot widen anything.
    """

    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=repr)
    except (TypeError, ValueError):
        return repr(value)


def _freeze(mapping: Optional[Mapping]) -> Mapping:
    if not mapping:
        return MappingProxyType({})

    return MappingProxyType(dict(mapping))


@dataclass(frozen=True)
class Restriction:
    """One applied restriction, and why.

    Frozen, and ``constraints`` is wrapped in a ``MappingProxyType`` at
    construction, so a caller that keeps a reference to the dict it
    passed in cannot rewrite an applied restriction afterwards.
    """

    fingerprint: str
    kind: RestrictionKind
    key: str
    reason: str
    trigger: Optional[str] = None
    applied_at: float = field(default_factory=time.time)
    #: Additional constraints, evaluated by the boundary's own
    #: ``_check_constraints``. Keyed exactly as capability constraints
    #: are, because it is the same evaluator.
    constraints: Mapping = field(default_factory=dict)
    #: Capability patterns the action must match. Empty means no pattern
    #: restriction; a non-empty tuple that nothing matches denies.
    patterns: tuple[str, ...] = ()
    #: Monotone within a store, for ordering in explanations.
    sequence: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "constraints", _freeze(self.constraints))
        object.__setattr__(self, "patterns", tuple(self.patterns))

        if not isinstance(self.kind, RestrictionKind):
            raise ValueError(f"not a restriction kind: {self.kind!r}")

        if not self.fingerprint or not isinstance(self.fingerprint, str):
            raise ValueError("a restriction must name the grant it binds")

        if not self.key or not isinstance(self.key, str):
            raise ValueError("a restriction must carry a key, so it can be lifted")

        if self.kind is RestrictionKind.NARROW and not (
            self.constraints or self.patterns
        ):
            raise ValueError(
                "a NARROW restriction that narrows nothing would record a "
                "restriction that does not exist; use SUSPEND, or supply "
                "constraints or patterns"
            )

    @property
    def suspends(self) -> bool:
        return self.kind is RestrictionKind.SUSPEND

    def excludes(
        self,
        action: str,
        request: Any,
    ) -> Optional[str]:
        """Why this restriction refuses ``(action, request)``, or ``None``.

        Returns a reason string rather than a bool because the gate has
        to say what happened (§17), and because a bool would invite
        ``if not restriction.excludes(...)`` to be read as an allow.
        Nothing here allows: ``None`` means *this restriction* has no
        objection, and the remaining gates still run.
        """

        if self.suspends:
            return f"aegis_suspended:{self.key}"

        if self.patterns:
            if not isinstance(action, str) or not any(
                matches(pattern, action) for pattern in self.patterns
            ):
                return f"aegis_action_not_permitted:{self.key}"

        if self.constraints:
            try:
                admitted = _check_constraints(
                    dict(self.constraints),
                    request if isinstance(request, Mapping) else {},
                )
            except Exception:
                # A restriction that cannot be evaluated is not a
                # restriction that passes.
                return f"aegis_restriction_unreadable:{self.key}"

            if not admitted:
                return f"aegis_constraint_denied:{self.key}"

        return None

    def identity(self) -> tuple:
        """The dedup key: what the restriction *does*, not when."""

        return (
            self.key,
            self.kind.value,
            self.patterns,
            _canonical(dict(self.constraints)),
        )

    def describe(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "kind": self.kind.value,
            "key": self.key,
            "reason": self.reason,
            "trigger": self.trigger,
            "applied_at": self.applied_at,
            "constraints": dict(self.constraints),
            "patterns": list(self.patterns),
            "sequence": self.sequence,
        }


def suspend(
    fingerprint: str,
    *,
    key: str,
    reason: str,
    trigger: Optional[str] = None,
    at: Optional[float] = None,
) -> Restriction:
    """Build a ``SUSPEND``. A convenience, with no behaviour of its own."""

    return Restriction(
        fingerprint=fingerprint,
        kind=RestrictionKind.SUSPEND,
        key=key,
        reason=reason,
        trigger=trigger,
        applied_at=time.time() if at is None else float(at),
    )


def narrow(
    fingerprint: str,
    *,
    key: str,
    reason: str,
    constraints: Optional[Mapping] = None,
    patterns: Iterable[str] = (),
    trigger: Optional[str] = None,
    at: Optional[float] = None,
) -> Restriction:
    """Build a ``NARROW``. Raises if it would narrow nothing."""

    return Restriction(
        fingerprint=fingerprint,
        kind=RestrictionKind.NARROW,
        key=key,
        reason=reason,
        trigger=trigger,
        applied_at=time.time() if at is None else float(at),
        constraints=dict(constraints or {}),
        patterns=tuple(patterns),
    )
class RestrictionStore:
    """A lock-guarded, per-fingerprint set of active restrictions.

    Every public method takes the lock. Reads return immutable tuples, so
    a caller cannot hold a live view that changes underneath it -- and
    cannot write one back.
    """

    def __init__(self, *, max_per_grant: int = MAX_RESTRICTIONS_PER_GRANT) -> None:
        if not isinstance(max_per_grant, int) or max_per_grant < 1:
            raise ValueError("max_per_grant must be a positive integer")

        self._lock = threading.RLock()
        self._by_fingerprint: dict[str, tuple[Restriction, ...]] = {}
        self._sequence = 0
        self._max_per_grant = max_per_grant
        #: Every apply and lift, in order, for explanation and audit.
        self._journal: list[dict] = []

    # -- writes ------------------------------------------------------

    def apply(self, restriction: Restriction) -> tuple[Restriction, ...]:
        """Record ``restriction``; return the grant's resulting set.

        Idempotent on an identical restriction. Escalates to a single
        ``SUSPEND`` if the grant is at the cap.
        """

        if not isinstance(restriction, Restriction):
            raise TypeError("apply expects a Restriction")

        if restriction.key == CAP_ESCALATION_KEY:
            raise ValueError(
                f"{CAP_ESCALATION_KEY!r} is reserved for the store's own "
                f"cap escalation"
            )

        with self._lock:
            existing = self._by_fingerprint.get(restriction.fingerprint, ())
            identities = {item.identity() for item in existing}

            if restriction.identity() in identities:
                self._record("apply_deduplicated", restriction)
                return existing

            if any(item.key == CAP_ESCALATION_KEY for item in existing):
                # Already escalated. The grant admits nothing, so a
                # further conjunct changes no answer; recording it in the
                # set would let the set grow again behind a suspension
                # that already refuses everything. The journal keeps the
                # finding, which is where the explanation belongs.
                self._record("apply_ignored_while_capped", restriction)
                return existing

            self._sequence += 1
            stamped = Restriction(
                fingerprint=restriction.fingerprint,
                kind=restriction.kind,
                key=restriction.key,
                reason=restriction.reason,
                trigger=restriction.trigger,
                applied_at=restriction.applied_at,
                constraints=dict(restriction.constraints),
                patterns=restriction.patterns,
                sequence=self._sequence,
            )

            if len(existing) >= self._max_per_grant:
                escalated = Restriction(
                    fingerprint=restriction.fingerprint,
                    kind=RestrictionKind.SUSPEND,
                    key=CAP_ESCALATION_KEY,
                    reason=(
                        f"{len(existing)} distinct restrictions reached the "
                        f"per-grant cap; suspending rather than dropping "
                        f"{restriction.key!r}"
                    ),
                    trigger=restriction.trigger,
                    applied_at=stamped.applied_at,
                    sequence=self._sequence,
                )
                self._by_fingerprint[restriction.fingerprint] = (escalated,)
                self._record("apply_escalated_to_cap", escalated)
                return (escalated,)

            self._by_fingerprint[restriction.fingerprint] = existing + (stamped,)
            self._record("apply", stamped)

            return self._by_fingerprint[restriction.fingerprint]

    def lift(self, fingerprint: str, key: str) -> tuple[Restriction, ...]:
        """Remove every restriction on ``fingerprint`` under ``key``.

        The only operation in this module that widens. Returns what was
        removed, so a caller cannot lift blindly and report success: an
        empty tuple means there was nothing under that key.

        Bracketed by the authority epoch, so an authorization in flight
        when this runs refuses rather than answering from reads taken on
        both sides of it. The bracket is unconditional even though a lift
        that removes nothing widens nothing: the interval has to be open
        before the outcome is known, and the alternative -- deciding after
        the fact that this particular widening was harmless -- is the
        reasoning the epoch exists to stop trusting.
        """

        with record_widening(self, "aegis_restriction_lifted"):
            with self._lock:
                existing = self._by_fingerprint.get(fingerprint, ())
                removed = tuple(item for item in existing if item.key == key)
                kept = tuple(item for item in existing if item.key != key)

                if kept:
                    self._by_fingerprint[fingerprint] = kept
                else:
                    self._by_fingerprint.pop(fingerprint, None)

                for item in removed:
                    self._record("lift", item)

                return removed

    def clear(self, fingerprint: str) -> tuple[Restriction, ...]:
        """Remove every restriction on ``fingerprint``.

        Present for operator recovery and for test teardown. It widens,
        by design and by name -- there is no way to read ``clear`` as
        anything but removing restrictions. Epoch-bracketed for the same
        reason :meth:`lift` is.
        """

        with record_widening(self, "aegis_restrictions_cleared"):
            with self._lock:
                removed = self._by_fingerprint.pop(fingerprint, ())

                for item in removed:
                    self._record("clear", item)

                return removed
    # -- reads -------------------------------------------------------

    def restrictions_for(self, fingerprint: str) -> tuple[Restriction, ...]:
        with self._lock:
            return self._by_fingerprint.get(fingerprint, ())

    def suspended(self, fingerprint: str) -> bool:
        with self._lock:
            return any(
                item.suspends
                for item in self._by_fingerprint.get(fingerprint, ())
            )

    def any_suspended(self, fingerprints: Iterable[str]) -> Optional[str]:
        """The first suspended fingerprint in ``fingerprints``, or ``None``.

        Used by the commit-time re-check in ``_gate_transaction``, which
        needs the cheapest possible question: is anything in this chain
        suspended *now*.
        """

        with self._lock:
            for fingerprint in fingerprints:
                for item in self._by_fingerprint.get(fingerprint, ()):
                    if item.suspends:
                        return fingerprint

            return None

    def fingerprints(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._by_fingerprint)

    def excludes(
        self,
        fingerprints: Iterable[str],
        action: str,
        request: Any,
    ) -> Optional[tuple[Restriction, str]]:
        """The first restriction across the chain that refuses, and why.

        Takes the whole chain because a restriction on an ancestor binds
        every descendant. Evaluates under the lock so a concurrent apply
        cannot be half-observed; the evaluation is pure and bounded, so
        holding the lock across it costs nothing an authorization call
        would notice.

        ``None`` is *not* an allow. It means no restriction objected, and
        the rest of the gate chain still has to run.
        """

        with self._lock:
            ordered = self._ordered_for(fingerprints)

        for restriction in ordered:
            reason = restriction.excludes(action, request)

            if reason is not None:
                return restriction, reason

        return None

    def _ordered_for(
        self,
        fingerprints: Iterable[str],
    ) -> tuple[Restriction, ...]:
        """Suspensions first, then by application order.

        Caller holds the lock. Suspensions come first so that a
        suspended grant reports ``aegis_suspended`` rather than whichever
        narrowing happened to be applied earliest -- the reason a caller
        is shown should be the strongest one, not an arbitrary one.
        """

        collected: list[Restriction] = []
        seen: set[str] = set()

        for fingerprint in fingerprints:
            if not isinstance(fingerprint, str) or fingerprint in seen:
                continue

            seen.add(fingerprint)
            collected.extend(self._by_fingerprint.get(fingerprint, ()))

        return tuple(
            sorted(collected, key=lambda item: (not item.suspends, item.sequence))
        )

    # -- audit -------------------------------------------------------

    def _record(self, event: str, restriction: Restriction) -> None:
        """Caller holds the lock."""

        self._journal.append(
            {
                "event": event,
                "at": time.time(),
                "restriction": restriction.describe(),
            }
        )

        # The journal is an explanation aid, not evidence. Bound it, and
        # bound it by dropping the oldest rather than by refusing to
        # record -- an unbounded list in a long-lived process is a leak,
        # and losing old explanation text weakens nothing enforced.
        if len(self._journal) > 4096:
            del self._journal[: len(self._journal) - 4096]

    def journal(self) -> tuple[dict, ...]:
        with self._lock:
            return tuple(dict(entry) for entry in self._journal)

    def describe(self) -> dict:
        with self._lock:
            return {
                "max_per_grant": self._max_per_grant,
                "grants_restricted": len(self._by_fingerprint),
                "restrictions": {
                    fingerprint: [item.describe() for item in items]
                    for fingerprint, items in self._by_fingerprint.items()
                },
            }
