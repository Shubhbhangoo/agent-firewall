"""Scheduled decay: the only form of authority decay Aegis implements.

§8 permits authority decay and requires that, if implemented, it be
deterministic and explainable, with no arbitrary risk score that secretly
becomes authorization. Decay *as an independent shrinking of granted
authority over time* is rejected outright and the reason is structural
rather than stylistic: ``expires_at`` already exists, is covered by the
capability signature, and is enforced by ``_gate_time`` and by
``CapabilityVerifier.verify`` for every chain member. A second clock
deciding when authority ends would be a competing representation of the
same security concept -- exactly what the standing constraints forbid.

What is implemented instead is a schedule an operator writes:

    narrow_after   seconds after the grant's start, apply this narrowing
    suspend_after  seconds after the grant's start, suspend

It satisfies §8 by construction rather than by testing:

* **Deterministic.** :meth:`DecaySchedule.stage_at` is a pure function of
  one float. Same elapsed time, same stage, always.
* **Explainable.** The schedule *is* the explanation. There is no model,
  no weighting, and no number that is not one the operator typed.
* **Monotone.** ``narrow_after <= suspend_after`` is validated at
  construction, so the stage sequence can only run
  ``NONE -> NARROW -> SUSPEND``. It cannot run backwards, which is what
  makes it safe to apply repeatedly: re-evaluating an old schedule can
  never restore authority.
* **Opt-in.** A grant with no schedule decays not at all, so the default
  behaviour of the system is unchanged.
* **Subtractive.** The output is a
  :class:`~firewall.aegis.restriction.Restriction` -- the same type the
  classifier produces, enforced by the same deny-only gate. There is no
  code path from a schedule to an allow.

An unreadable clock
-------------------

``stage_at`` is given elapsed time, not a clock, so it cannot itself be
fooled. But a caller can hand it ``nan``, or a negative value from a clock
that moved backwards. Both resolve to the **most severe stage the schedule
defines**, because a schedule whose position cannot be determined has not
been shown to be in its permissive phase. An operator who opts into decay
accepts that a broken clock suspends rather than extends -- which is the
same reading ``EXPIRED`` gets in the state machine, where latching is
preferred to re-deriving from a clock that may run backwards.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Iterable, Mapping, Optional

from firewall.aegis.restriction import Restriction, narrow, suspend


class DecayStage(str, Enum):
    """Where a grant sits on its schedule. Ordered, and only forwards."""

    NONE = "none"
    NARROW = "narrow"
    SUSPEND = "suspend"


DECAY_STAGE_SEVERITY: Mapping[DecayStage, int] = {
    DecayStage.NONE: 0,
    DecayStage.NARROW: 1,
    DecayStage.SUSPEND: 2,
}


def _positive_finite(value: object, label: str) -> Optional[float]:
    if value is None:
        return None

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a number of seconds")

    number = float(value)

    if not math.isfinite(number):
        raise ValueError(f"{label} must be finite")

    if number < 0:
        raise ValueError(f"{label} must not be negative")

    return number


@dataclass(frozen=True)
class DecaySchedule:
    """An operator-authored decay schedule for one grant or many.

    ``narrow_after`` and ``suspend_after`` are offsets in seconds from the
    grant's start. Either may be omitted; omitting both is a schedule that
    does nothing, which is refused rather than silently accepted -- an
    inert schedule attached to a grant would misrepresent the grant as
    decaying.
    """

    narrow_after: Optional[float] = None
    suspend_after: Optional[float] = None
    #: What the narrowing narrows to. Same shape as capability
    #: constraints, because the same evaluator reads it.
    constraints: Mapping = field(default_factory=dict)
    #: Capability patterns the action must match once narrowed.
    patterns: tuple[str, ...] = ()
    #: Restriction key, so a decay restriction can be lifted by name.
    key: str = "aegis:decay"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "narrow_after",
            _positive_finite(self.narrow_after, "narrow_after"),
        )
        object.__setattr__(
            self,
            "suspend_after",
            _positive_finite(self.suspend_after, "suspend_after"),
        )
        object.__setattr__(
            self,
            "constraints",
            MappingProxyType(dict(self.constraints or {})),
        )
        object.__setattr__(self, "patterns", tuple(self.patterns))

        if self.narrow_after is None and self.suspend_after is None:
            raise ValueError(
                "a decay schedule must define narrow_after, suspend_after, or "
                "both; an inert schedule would record decay that never happens"
            )

        if (
            self.narrow_after is not None
            and self.suspend_after is not None
            and self.suspend_after < self.narrow_after
        ):
            raise ValueError(
                f"suspend_after ({self.suspend_after}) precedes narrow_after "
                f"({self.narrow_after}); decay must be monotone"
            )

        if self.narrow_after is not None and not (self.constraints or self.patterns):
            raise ValueError(
                "narrow_after requires constraints or patterns to narrow to"
            )

        if not self.key or not isinstance(self.key, str):
            raise ValueError("a decay schedule must carry a restriction key")

    @property
    def strongest_stage(self) -> DecayStage:
        """The most severe stage this schedule can ever reach."""

        if self.suspend_after is not None:
            return DecayStage.SUSPEND

        return DecayStage.NARROW

    def stage_at(self, elapsed: object) -> DecayStage:
        """Which stage ``elapsed`` seconds places this grant in.

        Non-decreasing in ``elapsed`` for every valid input, and
        :attr:`strongest_stage` for every invalid one.
        """

        if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)):
            return self.strongest_stage

        try:
            seconds = float(elapsed)
        except (OverflowError, ValueError):
            # An int too large for a float. Mathematically finite, but not
            # a reading this schedule can place, and the promise above is
            # the strongest stage for every input it cannot place.
            return self.strongest_stage

        if not math.isfinite(seconds) or seconds < 0:
            return self.strongest_stage

        if self.suspend_after is not None and seconds >= self.suspend_after:
            return DecayStage.SUSPEND

        if self.narrow_after is not None and seconds >= self.narrow_after:
            return DecayStage.NARROW

        return DecayStage.NONE

    def restriction_at(
        self,
        fingerprint: str,
        elapsed: object,
        *,
        at: Optional[float] = None,
    ) -> Optional[Restriction]:
        """The restriction this schedule calls for, or ``None``.

        ``None`` means the schedule has nothing to apply yet. It does not
        mean the grant is authorized -- nothing in this module says
        anything about authorization.
        """

        stage = self.stage_at(elapsed)

        if stage is DecayStage.NONE:
            return None

        if stage is DecayStage.SUSPEND:
            return suspend(
                fingerprint,
                key=self.key,
                reason=(
                    f"decay schedule: suspend_after {self.suspend_after}s "
                    f"reached"
                ),
                trigger="time",
                at=at,
            )

        return narrow(
            fingerprint,
            key=self.key,
            reason=f"decay schedule: narrow_after {self.narrow_after}s reached",
            constraints=dict(self.constraints),
            patterns=self.patterns,
            trigger="time",
            at=at,
        )

    def describe(self) -> dict:
        return {
            "narrow_after": self.narrow_after,
            "suspend_after": self.suspend_after,
            "constraints": dict(self.constraints),
            "patterns": list(self.patterns),
            "key": self.key,
            "strongest_stage": self.strongest_stage.value,
        }


def stages_are_monotone(
    schedule: DecaySchedule,
    samples: Iterable[float],
) -> bool:
    """Does ``stage_at`` never decrease over ``samples`` in order?

    Exported so a test -- and the AEGIS_STATE_TRANSITIONS invariant --
    can check the property on real schedules rather than trusting the
    construction-time validation alone.
    """

    highest = -1

    for sample in samples:
        severity = DECAY_STAGE_SEVERITY[schedule.stage_at(sample)]

        if severity < highest:
            return False

        highest = max(highest, severity)

    return True
