"""The seventeen named security invariants, and the suite that runs them.

Each invariant is a claim about every execution of the platform, stated
here in one sentence and checked by exactly one function. The registry
exists so the claims live in one place instead of being implied by the
set of functions that happen to exist: an invariant with no check is a
missing entry rather than a silently absent property, and a check with no
invariant has nowhere to be called from.

Nothing in this module can grant authority. :func:`check_all` reads
source text and live state and returns an
:class:`~firewall.invariants.model.InvariantReport`; it constructs no
``AuthorizationResult`` and mutates no control-plane container. The
AUTHORIZATION_UNIQUENESS and CONTROL_PLANE_INTEGRITY invariants it ships
would flag it if it did.

Two properties of the suite matter as much as the individual checks.

**Unverifiable is not passing.** :attr:`InvariantReport.holds` is false
whenever any invariant is ``UNVERIFIABLE``, and :func:`assert_all`
raises on it. Eight of the seventeen need state to examine -- delegation
edges, an attenuation, a revocation, a policy transformation, a
simulation, an authority envelope either side of a lineage edge, a
recorded Aegis history -- and a fresh SDK has none, so a green report
requires an SDK that has actually been used.

**Every check is called the same way.** Each runner takes the SDK and
the policy history whether or not it needs them, so no invariant can be
skipped because the caller did not know to pass it something.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Optional, Sequence

from firewall.invariants import runtime, static
from firewall.invariants.model import (
    InvariantReport,
    InvariantResult,
    InvariantStatus,
    InvariantViolation,
)
from firewall.sdk import FirewallSDK

#: Signature every invariant runner conforms to.
Runner = Callable[
    [Optional[FirewallSDK], Optional[Sequence[Any]]],
    InvariantResult,
]


@dataclass(frozen=True)
class Invariant:
    """One named invariant: the claim, why it matters, and its check.

    ``statement`` is written as a property that must hold, not as a
    description of the check. The distinction matters when a check is
    later strengthened: the statement is the thing being promised, and a
    check that no longer establishes it is a gap to be reported rather
    than a redefinition of the promise.

    ``needs_state`` records whether the invariant is about live state
    rather than about source text or a pure algebra. It is documentation
    for the caller who gets an ``UNVERIFIABLE`` and needs to know
    whether the fix is to wire something up or to exercise the system.
    """

    name: str
    statement: str
    runner: Runner
    needs_state: bool = False

    def check(
        self,
        sdk: Optional[FirewallSDK] = None,
        policy_history: Optional[Sequence[Any]] = None,
    ) -> InvariantResult:
        """Run the check, converting a crash into ``UNVERIFIABLE``.

        A checker that raises has established nothing, and the honest
        report of "established nothing" is ``UNVERIFIABLE``. Letting the
        exception escape would abort the remaining invariants, which is
        the one outcome worse than an incomplete report: a caller would
        see no findings at all and could not tell that from a clean run.
        """

        try:
            return self.runner(sdk, policy_history)
        except Exception as error:  # noqa: BLE001
            from firewall.invariants.model import unverifiable

            return unverifiable(
                self.name,
                f"the check itself raised {type(error).__name__}: "
                f"{error}",
            )


def _static(
    check: Callable[[], InvariantResult],
) -> Runner:
    """Adapt a no-argument static check to the uniform runner signature."""

    def runner(
        sdk: Optional[FirewallSDK],
        policy_history: Optional[Sequence[Any]],
    ) -> InvariantResult:
        return check()

    return runner


def _live(
    name: str,
    check: Callable[[FirewallSDK], InvariantResult],
) -> Runner:
    """Adapt a check that requires a live SDK.

    Without an SDK the property is unverifiable rather than satisfied:
    the individual checks already refuse a duck-typed stand-in, and
    refusing ``None`` here is the same rule one level up. ``name`` is
    passed explicitly so the result carries the invariant's name rather
    than the check function's.
    """

    def runner(
        sdk: Optional[FirewallSDK],
        policy_history: Optional[Sequence[Any]],
    ) -> InvariantResult:
        if sdk is None:
            from firewall.invariants.model import unverifiable

            return unverifiable(
                name,
                "no FirewallSDK was supplied, so live state could not "
                "be inspected",
            )

        return check(sdk)

    return runner


def _policy(
    sdk: Optional[FirewallSDK],
    policy_history: Optional[Sequence[Any]],
) -> InvariantResult:
    return runtime.check_policy_non_widening(
        sdk,
        policy_history=policy_history,
    )


def _aegis_transitions(
    sdk: Optional[FirewallSDK],
    policy_history: Optional[Sequence[Any]],
) -> InvariantResult:
    """AEGIS_STATE_TRANSITIONS, which is half algebra and half live state.

    Not adapted with :func:`_live`, which would short-circuit to
    ``UNVERIFIABLE`` before the algebra ran. The state machine's own rules
    -- terminal states are final, only an evidenced edge may widen, the
    evidence predicate accepts nothing but a canonical allow -- are
    properties of the code and are worth reporting on with or without a
    deployment to audit. The check itself decides what it could not
    establish and says which half is missing.
    """

    return runtime.check_aegis_state_transitions(sdk)


def _epoch_coverage(
    sdk: Optional[FirewallSDK],
    policy_history: Optional[Sequence[Any]],
) -> InvariantResult:
    """AUTHORITY_EPOCH_COVERAGE, also half source and half live state.

    Not adapted with :func:`_live` for the same reason as
    :func:`_aegis_transitions`: the census half is a property of the
    source and is worth reporting with or without a running system, and
    it is the half that fails when someone adds a widening write without
    bracketing it. Short-circuiting on a missing SDK would hide exactly
    the regression the invariant exists to catch.
    """

    return runtime.check_authority_epoch_coverage(sdk)


#: The seventeen invariants, in the order they are reported.
#:
#: Ordered structural-first: the three source-level invariants describe
#: the shape of the code and hold or fail regardless of what the SDK has
#: been asked to do, so a caller reading a failing report sees the
#: architectural findings before the state-dependent ones.
INVARIANTS: tuple[Invariant, ...] = (
    Invariant(
        name="AUTHORIZATION_UNIQUENESS",
        statement=(
            "An authorization verdict is constructed only inside the "
            "authorization boundary, and only in a declared function "
            "there. No subsystem -- risk, intel, twin, telemetry, UI, "
            "adapter -- can produce one, and an allow originates in "
            "exactly one place."
        ),
        runner=_static(static.check_authorization_uniqueness),
    ),
    Invariant(
        name="MODEL_NON_AUTHORITY",
        statement=(
            "Only the terminal gate may allow. Every other gate can "
            "deny or abstain, so adding a gate -- a model verdict, a "
            "risk score, a behavioural signal -- can only narrow "
            "authority, never widen it."
        ),
        runner=_static(static.check_model_non_authority),
    ),
    Invariant(
        name="CONTROL_PLANE_INTEGRITY",
        statement=(
            "Mutable control-plane state is reachable only through the "
            "SDK's own API. No subsystem holds the live capability, "
            "identity, task or posture container."
        ),
        runner=_static(static.check_control_plane_integrity),
    ),
    Invariant(
        name="PROVENANCE_INTEGRITY",
        statement=(
            "There is one provenance vocabulary, and combining claims "
            "never strengthens one: inferred is not observed, simulated "
            "is not observed, and an unrecognized label degrades to "
            "unknown."
        ),
        runner=_static(runtime.check_provenance_integrity),
    ),
    Invariant(
        name="UNKNOWN_NON_AUTHORIZATION",
        statement=(
            "Nothing the adaptive layer failed to establish is treated "
            "as benign: an unrecognized trigger, an unsized blast "
            "radius, a missing snapshot and a bottom envelope all "
            "resolve away from the permissive end, and no analysis "
            "object answers a truth test."
        ),
        runner=_static(runtime.check_unknown_non_authorization),
    ),
    Invariant(
        name="EVIDENCE_INTEGRITY",
        statement=(
            "Recorded evidence cannot be altered without verification "
            "failing and the alteration being named."
        ),
        runner=_static(runtime.check_evidence_integrity),
    ),
    Invariant(
        name="FAIL_CLOSED",
        statement=(
            "Hostile, malformed and unauthorized requests are denied "
            "with a verdict, and so is a legitimate request the boundary "
            "cannot evaluate because one of its own dependencies is "
            "unreadable. The authorization path never raises in place of "
            "deciding, on either verdict."
        ),
        runner=_static(runtime.check_fail_closed),
    ),
    Invariant(
        name="ENVELOPE_SOUNDNESS",
        statement=(
            "Whatever the authority envelope states is outside a grant, "
            "the canonical boundary denies. Sampled over a probe grid, "
            "and one-directional: an envelope that excludes nothing "
            "predicts nothing."
        ),
        runner=_static(runtime.check_envelope_soundness),
    ),
    Invariant(
        name="SIMULATION_ISOLATION",
        statement=(
            "A simulation leaves production control-plane state "
            "byte-identical and declares its decisions simulated."
        ),
        runner=_live(
            "SIMULATION_ISOLATION",
            runtime.check_simulation_isolation,
        ),
        needs_state=True,
    ),
    Invariant(
        name="DELEGATION_MONOTONICITY",
        statement=(
            "Every signed delegation edge agrees with the registered "
            "one and narrows: a delegated capability is never broader "
            "than the parent whose fingerprint it carries."
        ),
        runner=_live(
            "DELEGATION_MONOTONICITY",
            runtime.check_delegation_monotonicity,
        ),
        needs_state=True,
    ),
    Invariant(
        name="CAPABILITY_MONOTONICITY",
        statement=(
            "Every registered lineage edge narrows, including "
            "attenuation, which carries no signed parent and so is "
            "invisible to DELEGATION_MONOTONICITY."
        ),
        runner=_live(
            "CAPABILITY_MONOTONICITY",
            runtime.check_capability_monotonicity,
        ),
        needs_state=True,
    ),
    Invariant(
        name="ENVELOPE_MONOTONICITY",
        statement=(
            "Every lineage edge's child projects an authority envelope "
            "contained in its parent's, so no derivation widens the "
            "bound a caller reads to decide what a grant may still do."
        ),
        runner=_live(
            "ENVELOPE_MONOTONICITY",
            runtime.check_envelope_monotonicity,
        ),
        needs_state=True,
    ),
    Invariant(
        name="REVOCATION_MONOTONICITY",
        statement=(
            "Revocation propagates to every descendant and is never "
            "undone: a revoked capability's children are effectively "
            "revoked too."
        ),
        runner=_live(
            "REVOCATION_MONOTONICITY",
            runtime.check_revocation_monotonicity,
        ),
        needs_state=True,
    ),
    Invariant(
        name="POLICY_NON_WIDENING",
        statement=(
            "Every applied policy transformation narrowed authority or "
            "left it unchanged."
        ),
        runner=_policy,
        needs_state=True,
    ),
    Invariant(
        name="AEGIS_STATE_TRANSITIONS",
        statement=(
            "No Aegis state transition returns authority a previous one "
            "removed, except across an evidenced edge carrying a "
            "canonical FirewallSDK.authorize() allow for that same "
            "capability. Revocation and expiry are final, and every "
            "recorded history is legal."
        ),
        runner=_aegis_transitions,
        needs_state=True,
    ),
    Invariant(
        name="REVALIDATION_CONSISTENCY",
        statement=(
            "Continuous revalidation never reports an authority the "
            "canonical boundary denies. Sampled over security-state "
            "changes, and one-directional: the engine may report a "
            "denial where the boundary allows, because it subtracts on "
            "unreadable state, but never the reverse."
        ),
        runner=_static(runtime.check_revalidation_consistency),
    ),
    Invariant(
        name="AUTHORITY_EPOCH_COVERAGE",
        statement=(
            "Every write that can widen authority opens an authority "
            "epoch interval, and every store an SDK wires is bound to "
            "the epoch its boundary samples, so a widening cannot land "
            "between two of an authorization's reads without the "
            "boundary observing it and denying."
        ),
        runner=_epoch_coverage,
        needs_state=True,
    ),
)


def invariant(name: str) -> Invariant:
    """Look up one invariant by name.

    Raises ``KeyError`` rather than returning ``None``: a caller asking
    for an invariant that does not exist has a typo or a stale name, and
    silently checking nothing is the failure mode this package exists to
    prevent.
    """

    for entry in INVARIANTS:
        if entry.name == name:
            return entry

    raise KeyError(
        f"unknown invariant {name!r}; known: "
        f"{[entry.name for entry in INVARIANTS]}"
    )


def check_all(
    sdk: Optional[FirewallSDK] = None,
    *,
    policy_history: Optional[Sequence[Any]] = None,
) -> InvariantReport:
    """Run all seventeen invariants and return the report.

    Never raises for a failing invariant -- a violation is data, and a
    caller inspecting a report is the normal case. Use
    :func:`assert_all` to turn failures into an exception.

    ``sdk`` is optional so the three structural invariants and the five
    self-contained probes can be run against a source checkout with no
    running system, but the seven state-dependent invariants will then
    report ``UNVERIFIABLE`` and :attr:`InvariantReport.holds` will be
    false. That is the intended behaviour: a report cannot claim the
    system is sound while most of it was never examined.
    """

    return InvariantReport(
        results=tuple(
            entry.check(sdk, policy_history) for entry in INVARIANTS
        ),
        checked_at=time.time(),
    )


def assert_all(
    sdk: Optional[FirewallSDK] = None,
    *,
    policy_history: Optional[Sequence[Any]] = None,
) -> InvariantReport:
    """Run all seventeen invariants; raise unless every one ``HOLDS``.

    Raises :class:`~firewall.invariants.model.InvariantViolation` on a
    violation *or* an unverifiable result. Accepting unverifiables here
    would make the assertion satisfiable by breaking the checker, which
    is a strictly easier attack than satisfying the invariants.
    """

    report = check_all(sdk, policy_history=policy_history)

    if report.holds:
        return report

    raise InvariantViolation(report.summary(), report)


def unverifiable_names(report: InvariantReport) -> tuple[str, ...]:
    """Names of invariants the report could not establish.

    Convenience for a caller that wants to say "wire these up" rather
    than print the whole report.
    """

    return tuple(
        item.name
        for item in report.results
        if item.status is InvariantStatus.UNVERIFIABLE
    )
