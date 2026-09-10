"""Replay recorded requests under two rule sets and compare.

The method is deliberately boring, because the interesting part must not
be clever:

1. For each case, build a throwaway in-memory workspace and reconstruct
   the capability chain the case describes.
2. Apply the rule set *after* the chain exists -- which is the real
   sequence of events, since a rule change always arrives after the
   authority it governs was granted.
3. Call the real ``FirewallSDK.authorize()`` and keep whatever it says.

Two properties are worth stating outright.

**Isolation.** Every case gets its own workspace, per rule set. Refusal
memoization, replay protection, and delegation budgets are real,
persistent security state; sharing one workspace across cases would make
a simulation's answer depend on the order the cases happened to be
recorded in. Fresh workspaces cost more and are the only correct choice.

**Fidelity is measured, not assumed.** A replay re-issues capabilities
with a simulation key, so it reproduces the facts the gates reason about
rather than the original bytes. Rather than guess where that breaks, each
case is first replayed under the *current* rules and compared against the
decision that was actually observed. Cases that fail that check are
reported but never counted toward a claim about the rule change.
"""

from __future__ import annotations

import time
from typing import Any, Iterable

from firewall.capability import Capability
from firewall.sdk import FirewallSDK
from firewall.simulation.case import (
    CaseSet,
    RequestCase,
    SimulationError,
)
from firewall.simulation.report import (
    ERRORED,
    NEWLY_ALLOWED,
    NEWLY_DENIED,
    REASON_CHANGED,
    UNCHANGED,
    CaseOutcome,
    SimulationReport,
)
from firewall.simulation.ruleset import RuleSet

#: Ceiling on cases per simulation. Each case builds two isolated
#: workspaces, so this bounds the cost of a single browser request.
MAX_CASES = 200

#: Key used to sign reconstructed capabilities inside a replay workspace.
#: It exists only for the lifetime of one case and never leaves it.
SIMULATION_KEY_ID = "simulation-key"

#: Bound on an error string copied into a report.
MAX_ERROR = 200


def simulate(
    cases: Iterable[RequestCase] | CaseSet,
    before: RuleSet,
    after: RuleSet,
    *,
    limit: int = MAX_CASES,
) -> SimulationReport:
    """Replay ``cases`` under ``before`` and ``after`` and compare."""

    if not isinstance(before, RuleSet) or not isinstance(
        after,
        RuleSet,
    ):
        raise SimulationError(
            "before and after must be RuleSet values"
        )

    if isinstance(limit, bool) or not isinstance(
        limit,
        int,
    ):
        raise SimulationError(
            "limit must be an integer"
        )

    if limit <= 0:
        raise SimulationError(
            "limit must be positive"
        )

    ordered = list(cases)

    for case in ordered:
        if not isinstance(case, RequestCase):
            raise SimulationError(
                "cases must be RequestCase values"
            )

    selected = ordered[:limit]
    skipped = len(ordered) - len(selected)

    outcomes = tuple(
        _replay_one(case, before, after)
        for case in selected
    )

    report = SimulationReport(
        before=before.to_dict(),
        after=after.to_dict(),
        diff=before.diff(after),
        description=tuple(
            before.describe(after)
        ),
        outcomes=outcomes,
        skipped=skipped,
        caveats=_caveats(
            selected,
            before,
            outcomes,
            skipped,
            limit,
        ),
    )

    return report


def simulate_change(
    sdk: Any,
    cases: Iterable[RequestCase] | CaseSet,
    *,
    limit: int = MAX_CASES,
    **changes: Any,
) -> SimulationReport:
    """Simulate a change relative to what ``sdk`` enforces right now.

    This never touches ``sdk``: the live rules are only read, to form the
    ``before`` side of the comparison.
    """

    before = RuleSet.from_sdk(sdk)

    return simulate(
        cases,
        before,
        before.replace(**changes),
        limit=limit,
    )


# ----------------------------------------------------------------------
# One case
# ----------------------------------------------------------------------


def _replay_one(
    case: RequestCase,
    before: RuleSet,
    after: RuleSet,
) -> CaseOutcome:
    shared = {
        "case_id": case.case_id,
        "action": case.action,
        "capability": case.capability,
        "agent": case.agent,
        "agents": case.agents,
        "depth": case.depth,
        "baseline_reason": case.baseline_reason,
        "reproducible": case.reproducible,
        "note": case.note,
    }

    try:
        before_allowed, before_reason = _evaluate(
            case,
            before,
        )
        after_allowed, after_reason = _evaluate(
            case,
            after,
        )
    except Exception as exc:
        return CaseOutcome(
            change=ERRORED,
            faithful=False,
            error=(
                f"{type(exc).__name__}: "
                f"{str(exc)[:MAX_ERROR]}"
            ),
            **shared,
        )

    # Faithful when the replay, under today's rules, lands on the same
    # reason the live pipeline actually gave. An unrecorded baseline
    # cannot be checked, so it is not treated as verified.
    faithful = (
        case.baseline_reason is not None
        and before_reason == case.baseline_reason
    )

    if before_allowed and not after_allowed:
        change = NEWLY_DENIED
    elif not before_allowed and after_allowed:
        change = NEWLY_ALLOWED
    elif before_reason != after_reason:
        change = REASON_CHANGED
    else:
        change = UNCHANGED

    return CaseOutcome(
        change=change,
        before_allowed=before_allowed,
        before_reason=before_reason,
        after_allowed=after_allowed,
        after_reason=after_reason,
        faithful=faithful,
        **shared,
    )


def _evaluate(
    case: RequestCase,
    rules: RuleSet,
) -> tuple[bool, str]:
    """Build an isolated workspace, apply ``rules``, authorize."""

    sdk = FirewallSDK(
        trusted_issuers={case.issuer},
    )

    try:
        sdk.generate_key(SIMULATION_KEY_ID)
        private_key = sdk.active_key().private_key

        chain = _materialize(
            sdk,
            case,
            private_key,
        )

        # Revocations belong to the artifact, not to the rules, so they
        # are applied while the chain is being built. Transitive effects
        # are left for the revocation gate to derive.
        revoked = set(case.revoked_agents)

        for member in chain:
            if member.agent_id in revoked:
                sdk.revoke(
                    member,
                    reason="recorded revocation",
                )

        # Rules land last: a rule change always arrives after the
        # authority it governs was granted.
        rules.apply_to(sdk)

        result = sdk.authorize(
            chain[-1],
            case.action,
            dict(case.request),
        )

        return bool(result.allowed), str(
            result.reason
        )
    finally:
        _close(sdk)


def _materialize(
    sdk: FirewallSDK,
    case: RequestCase,
    private_key: Any,
) -> tuple[Capability, ...]:
    """Rebuild the case's capability chain in a fresh workspace."""

    root = sdk.issue(
        agent=case.root_agent,
        capability=case.capability,
        private_key=private_key,
        constraints=dict(case.root_constraints),
        issuer=case.issuer,
        tool=case.tool,
        expires_at=time.time() + case.lifetime,
    )

    chain = [root]

    for hop in case.hops:
        parent = chain[-1]

        # Re-delegating with constraints identical to the parent's is a
        # no-op narrowing that attenuation may reject, so pass None and
        # let inheritance do it.
        narrowing = (
            None
            if hop.constraints
            == dict(parent.constraints or {})
            else dict(hop.constraints)
        )

        chain.append(
            sdk.delegate(
                parent,
                private_key,
                delegatee=hop.delegatee,
                constraints=narrowing,
            ).child
        )

    return tuple(chain)


def _close(sdk: FirewallSDK) -> None:
    try:
        sdk.close()
    except Exception:
        # A throwaway workspace failing to close must not mask the
        # decision it just produced.
        pass


# ----------------------------------------------------------------------
# Caveats
# ----------------------------------------------------------------------


def _caveats(
    cases: list[RequestCase],
    before: RuleSet,
    outcomes: tuple[CaseOutcome, ...],
    skipped: int,
    limit: int,
) -> tuple[str, ...]:
    """State the limits of this report, in the report."""

    caveats: list[str] = [
        "Replayed capabilities are re-signed with a simulation key, so "
        "this report cannot speak to failures of the original "
        "signatures.",
    ]

    if skipped:
        caveats.append(
            f"{skipped} case(s) were not replayed: the case set "
            f"exceeded the {limit}-case limit for one simulation."
        )

    expired = [
        outcome
        for outcome in outcomes
        if not outcome.reproducible
    ]

    if expired:
        caveats.append(
            f"{len(expired)} case(s) were already expired when "
            "recorded; a fresh workspace cannot re-create an expired "
            "capability, so they are excluded from the counts."
        )

    unfaithful = [
        outcome
        for outcome in outcomes
        if outcome.error is None
        and outcome.reproducible
        and not outcome.faithful
    ]

    if unfaithful:
        missing = [
            outcome
            for outcome in unfaithful
            if outcome.baseline_reason is None
        ]
        diverged = len(unfaithful) - len(missing)

        if missing:
            caveats.append(
                f"{len(missing)} case(s) recorded no observed "
                "decision, so the replay could not be checked against "
                "reality and is not counted."
            )

        if diverged:
            caveats.append(
                f"{diverged} case(s) replayed to a different reason "
                "than was originally observed, so the simulator does "
                "not stand behind them."
            )

    errored = [
        outcome
        for outcome in outcomes
        if outcome.error is not None
    ]

    if errored:
        caveats.append(
            f"{len(errored)} case(s) could not be replayed at all."
        )

    untrusted = sorted(
        {
            case.issuer
            for case in cases
            if case.issuer
            not in before.trusted_issuers
        }
    )

    if untrusted:
        caveats.append(
            "The 'before' rule set does not trust "
            + ", ".join(untrusted)
            + ", so cases from those issuers are denied on both sides "
            "and cannot show a change."
        )

    return tuple(caveats)
