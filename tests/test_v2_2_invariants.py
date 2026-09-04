"""Tests for the v2.2 machine-checkable invariant suite.

The suite's own failure mode is the one worth testing hardest: a checker
that reports success when it established nothing would convert absent
verification into a security claim, and every subsequent green CI run
would be evidence of nothing. So these tests pin the three-valued status
as behaviour -- ``UNVERIFIABLE`` is falsy, makes the whole report falsy,
and raises from ``assert_all`` -- before they pin any individual
invariant.

The suite is also not an authorization authority. The last section pins
that ``check_all`` leaves the control plane untouched and changes no
``authorize`` verdict.
"""

from __future__ import annotations

import json

import pytest

from firewall.capability2.constraints import Capability2
from firewall.invariants import (
    INVARIANTS,
    InvariantStatus,
    InvariantViolation,
    assert_all,
    canonical_estate,
    check_all,
    control_plane_snapshot,
    invariant,
    narrowing_policy_history,
    unverifiable_names,
)
from firewall.invariants.__main__ import main as invariants_main
from firewall.sdk import FirewallSDK

#: The seventeen names, spelled out rather than derived from ``INVARIANTS``.
#:
#: Deriving them would make the completeness test tautological: deleting
#: an invariant would delete its expectation too and the suite would stay
#: green while checking less.
EXPECTED_INVARIANTS = frozenset(
    {
        "AUTHORIZATION_UNIQUENESS",
        "DELEGATION_MONOTONICITY",
        "REVOCATION_MONOTONICITY",
        "CAPABILITY_MONOTONICITY",
        "FAIL_CLOSED",
        "MODEL_NON_AUTHORITY",
        "SIMULATION_ISOLATION",
        "PROVENANCE_INTEGRITY",
        "EVIDENCE_INTEGRITY",
        "POLICY_NON_WIDENING",
        "CONTROL_PLANE_INTEGRITY",
        # v2.4 (Project Aegis)
        "UNKNOWN_NON_AUTHORIZATION",
        "ENVELOPE_SOUNDNESS",
        "ENVELOPE_MONOTONICITY",
        "AEGIS_STATE_TRANSITIONS",
        # v2.5 -- the stale allow no verdict census could see
        "REVALIDATION_CONSISTENCY",
        # v2.6 -- the store that widens and the boundary that samples it
        # must hold the same epoch, or the divergence check is decoration
        "AUTHORITY_EPOCH_COVERAGE",
    }
)

def _narrowing_policy_history() -> list[tuple[Capability2, Capability2]]:
    """One real narrowing policy transformation.

    POLICY_NON_WIDENING is ``UNVERIFIABLE`` without a history by design,
    so a report that holds must supply one.

    Delegates to :mod:`firewall.invariants.exercise`, which v2.3 made the
    single definition of the exercised estate. The history used to be
    duplicated here, which meant the shipped exerciser and the suite that
    proves the invariants have teeth could drift apart -- and the drift
    would show up as this suite still passing against an exerciser CI had
    stopped exercising.
    """

    return list(narrowing_policy_history())


def _widening_policy_history() -> list[tuple[Capability2, Capability2]]:
    """A transformation that adds an action the old policy did not allow."""

    return [
        (
            Capability2(
                capability="payments.send",
                constraints={"action": ["send"]},
            ),
            Capability2(
                capability="payments.send",
                constraints={"action": ["send", "refund"]},
            ),
        ),
    ]


def _seeded_sdk() -> FirewallSDK:
    """An SDK that has actually issued, delegated, attenuated, revoked.

    Every state-dependent invariant needs the state it is about to
    exist. A fresh SDK produces ``UNVERIFIABLE`` for six of the seventeen,
    which is correct and is pinned separately below -- so the seeding
    here is not test convenience, it is the precondition for the suite
    being able to say anything.

    The estate itself is :func:`firewall.invariants.canonical_estate`,
    which v2.3 promoted out of this file so CI could run
    ``--exercise --strict`` against the same state these tests use. It is
    deliberately awkward in three places: the revocation is mid-chain, so
    REVOCATION_MONOTONICITY has a descendant to propagate to instead of
    being satisfied by a revoked leaf; the attenuation hangs off the
    root with no signed parent fingerprint, so CAPABILITY_MONOTONICITY
    has an edge that DELEGATION_MONOTONICITY cannot see; and one Aegis
    grant is narrowed, lifted and then re-authorized, so
    AEGIS_STATE_TRANSITIONS has a real traversal of the one edge that
    raises residual authority rather than an algebra with nothing
    recorded under it.

    Sharing one definition means this suite now also guards the
    exerciser: an estate that stops reaching an invariant fails here as
    well as in the strict gate.
    """

    return canonical_estate().sdk


# ----------------------------------------------------------------------
# The registry is complete
# ----------------------------------------------------------------------


def test_all_seventeen_invariants_are_registered():
    """Seventeen named invariants, each appearing exactly once.

    An invariant with no registry entry is not checked by anything, and
    a duplicate name would let a passing entry hide a failing one from
    ``InvariantReport.get``.
    """

    names = [entry.name for entry in INVARIANTS]

    assert len(names) == len(set(names))
    assert set(names) == EXPECTED_INVARIANTS


def test_every_invariant_states_a_property():
    """Each entry carries a claim, not just a function reference.

    The statement is what is being promised. A registry of bare
    callables would leave the promise implicit in whatever the check
    happens to do, so a weakened check would silently weaken the claim.
    """

    for entry in INVARIANTS:
        assert entry.statement.strip()
        assert callable(entry.runner)


def test_unknown_invariant_name_raises():
    """Asking for an invariant that does not exist must not be silent."""

    with pytest.raises(KeyError):
        invariant("NO_SUCH_INVARIANT")

    assert invariant("FAIL_CLOSED").name == "FAIL_CLOSED"


# ----------------------------------------------------------------------
# Unverifiable is not passing
# ----------------------------------------------------------------------


def test_fresh_sdk_leaves_state_invariants_unverifiable():
    """A fresh SDK has no edges, so the report must not claim it is sound.

    This is the fail-open shape the three-valued status exists to
    prevent: "no violations found" over an empty registry is not a pass.
    """

    report = check_all(FirewallSDK())

    unverified = set(unverifiable_names(report))

    assert "DELEGATION_MONOTONICITY" in unverified
    assert "CAPABILITY_MONOTONICITY" in unverified
    assert "REVOCATION_MONOTONICITY" in unverified
    assert "POLICY_NON_WIDENING" in unverified

    assert report.violations == ()
    assert report.holds is False


def test_unverifiable_result_is_falsy_and_poisons_the_report():
    """``bool(result)`` and ``report.holds`` are true only for HOLDS.

    Pinned as behaviour because the natural mistake -- ``if not
    result.violated`` -- quietly accepts an unverifiable, and that
    reading would make the whole suite satisfiable by breaking the
    checker rather than by satisfying the invariants.
    """

    report = check_all()  # no SDK at all
    policy = report.get("POLICY_NON_WIDENING")

    assert policy is not None
    assert policy.status is InvariantStatus.UNVERIFIABLE
    assert bool(policy) is False
    assert policy.holds is False
    assert report.holds is False
    assert bool(report) is False


def test_assert_all_raises_on_unverifiable_not_only_on_violation():
    """Strictness is the point: an unexamined invariant fails the assert."""

    with pytest.raises(InvariantViolation) as caught:
        assert_all(FirewallSDK())

    report = caught.value.report

    assert report.violations == ()
    assert report.unverifiable
    assert "unverifiable" in report.summary()


# ----------------------------------------------------------------------
# All seventeen hold against a system that has been used
# ----------------------------------------------------------------------


def test_all_seventeen_invariants_hold_on_an_exercised_system():
    """The positive control for the whole suite.

    Without this, every other test here is satisfiable by a suite that
    reports failure unconditionally. With it, the ``UNVERIFIABLE`` tests
    above are known to be reporting a real distinction rather than a
    checker that never passes.
    """

    report = assert_all(
        _seeded_sdk(),
        policy_history=_narrowing_policy_history(),
    )

    assert report.holds is True
    assert len(report.results) == len(EXPECTED_INVARIANTS)
    assert report.violations == ()
    assert report.unverifiable == ()


def test_structural_invariants_hold_without_any_sdk():
    """The source-level claims do not depend on a running system.

    They are properties of every code path, so they must be checkable
    against a checkout. The seven state-dependent ones are then
    ``UNVERIFIABLE``, which keeps the report honest about what was
    examined.
    """

    report = check_all()

    for name in (
        "AUTHORIZATION_UNIQUENESS",
        "MODEL_NON_AUTHORITY",
        "CONTROL_PLANE_INTEGRITY",
        "PROVENANCE_INTEGRITY",
        "UNKNOWN_NON_AUTHORIZATION",
        "EVIDENCE_INTEGRITY",
        "FAIL_CLOSED",
        "ENVELOPE_SOUNDNESS",
        "REVALIDATION_CONSISTENCY",
    ):
        result = report.get(name)
        assert result is not None, name
        assert result.status is InvariantStatus.HOLDS, (
            name,
            result.reason,
            result.findings,
        )


# ----------------------------------------------------------------------
# The suite detects a real violation
# ----------------------------------------------------------------------


def test_widening_policy_history_is_reported_as_a_violation():
    """POLICY_NON_WIDENING has teeth, not just an unverifiable branch.

    An invariant that can only report ``HOLDS`` or ``UNVERIFIABLE`` has
    never been shown to distinguish a safe transformation from an unsafe
    one.
    """

    report = check_all(
        _seeded_sdk(),
        policy_history=_widening_policy_history(),
    )

    result = report.get("POLICY_NON_WIDENING")

    assert result is not None
    assert result.status is InvariantStatus.VIOLATED
    assert result.findings
    assert "widens" in " ".join(result.findings)
    assert report.holds is False


def test_a_crashing_check_reports_unverifiable_not_success():
    """A checker that raises has established nothing.

    ``Invariant.check`` converts the exception rather than letting it
    abort the run: a caller who saw an exception escape would get no
    findings at all and could not tell that from a clean report.
    """

    entry = invariant("FAIL_CLOSED")

    def exploding(sdk, policy_history):
        raise RuntimeError("checker is broken")

    broken = type(entry)(
        name=entry.name,
        statement=entry.statement,
        runner=exploding,
    )

    result = broken.check(None, None)

    assert result.status is InvariantStatus.UNVERIFIABLE
    assert result.name == "FAIL_CLOSED"
    assert "RuntimeError" in result.reason


# ----------------------------------------------------------------------
# The suite is not an authorization authority
# ----------------------------------------------------------------------


def test_running_the_suite_does_not_change_the_control_plane():
    """Checking the system must not be a way to modify it.

    Three of the seventeen checks probe hostile input and tamper with
    signed evidence, and SIMULATION_ISOLATION replays a delegation chain.
    All four do that on scratch instances precisely so this holds -- if
    any of them reached for the supplied SDK's containers, the snapshot
    would differ.

    The Aegis evidence probe is the sharpest case: it needs a genuine
    ``authorize()`` allow and a genuine denial to feed the evidence
    predicate, and it obtains both from a scratch SDK rather than from
    this one. Minting them here would leave flight records and refusal
    state behind.
    """

    sdk = _seeded_sdk()
    before = control_plane_snapshot(sdk)

    check_all(sdk, policy_history=_narrowing_policy_history())

    assert control_plane_snapshot(sdk) == before


def test_a_holding_report_grants_no_authority():
    """A green report does not make an unauthorized request allowed.

    ``FirewallSDK.authorize`` is the only decision point. The suite
    produces findings; it is not consulted by the gate chain and cannot
    change a verdict in either direction.
    """

    sdk = _seeded_sdk()
    capability = sdk.issue(
        agent="agent-fresh",
        capability="payments.send",
        constraints={"amount_max": 100},
    )

    report = check_all(sdk, policy_history=_narrowing_policy_history())
    assert report.holds is True

    # The allow probe runs first, deliberately. A denial trips
    # ``RefusalState``, after which every later call on this capability
    # returns ``refusal_state`` -- so the reverse order would test the
    # refusal machinery rather than this invariant.
    within = sdk.authorize(
        capability,
        action="payments.send",
        request={"amount": 10},
    )
    assert within.allowed is True

    # Over the ceiling: still denied, with the suite reporting sound.
    denied = sdk.authorize(
        capability,
        action="payments.send",
        request={"amount": 10_000},
    )
    assert denied.allowed is False


def test_a_violated_report_removes_no_authority():
    """Symmetrically, a failing report does not revoke anything.

    The suite reporting a problem is evidence for an operator to act on.
    Acting on it means calling ``revoke``; the report itself cannot.
    """

    sdk = _seeded_sdk()
    capability = sdk.issue(
        agent="agent-fresh",
        capability="payments.send",
        constraints={"amount_max": 100},
    )

    report = check_all(sdk, policy_history=_widening_policy_history())
    assert report.holds is False

    allowed = sdk.authorize(
        capability,
        action="payments.send",
        request={"amount": 10},
    )
    assert allowed.allowed is True

    sdk.revoke(capability)
    assert (
        sdk.authorize(
            capability,
            action="payments.send",
            request={"amount": 10},
        ).allowed
        is False
    )


# ----------------------------------------------------------------------
# The correction FAIL_CLOSED found
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "action",
    ["", "   ", "\t\n", None, 0, ["payments.send"]],
)
def test_unusable_action_is_denied_rather_than_raised(action):
    """``authorize`` returns a verdict for every input, including junk.

    FAIL_CLOSED found this: ``RefusalState.check_action`` validates its
    arguments and raised ``ValueError`` on an empty action, so
    ``authorize(cap, action="")`` raised from inside the first gate
    instead of denying. That breaks the gate chain's contract -- every
    gate decides or abstains -- and a caller wrapping ``authorize`` in
    ``except Exception`` would treat an unauthorized request as an
    infrastructure error with no verdict attached. Action names can
    originate in untrusted tool output, so it was reachable from
    outside.

    The fix is purely narrowing: none of these was ever authorized, and
    the namespace check would have denied them had the chain got that
    far.
    """

    sdk = FirewallSDK()
    sdk.generate_key("k")
    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={"amount_max": 100},
    )

    outcome = sdk.authorize(
        capability,
        action=action,
        request={"amount": 10},
    )

    assert outcome.allowed is False
    assert outcome.reason == "invalid_action"


# ----------------------------------------------------------------------
# The CI entry point
# ----------------------------------------------------------------------

def test_the_entry_point_exits_zero_on_a_source_only_run(capsys):
    """A source-only run gates the nine invariants that need no system.

    Exit 0 here is not a claim that the system is sound -- the seven
    state-dependent invariants are unverifiable without a running system,
    and the output says so. Exiting non-zero by default would make the
    only usable CI gate a red one, and a permanently red gate is ignored.
    """

    code = invariants_main([])
    printed = capsys.readouterr().out

    assert code == 0
    assert "unverifiable" in printed
    assert "Unverifiable is not a pass" in printed


def test_strict_refuses_to_pass_what_it_could_not_check(capsys):
    """``--strict`` is ``assert_all``: unverifiable is a failure, and its
    exit code is distinct from a violation so CI can tell a wiring gap
    from a security defect."""

    code = invariants_main(["--strict"])
    capsys.readouterr()

    assert code == 2


def test_the_entry_point_lists_every_invariant(capsys):
    code = invariants_main(["--list"])
    printed = capsys.readouterr().out

    assert code == 0
    for name in EXPECTED_INVARIANTS:
        assert name in printed
    assert "needs live state" in printed


def test_the_json_report_names_every_invariant(capsys):
    code = invariants_main(["--json"])
    payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert {item["name"] for item in payload["results"]} == EXPECTED_INVARIANTS
    # holds is false on a source-only run: seven invariants were not
    # established, and the report will not claim otherwise.
    assert payload["holds"] is False


def test_a_violation_outranks_an_unverifiable_in_the_exit_code(monkeypatch):
    """A violated invariant must exit 1 even when unverifiables are also
    present, and even without ``--strict``: a security defect is not
    downgraded by a wiring gap sitting next to it."""

    from firewall.invariants import __main__ as entry
    from firewall.invariants.model import InvariantReport, unverifiable, violated

    report = InvariantReport(
        results=(
            violated("FAIL_CLOSED", "a probe was authorized"),
            unverifiable("POLICY_NON_WIDENING", "no history supplied"),
        ),
        checked_at=0.0,
    )
    monkeypatch.setattr(entry, "check_all", lambda *a, **k: report)

    assert entry.main([]) == 1
    assert entry.main(["--strict"]) == 1
