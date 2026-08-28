"""Tests for the v1.7 rule simulation engine (``firewall.simulation``).

Pins the properties that make simulation safe to trust before enforcing:

* a case is the material facts of a request, not a credential -- it
  serializes without signatures or key material and survives a JSON round
  trip;
* a rule set holds exactly the two globally scoped rules the real gates
  enforce, and can never hold a value the SDK would refuse;
* replay measures its own fidelity against the decision that was actually
  observed, and a report never counts a case it could not stand behind;
* ``simulate`` is read-only with respect to any live SDK and isolates
  every replay in its own workspace, so the answer cannot depend on case
  order or on shared security state.

No pre-existing test is modified by this file.
"""

from __future__ import annotations

import json
import time

import pytest

from firewall.sdk import FirewallSDK
from firewall.simulation import (
    MAX_CASES,
    CaseRecorder,
    CaseSet,
    DelegationHop,
    RequestCase,
    RuleSet,
    SimulationError,
    simulate,
    simulate_change,
)
from firewall.simulation.report import (
    ERRORED,
    NEWLY_ALLOWED,
    NEWLY_DENIED,
    REASON_CHANGED,
    UNCHANGED,
)


# ======================================================================
# Fixtures and helpers
# ======================================================================


@pytest.fixture()
def sdk() -> FirewallSDK:
    """A disposable in-memory SDK with a signing key."""

    instance = FirewallSDK(
        trusted_issuers={"trusted-issuer"}
    )
    instance.generate_key("test-key")
    return instance


def record_chain(
    sdk: FirewallSDK,
    *,
    agents: tuple[str, ...],
    capability: str = "pay.send",
    action: str = "pay.send",
    request: dict | None = None,
    constraints: dict | None = None,
) -> RequestCase:
    """Authorize a real delegation chain and record the observed verdict."""

    pk = sdk.active_key().private_key
    root = sdk.issue(
        agent=agents[0],
        capability=capability,
        private_key=pk,
        issuer="trusted-issuer",
        constraints=constraints,
    )

    chain = [root]

    for delegatee in agents[1:]:
        chain.append(
            sdk.delegate(
                chain[-1],
                pk,
                delegatee=delegatee,
            ).child
        )

    decision = sdk.authorize(
        chain[-1],
        action,
        dict(request or {}),
    )

    recorder = CaseRecorder()

    return recorder.record(
        sdk,
        chain[-1],
        action,
        request,
        decision,
    )


def record_cases(
    sdk: FirewallSDK,
    *agents: tuple[str, ...],
) -> CaseSet:
    recorder = CaseRecorder()

    for chain_agents in agents:
        pk = sdk.active_key().private_key
        root = sdk.issue(
            agent=chain_agents[0],
            capability="pay.send",
            private_key=pk,
            issuer="trusted-issuer",
        )

        members = [root]

        for delegatee in chain_agents[1:]:
            members.append(
                sdk.delegate(
                    members[-1],
                    pk,
                    delegatee=delegatee,
                ).child
            )

        decision = sdk.authorize(
            members[-1],
            "pay.send",
            {},
        )

        recorder.record(
            sdk,
            members[-1],
            "pay.send",
            {},
            decision,
        )

    return recorder.cases()


def evaluate(
    case: RequestCase,
    rules: RuleSet,
) -> tuple[bool, str]:
    """Replay one case under one rule set, like ``simulate`` does."""

    from firewall.simulation.replay import _evaluate

    return _evaluate(case, rules)


# ======================================================================
# RequestCase: validation
# ======================================================================


def test_case_requires_the_material_fields() -> None:
    for missing in (
        "case_id",
        "action",
        "capability",
        "root_agent",
    ):
        payload = {
            "case_id": "c1",
            "action": "pay.send",
            "capability": "pay.send",
            "root_agent": "agent-a",
        }
        del payload[missing]

        with pytest.raises(SimulationError):
            RequestCase.from_dict(payload)


def test_case_rejects_blank_required_text() -> None:
    with pytest.raises(SimulationError):
        RequestCase(
            case_id=" ",
            action="pay.send",
            capability="pay.send",
            root_agent="agent-a",
        )


def test_case_rejects_overlong_text() -> None:
    with pytest.raises(SimulationError):
        RequestCase(
            case_id="c1",
            action="x" * 201,
            capability="pay.send",
            root_agent="agent-a",
        )


def test_case_rejects_non_json_serializable_maps() -> None:
    with pytest.raises(SimulationError):
        RequestCase(
            case_id="c1",
            action="pay.send",
            capability="pay.send",
            root_agent="agent-a",
            request={"amount": object()},
        )


def test_case_rejects_a_non_dict_request() -> None:
    with pytest.raises(SimulationError):
        RequestCase(
            case_id="c1",
            action="pay.send",
            capability="pay.send",
            root_agent="agent-a",
            request=["not", "a", "map"],
        )


def test_case_rejects_non_string_map_keys() -> None:
    with pytest.raises(SimulationError):
        RequestCase(
            case_id="c1",
            action="pay.send",
            capability="pay.send",
            root_agent="agent-a",
            request={1: "one"},
        )


def test_case_rejects_bad_hops() -> None:
    with pytest.raises(SimulationError):
        RequestCase(
            case_id="c1",
            action="pay.send",
            capability="pay.send",
            root_agent="agent-a",
            hops=("not-a-hop",),  # type: ignore[arg-type]
        )


def test_case_rejects_a_non_finite_lifetime() -> None:
    with pytest.raises(SimulationError):
        RequestCase(
            case_id="c1",
            action="pay.send",
            capability="pay.send",
            root_agent="agent-a",
            lifetime=float("inf"),
        )


def test_case_rejects_a_non_positive_lifetime() -> None:
    with pytest.raises(SimulationError):
        RequestCase(
            case_id="c1",
            action="pay.send",
            capability="pay.send",
            root_agent="agent-a",
            lifetime=0,
        )


def test_case_rejects_a_boolean_lifetime() -> None:
    with pytest.raises(SimulationError):
        RequestCase(
            case_id="c1",
            action="pay.send",
            capability="pay.send",
            root_agent="agent-a",
            lifetime=True,
        )


def test_case_rejects_a_non_bool_expired_flag() -> None:
    with pytest.raises(SimulationError):
        RequestCase(
            case_id="c1",
            action="pay.send",
            capability="pay.send",
            root_agent="agent-a",
            expired="yes",  # type: ignore[arg-type]
        )


def test_case_rejects_a_non_bool_baseline() -> None:
    with pytest.raises(SimulationError):
        RequestCase(
            case_id="c1",
            action="pay.send",
            capability="pay.send",
            root_agent="agent-a",
            baseline_allowed="yes",  # type: ignore[arg-type]
        )


# ======================================================================
# RequestCase: derived facts
# ======================================================================


def test_depth_counts_the_root_as_one() -> None:
    case = RequestCase(
        case_id="c1",
        action="pay.send",
        capability="pay.send",
        root_agent="agent-a",
        hops=(
            DelegationHop(delegatee="agent-b"),
            DelegationHop(delegatee="agent-c"),
        ),
    )

    assert case.depth == 3


def test_agent_is_the_leaf_of_the_chain() -> None:
    case = RequestCase(
        case_id="c1",
        action="pay.send",
        capability="pay.send",
        root_agent="agent-a",
        hops=(DelegationHop(delegatee="agent-b"),),
    )

    assert case.agent == "agent-b"
    assert case.agents == ("agent-a", "agent-b")


def test_agent_is_the_root_without_hops() -> None:
    case = RequestCase(
        case_id="c1",
        action="pay.send",
        capability="pay.send",
        root_agent="agent-a",
    )

    assert case.agent == "agent-a"
    assert case.agents == ("agent-a",)
    assert case.depth == 1


def test_expired_cases_are_not_reproducible() -> None:
    fresh = RequestCase(
        case_id="c1",
        action="pay.send",
        capability="pay.send",
        root_agent="agent-a",
        expired=False,
    )
    stale = RequestCase(
        case_id="c2",
        action="pay.send",
        capability="pay.send",
        root_agent="agent-a",
        expired=True,
    )

    assert fresh.reproducible
    assert not stale.reproducible


# ======================================================================
# RequestCase: serialization
# ======================================================================


def test_case_survives_a_json_round_trip() -> None:
    case = RequestCase(
        case_id="c1",
        action="pay.send",
        capability="pay.send",
        root_agent="agent-a",
        issuer="platform-issuer",
        root_constraints={"amount_max": 1000},
        hops=(
            DelegationHop(
                delegatee="agent-b",
                constraints={"amount_max": 500},
            ),
        ),
        request={"amount": 250},
        tool="stripe.charge",
        lifetime=1234.5,
        revoked_agents=("agent-b",),
        expired=False,
        baseline_allowed=True,
        baseline_reason="authorized",
        recorded_at=123.0,
        note="demo",
    )

    restored = RequestCase.from_dict(
        json.loads(json.dumps(case.to_dict()))
    )

    assert restored == case
    assert restored.tool == "stripe.charge"
    assert restored.revoked_agents == (
        "agent-b",
    )
    assert restored.baseline_reason == "authorized"


def test_case_from_dict_applies_defaults() -> None:
    case = RequestCase.from_dict(
        {
            "case_id": "c1",
            "action": "pay.send",
            "capability": "pay.send",
            "root_agent": "agent-a",
        }
    )

    assert case.issuer == "trusted-issuer"
    assert case.lifetime == 3600.0
    assert case.hops == ()
    assert case.revoked_agents == ()
    assert case.request == {}


def test_case_from_dict_rejects_a_non_object() -> None:
    with pytest.raises(SimulationError):
        RequestCase.from_dict("nope")


def test_delegation_hop_round_trip() -> None:
    hop = DelegationHop(
        delegatee="agent-b",
        constraints={"amount_max": 50},
    )

    assert DelegationHop.from_dict(
        hop.to_dict()
    ) == hop


# ======================================================================
# CaseSet
# ======================================================================


def test_case_set_deduplicates_by_id_last_write_wins() -> None:
    first = RequestCase(
        case_id="c1",
        action="pay.send",
        capability="pay.send",
        root_agent="agent-a",
        baseline_allowed=True,
    )
    second = RequestCase(
        case_id="c1",
        action="pay.send",
        capability="pay.send",
        root_agent="agent-a",
        baseline_allowed=False,
        baseline_reason="refusal_state",
    )

    case_set = CaseSet((first, second))

    assert len(case_set) == 1
    assert case_set.get("c1").baseline_allowed is False


def test_case_set_survives_a_json_round_trip() -> None:
    case_set = CaseSet(
        (
            RequestCase(
                case_id="c1",
                action="pay.send",
                capability="pay.send",
                root_agent="agent-a",
            ),
            RequestCase(
                case_id="c2",
                action="pay.send",
                capability="pay.send",
                root_agent="agent-b",
            ),
        )
    )

    restored = CaseSet.from_json(
        case_set.to_json()
    )

    assert len(restored) == 2
    assert "c1" in restored
    assert "c2" in restored


def test_case_set_requires_a_cases_list() -> None:
    with pytest.raises(SimulationError):
        CaseSet.from_dict({"version": 1})

    with pytest.raises(SimulationError):
        CaseSet.from_dict(
            {"version": 1, "cases": "nope"}
        )


def test_case_set_rejects_non_case_members() -> None:
    with pytest.raises(SimulationError):
        CaseSet(("not-a-case",))  # type: ignore[arg-type]


def test_case_set_rejects_bad_json() -> None:
    with pytest.raises(SimulationError):
        CaseSet.from_json("{not json")


# ======================================================================
# RuleSet: validation
# ======================================================================


def test_ruleset_defaults_are_disabled_and_empty() -> None:
    rules = RuleSet()

    assert rules.max_delegation_depth is None
    assert rules.trusted_issuers == frozenset()


def test_ruleset_rejects_a_boolean_depth() -> None:
    with pytest.raises(SimulationError):
        RuleSet(max_delegation_depth=True)


def test_ruleset_rejects_a_non_int_depth() -> None:
    with pytest.raises(SimulationError):
        RuleSet(max_delegation_depth=2.5)


def test_ruleset_rejects_a_non_positive_depth() -> None:
    with pytest.raises(SimulationError):
        RuleSet(max_delegation_depth=0)

    with pytest.raises(SimulationError):
        RuleSet(max_delegation_depth=-3)


def test_ruleset_rejects_a_string_issuer_collection() -> None:
    with pytest.raises(SimulationError):
        RuleSet(trusted_issuers="trusted-issuer")


def test_ruleset_rejects_non_string_issuers() -> None:
    with pytest.raises(SimulationError):
        RuleSet(trusted_issuers={1, 2})


def test_ruleset_rejects_blank_issuers() -> None:
    with pytest.raises(SimulationError):
        RuleSet(trusted_issuers={" "})


def test_ruleset_rejects_a_non_iterable() -> None:
    with pytest.raises(SimulationError):
        RuleSet(trusted_issuers=42)


def test_ruleset_is_immutable() -> None:
    rules = RuleSet(
        trusted_issuers={"trusted-issuer"}
    )

    with pytest.raises(AttributeError):
        rules.max_delegation_depth = 2  # type: ignore[misc]

    with pytest.raises(AttributeError):
        rules.trusted_issuers = frozenset()  # type: ignore[misc]


# ======================================================================
# RuleSet: derivation, diff, serialization
# ======================================================================


def test_ruleset_replace_changes_only_named_rules() -> None:
    rules = RuleSet(
        max_delegation_depth=3,
        trusted_issuers={"a", "b"},
    )

    changed = rules.replace(max_delegation_depth=1)

    assert changed.max_delegation_depth == 1
    assert changed.trusted_issuers == {"a", "b"}
    # The original is untouched.
    assert rules.max_delegation_depth == 3


def test_ruleset_replace_rejects_unknown_rules() -> None:
    with pytest.raises(SimulationError):
        RuleSet().replace(not_a_rule=True)


def test_ruleset_diff_describes_depth_and_issuer_changes() -> None:
    before = RuleSet(
        max_delegation_depth=3,
        trusted_issuers={"a", "b"},
    )
    after = RuleSet(
        max_delegation_depth=1,
        trusted_issuers={"b", "c"},
    )

    diff = before.diff(after)

    assert diff["max_delegation_depth"] == {
        "before": 3,
        "after": 1,
    }
    assert diff["trusted_issuers"] == {
        "trusted": ["c"],
        "untrusted": ["a"],
    }


def test_ruleset_diff_is_empty_for_identical_sets() -> None:
    rules = RuleSet(trusted_issuers={"a"})

    assert rules.diff(rules) == {}


def test_ruleset_describe_names_the_change() -> None:
    before = RuleSet(trusted_issuers={"a"})
    after = before.replace(
        trusted_issuers={"a", "b"},
        max_delegation_depth=2,
    )

    lines = before.describe(after)

    assert any(
        "unbounded -> 2" in line
        for line in lines
    )
    assert any(
        "trust b" in line for line in lines
    )


def test_ruleset_describe_no_change() -> None:
    rules = RuleSet()

    assert rules.describe(rules) == [
        "no rule changes"
    ]


def test_ruleset_from_dict_round_trip() -> None:
    rules = RuleSet(
        max_delegation_depth=2,
        trusted_issuers={"a", "b"},
    )

    restored = RuleSet.from_dict(
        json.loads(rules.to_json())
    )

    assert restored == rules


def test_ruleset_from_dict_rejects_unknown_keys() -> None:
    with pytest.raises(SimulationError):
        RuleSet.from_dict(
            {"max_delegation_depth": 2, "nope": 1}
        )


def test_ruleset_from_json_rejects_bad_json() -> None:
    with pytest.raises(SimulationError):
        RuleSet.from_json("{nope")


def test_ruleset_hash_and_equality() -> None:
    assert RuleSet(
        max_delegation_depth=2,
        trusted_issuers={"a"},
    ) == RuleSet(
        max_delegation_depth=2,
        trusted_issuers={"a"},
    )
    assert RuleSet(
        max_delegation_depth=2
    ) != RuleSet(max_delegation_depth=3)


# ======================================================================
# RuleSet: applying to a live SDK
# ======================================================================


def test_ruleset_apply_to_sets_depth_and_issuer_trust(
    sdk: FirewallSDK,
) -> None:
    previous = RuleSet.from_sdk(sdk)
    assert previous.max_delegation_depth is None

    candidate = RuleSet(
        max_delegation_depth=2,
        trusted_issuers={"trusted-issuer", "b"},
    )

    displaced = candidate.apply_to(sdk)

    # Returns the rules that were in force beforehand.
    assert displaced == previous
    assert sdk.max_delegation_depth == 2
    assert sdk.is_issuer_trusted("b")

    # Restoring is exact.
    displaced.apply_to(sdk)

    assert sdk.max_delegation_depth is None
    assert not sdk.is_issuer_trusted("b")


def test_ruleset_apply_to_revokes_untrusted_issuers(
    sdk: FirewallSDK,
) -> None:
    sdk.trust_issuer("extra-issuer")

    RuleSet(
        trusted_issuers={"trusted-issuer"}
    ).apply_to(sdk)

    assert not sdk.is_issuer_trusted("extra-issuer")
    assert sdk.is_issuer_trusted("trusted-issuer")


def test_ruleset_from_sdk_snapshots_live_rules(
    sdk: FirewallSDK,
) -> None:
    sdk.max_delegation_depth = 4
    sdk.trust_issuer("b")

    rules = RuleSet.from_sdk(sdk)

    assert rules.max_delegation_depth == 4
    assert rules.trusted_issuers == {
        "trusted-issuer",
        "b",
    }


# ======================================================================
# CaseRecorder
# ======================================================================


def test_recorder_requires_a_capability(
    sdk: FirewallSDK,
) -> None:
    recorder = CaseRecorder()

    with pytest.raises(SimulationError):
        recorder.record(
            sdk,
            "not-a-capability",  # type: ignore[arg-type]
            "pay.send",
            {},
        )


def test_recorder_captures_an_allowed_decision(
    sdk: FirewallSDK,
) -> None:
    recorder = CaseRecorder()
    pk = sdk.active_key().private_key
    root = sdk.issue(
        agent="agent-a",
        capability="pay.send",
        private_key=pk,
        issuer="trusted-issuer",
    )

    decision = sdk.authorize(root, "pay.send", {})

    case = recorder.record(
        sdk,
        root,
        "pay.send",
        {},
        decision,
    )

    assert case.baseline_allowed is True
    assert case.baseline_reason == "authorized"
    assert case.agent == "agent-a"
    assert case.expired is False


def test_recorder_captures_a_denied_decision(
    sdk: FirewallSDK,
) -> None:
    recorder = CaseRecorder()
    pk = sdk.active_key().private_key
    root = sdk.issue(
        agent="agent-a",
        capability="pay.send",
        private_key=pk,
        issuer="trusted-issuer",
        constraints={"amount_max": 100},
    )

    decision = sdk.authorize(
        root,
        "pay.send",
        {"amount": 500},
    )

    assert decision.allowed is False

    case = recorder.record(
        sdk,
        root,
        "pay.send",
        {"amount": 500},
        decision,
    )

    assert case.baseline_allowed is False
    # The recorder copies the pipeline's verdict verbatim.
    assert case.baseline_reason == decision.reason


def test_recorder_resolves_the_delegation_chain_root_first(
    sdk: FirewallSDK,
) -> None:
    recorder = CaseRecorder()
    pk = sdk.active_key().private_key
    root = sdk.issue(
        agent="agent-a",
        capability="pay.send",
        private_key=pk,
        issuer="trusted-issuer",
    )
    child = sdk.delegate(
        root,
        pk,
        delegatee="agent-b",
    ).child
    grand = sdk.delegate(
        child,
        pk,
        delegatee="agent-c",
    ).child

    decision = sdk.authorize(grand, "pay.send", {})

    case = recorder.record(
        sdk,
        grand,
        "pay.send",
        {},
        decision,
    )

    assert case.agents == (
        "agent-a",
        "agent-b",
        "agent-c",
    )
    assert case.agent == "agent-c"
    assert case.depth == 3
    assert case.root_agent == "agent-a"
    assert len(case.hops) == 2


def test_recorder_records_direct_revocations(
    sdk: FirewallSDK,
) -> None:
    recorder = CaseRecorder()
    pk = sdk.active_key().private_key
    root = sdk.issue(
        agent="agent-a",
        capability="pay.send",
        private_key=pk,
        issuer="trusted-issuer",
    )
    child = sdk.delegate(
        root,
        pk,
        delegatee="agent-b",
    ).child

    sdk.revoke(root, reason="audited")

    decision = sdk.authorize(child, "pay.send", {})

    assert decision.allowed is False

    case = recorder.record(
        sdk,
        child,
        "pay.send",
        {},
        decision,
    )

    assert case.revoked_agents == ("agent-a",)
    assert case.baseline_reason == "capability_revoked"


def test_recorder_marks_an_expired_capability(
    sdk: FirewallSDK,
) -> None:
    recorder = CaseRecorder()
    pk = sdk.active_key().private_key
    root = sdk.issue(
        agent="agent-a",
        capability="pay.send",
        private_key=pk,
        issuer="trusted-issuer",
    )

    decision = sdk.authorize(root, "pay.send", {})

    case = recorder.record(
        sdk,
        root,
        "pay.send",
        {},
        decision,
        now=time.time() + 99999,
    )

    assert case.expired is True
    assert case.reproducible is False


def test_recorder_deduplicates_identical_requests(
    sdk: FirewallSDK,
) -> None:
    recorder = CaseRecorder()
    pk = sdk.active_key().private_key
    root = sdk.issue(
        agent="agent-a",
        capability="pay.send",
        private_key=pk,
        issuer="trusted-issuer",
    )

    for _ in range(3):
        decision = sdk.authorize(root, "pay.send", {})
        recorder.record(
            sdk,
            root,
            "pay.send",
            {},
            decision,
        )

    assert len(recorder) == 1


def test_recorder_is_a_rolling_window(
    sdk: FirewallSDK,
) -> None:
    recorder = CaseRecorder(limit=2)
    pk = sdk.active_key().private_key

    for i in range(4):
        root = sdk.issue(
            agent=f"agent-{i}",
            capability="pay.send",
            private_key=pk,
            issuer="trusted-issuer",
        )
        decision = sdk.authorize(root, "pay.send", {})
        recorder.record(
            sdk,
            root,
            "pay.send",
            {},
            decision,
        )

    assert len(recorder) == 2


def test_recorder_rejects_a_bad_limit() -> None:
    with pytest.raises(SimulationError):
        CaseRecorder(limit=0)

    with pytest.raises(SimulationError):
        CaseRecorder(limit=True)


def test_recorded_case_carries_no_credential_material(
    sdk: FirewallSDK,
) -> None:
    """A case is meant to be written to disk; it must not leak keys."""

    recorder = CaseRecorder()
    pk = sdk.active_key().private_key
    root = sdk.issue(
        agent="agent-a",
        capability="pay.send",
        private_key=pk,
        issuer="trusted-issuer",
    )

    decision = sdk.authorize(root, "pay.send", {})
    case = recorder.record(
        sdk,
        root,
        "pay.send",
        {},
        decision,
    )

    blob = json.dumps(case.to_dict())

    assert "PRIVATE KEY" not in blob
    assert "BEGIN" not in blob
    assert "signature" not in blob
    assert "public_key" not in blob
    # The request/constraint maps are intact and small.
    assert len(blob) < 2000


# ======================================================================
# simulate: fidelity is measured, not assumed
# ======================================================================


def test_identity_simulation_reproduces_recorded_decisions(
    sdk: FirewallSDK,
) -> None:
    cases = record_cases(
        sdk,
        ("agent-a",),
        ("agent-a", "agent-b"),
        ("agent-a", "agent-b", "agent-c"),
    )

    rules = RuleSet.from_sdk(sdk)
    report = simulate(cases, rules, rules)

    assert report.totals["cases"] == 3
    assert report.totals["counted"] == 3
    assert report.totals["excluded"] == 0
    assert report.totals["unchanged"] == 3
    assert report.totals["newly_denied"] == 0
    assert report.safe

    # Every replayed case landed on the decision that was observed.
    assert all(
        outcome.faithful
        for outcome in report.outcomes
    )
    assert all(
        outcome.counted
        for outcome in report.outcomes
    )


def test_simulate_requires_rulesets() -> None:
    cases = CaseSet()

    with pytest.raises(SimulationError):
        simulate(cases, "before", "after")  # type: ignore[arg-type]


def test_simulate_rejects_a_bad_limit() -> None:
    cases = CaseSet()

    with pytest.raises(SimulationError):
        simulate(
            cases,
            RuleSet(),
            RuleSet(),
            limit=0,
        )

    with pytest.raises(SimulationError):
        simulate(
            cases,
            RuleSet(),
            RuleSet(),
            limit=True,
        )


# ======================================================================
# simulate: the depth ceiling
# ======================================================================


def test_lowering_the_depth_ceiling_newly_denies_deep_chains(
    sdk: FirewallSDK,
) -> None:
    cases = record_cases(
        sdk,
        ("agent-a",),
        ("agent-a", "agent-b"),
        ("agent-a", "agent-b", "agent-c"),
    )

    before = RuleSet.from_sdk(sdk)
    after = before.replace(max_delegation_depth=2)

    report = simulate(cases, before, after)

    denied = report.by_change(NEWLY_DENIED)

    assert len(denied) == 1
    assert denied[0].agent == "agent-c"
    assert denied[0].after_reason == (
        "delegation_depth_exceeded"
    )
    assert denied[0].counted

    radius = report.blast_radius
    assert radius["newly_denied"] == 1
    assert radius["agents"] == ["agent-c"]

    assert not report.safe


def test_raising_the_depth_ceiling_newly_allows_deep_chains(
    sdk: FirewallSDK,
) -> None:
    # Record under a ceiling that denies depth 3.
    sdk.max_delegation_depth = 2

    cases = record_cases(
        sdk,
        ("agent-a", "agent-b", "agent-c"),
    )

    before = RuleSet.from_sdk(sdk)
    after = before.replace(max_delegation_depth=None)

    report = simulate(cases, before, after)

    allowed = report.by_change(NEWLY_ALLOWED)

    assert len(allowed) == 1
    assert allowed[0].agent == "agent-c"
    assert allowed[0].counted
    assert report.safe  # Nothing that works today stops working.


def test_a_higher_ceiling_never_newly_denies(
    sdk: FirewallSDK,
) -> None:
    sdk.max_delegation_depth = 2

    cases = record_cases(
        sdk,
        ("agent-a", "agent-b"),
        ("agent-a", "agent-b", "agent-c"),
    )

    before = RuleSet.from_sdk(sdk)
    after = before.replace(max_delegation_depth=5)

    report = simulate(cases, before, after)

    assert report.totals["newly_denied"] == 0
    assert report.totals["newly_allowed"] == 1
    assert report.safe


# ======================================================================
# simulate: issuer trust (the revocation/untrust path)
# ======================================================================


def test_untrusting_an_issuer_newly_denies_its_cases(
    sdk: FirewallSDK,
) -> None:
    cases = record_cases(
        sdk,
        ("agent-a",),
        ("agent-a", "agent-b"),
    )

    before = RuleSet.from_sdk(sdk)
    after = before.replace(
        trusted_issuers=set(before.trusted_issuers)
        - {"trusted-issuer"}
    )

    report = simulate(cases, before, after)

    denied = report.by_change(NEWLY_DENIED)

    assert len(denied) == 2
    assert all(
        outcome.after_reason == "untrusted_issuer"
        for outcome in denied
    )
    assert report.blast_radius["agents"] == [
        "agent-a",
        "agent-b",
    ]
    assert not report.safe


def test_trusting_a_new_issuer_alone_changes_nothing(
    sdk: FirewallSDK,
) -> None:
    cases = record_cases(
        sdk,
        ("agent-a",),
    )

    before = RuleSet.from_sdk(sdk)
    after = before.replace(
        trusted_issuers=set(before.trusted_issuers)
        | {"extra-issuer"}
    )

    report = simulate(cases, before, after)

    assert report.totals["newly_denied"] == 0
    assert report.totals["newly_allowed"] == 0
    assert report.safe


def test_cases_from_an_untrusted_issuer_cannot_show_a_change(
    sdk: FirewallSDK,
) -> None:
    """A case whose issuer the 'before' rules do not trust is denied on
    both sides, so it must be reported as incapable of showing a change
    rather than as a silent pass.
    """

    cases = record_cases(sdk, ("agent-a",))

    # 'before' trusts nobody: the case's issuer is untrusted there.
    before = RuleSet(trusted_issuers=set())
    report = simulate(cases, before, before)

    assert report.totals["newly_denied"] == 0
    assert report.totals["excluded"] == 1
    assert any(
        "does not trust" in caveat
        for caveat in report.caveats
    )
    # "We could not tell" is not a pass.
    assert not report.safe


# ======================================================================
# simulate: counting discipline
# ======================================================================


def test_expired_cases_are_reported_but_never_counted(
    sdk: FirewallSDK,
) -> None:
    recorder = CaseRecorder()
    pk = sdk.active_key().private_key
    root = sdk.issue(
        agent="agent-a",
        capability="pay.send",
        private_key=pk,
        issuer="trusted-issuer",
    )

    decision = sdk.authorize(root, "pay.send", {})

    # Recorded as already expired (a fresh workspace cannot re-create
    # an expired capability).
    recorder.record(
        sdk,
        root,
        "pay.send",
        {},
        decision,
        now=time.time() + 99999,
    )

    rules = RuleSet.from_sdk(sdk)
    report = simulate(
        recorder.cases(),
        rules,
        rules,
    )

    assert report.totals["cases"] == 1
    assert report.totals["counted"] == 0
    assert report.totals["excluded"] == 1
    assert any(
        "already expired" in caveat
        for caveat in report.caveats
    )
    assert not report.safe


def test_cases_without_an_observed_decision_are_not_counted() -> None:
    case = RequestCase(
        case_id="c1",
        action="pay.send",
        capability="pay.send",
        root_agent="agent-a",
        baseline_reason=None,
    )

    report = simulate(
        [case],
        RuleSet(),
        RuleSet(),
    )

    assert report.totals["excluded"] == 1
    assert any(
        "recorded no observed decision" in caveat
        for caveat in report.caveats
    )


def test_cases_that_replay_differently_are_not_counted(
    sdk: FirewallSDK,
) -> None:
    """A case whose replayed reason diverges from the observed one must
    be excluded from every count -- the simulator does not stand behind
    it.
    """

    recorder = CaseRecorder()
    pk = sdk.active_key().private_key
    root = sdk.issue(
        agent="agent-a",
        capability="pay.send",
        private_key=pk,
        issuer="trusted-issuer",
    )

    decision = sdk.authorize(root, "pay.send", {})
    case = recorder.record(
        sdk,
        root,
        "pay.send",
        {},
        decision,
    )

    # Corrupt the baseline: claim a different decision was observed.
    from firewall.simulation.case import (
        RequestCase as RC,
    )

    doctored = RC(
        **{
            **case.to_dict(),
            "baseline_reason": "refusal_state",
        }
    )

    rules = RuleSet.from_sdk(sdk)
    report = simulate([doctored], rules, rules)

    assert report.totals["excluded"] == 1
    assert any(
        "different reason" in caveat
        for caveat in report.caveats
    )
    assert not report.safe


def test_a_replay_error_is_reported_and_never_counted(
    sdk: FirewallSDK,
) -> None:
    """A case whose chain cannot be rebuilt (here: a delegation hop that
    would broaden the parent's constraints) errors out and is excluded.
    """

    case = RequestCase(
        case_id="c1",
        action="pay.send",
        capability="pay.send",
        root_agent="agent-a",
        root_constraints={"amount_max": 100},
        hops=(
            DelegationHop(
                delegatee="agent-b",
                constraints={"amount_max": 200},
            ),
        ),
        baseline_allowed=True,
        baseline_reason="authorized",
    )

    rules = RuleSet.from_sdk(sdk)
    report = simulate([case], rules, rules)

    errored = report.by_change(
        ERRORED,
        counted_only=False,
    )

    assert len(errored) == 1
    assert errored[0].error is not None
    assert not errored[0].counted
    assert report.totals["error"] == 1
    assert any(
        "could not be replayed" in caveat
        for caveat in report.caveats
    )
    assert not report.safe


def test_the_case_limit_skips_and_says_so(
    sdk: FirewallSDK,
) -> None:
    cases = record_cases(
        sdk,
        ("agent-a",),
        ("agent-b",),
        ("agent-c",),
    )

    rules = RuleSet.from_sdk(sdk)
    report = simulate(cases, rules, rules, limit=2)

    assert report.totals["cases"] == 2
    assert report.totals["skipped"] == 1
    assert report.totals["counted"] == 2
    assert any(
        "were not replayed" in caveat
        for caveat in report.caveats
    )
    assert not report.safe


def test_limit_is_capped_by_the_module_ceiling() -> None:
    assert MAX_CASES == 200


# ======================================================================
# simulate: isolation and determinism
# ======================================================================


def test_the_answer_does_not_depend_on_case_order(
    sdk: FirewallSDK,
) -> None:
    """Each case replays in its own workspace, so refusal memoization,
    replay protection, and budgets cannot leak across cases.
    """

    cases = record_cases(
        sdk,
        ("agent-a",),
        ("agent-a", "agent-b", "agent-c"),
    )

    ordered = list(cases)
    reversed_cases = CaseSet(reversed(ordered))

    rules = RuleSet.from_sdk(sdk)
    after = rules.replace(max_delegation_depth=2)

    forward = simulate(cases, rules, after)
    backward = simulate(reversed_cases, rules, after)

    assert forward.totals == backward.totals
    assert forward.blast_radius == (
        backward.blast_radius
    )


def test_simulate_never_touches_a_live_sdk(
    sdk: FirewallSDK,
) -> None:
    cases = record_cases(
        sdk,
        ("agent-a", "agent-b", "agent-c"),
    )

    before = RuleSet.from_sdk(sdk)
    after = before.replace(max_delegation_depth=1)

    depth_before = sdk.max_delegation_depth
    issuers_before = (
        sdk.issuer_trust_store.trusted_issuers()
    )

    simulate(cases, before, after)

    assert sdk.max_delegation_depth == depth_before
    assert (
        sdk.issuer_trust_store.trusted_issuers()
        == issuers_before
    )


def test_simulate_change_reads_the_live_rules_and_applies_changes(
    sdk: FirewallSDK,
) -> None:
    cases = record_cases(
        sdk,
        ("agent-a", "agent-b"),
    )

    report = simulate_change(
        sdk,
        cases,
        max_delegation_depth=1,
    )

    assert report.before["max_delegation_depth"] is None
    assert report.after["max_delegation_depth"] == 1
    assert report.totals["newly_denied"] == 1
    # The live SDK was never modified.
    assert sdk.max_delegation_depth is None


def test_report_summary_mentions_newly_denied_agents(
    sdk: FirewallSDK,
) -> None:
    cases = record_cases(
        sdk,
        ("agent-a", "agent-b", "agent-c"),
    )

    before = RuleSet.from_sdk(sdk)
    report = simulate(
        cases,
        before,
        before.replace(max_delegation_depth=2),
    )

    summary = report.summary()

    assert "1 newly denied" in summary
    assert "agent-c" in summary
