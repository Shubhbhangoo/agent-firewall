"""v2.3: policy conflict analysis that reports what it actually found.

``firewall.policy_analysis`` shipped with zero tests and zero importers.
Four properties are under test here.

**A case that could not be replayed is not a denial.** The old
counterfactual counted every outcome, allowed or not, by comparing
``after_reason`` to the string ``"authorized"``. An errored case has
``after_reason is None``, which is ``!= "authorized"``, so cases the
simulator never managed to evaluate were tallied as denials -- and enough
of them turned a *widening* into a report of ``"improved"``. Counts now
come from ``report.counted_outcomes`` and read the ``after_allowed``
boolean.

**A checker written against the wrong model can never fire.** The
contradiction check read ``constraints[namespace]`` as an operator dict
and looked for ``"eq"`` beside ``"neq"``. At that level those keys are
*field names*, and ``validate_constraints`` rejects ``neq`` as a
Capability2 operator anywhere, so the check was dead on both counts.
Satisfiability now walks the real ``{namespace: {field: {operator:
value}}}`` shape.

**Silence about a source is not a clean result.** A policy that could not
be parsed used to be dropped, so "no conflicts" read identically whether
the estate was clean or unreadable.

**Structural analysis is not a decision procedure.** When these checks
stay silent that is the absence of a recognized contradiction, not a
proof of satisfiability, and the tests below pin a case that is genuinely
unsatisfiable and deliberately not reported.
"""

from __future__ import annotations

import dataclasses

import pytest

from firewall.capability2 import Capability2, Capability2Error
from firewall.policy_analysis import (
    CounterfactualResult,
    PolicyConflict,
    PolicyConflictEngine,
    _operator_verdict,
)
from firewall.sdk import FirewallSDK
from firewall.simulation import (
    CaseRecorder,
    CaseSet,
    RuleSet,
)


@pytest.fixture
def sdk() -> FirewallSDK:
    instance = FirewallSDK(trusted_issuers={"trusted-issuer"})
    instance.generate_key("test-key")
    yield instance
    instance.close()


@pytest.fixture
def engine(sdk: FirewallSDK) -> PolicyConflictEngine:
    # The engine holds an SDK for the replay side of the counterfactual.
    # It never asks that SDK to authorize on an analysis's behalf.
    return PolicyConflictEngine(sdk)


def _cap(constraints: dict) -> Capability2:
    return Capability2(capability="files.read", constraints=constraints)


def _kinds(conflicts) -> list[str]:
    return [c.conflict_type for c in conflicts]


def _of_kind(conflicts, kind: str) -> list[PolicyConflict]:
    return [c for c in conflicts if c.conflict_type == kind]


# ======================================================================
# Unsatisfiable constraints: dead weight that reads as enforcement
# ======================================================================


class TestUnsatisfiableConstraints:
    @pytest.mark.parametrize(
        "operators,fragment",
        [
            ({"gte": 100, "lte": 10}, "gte 100 is above lte 10"),
            ({"gt": 10, "lte": 10}, "gt 10 leaves nothing at or below 10"),
            ({"gte": 10, "lt": 10}, "gte 10 leaves nothing below 10"),
            ({"gt": 10, "lt": 10}, "gt 10 leaves nothing below 10"),
            ({"in": []}, "in is empty"),
            ({"eq": "a", "in": ["b"]}, "does not contain it"),
            ({"eq": 1, "gte": 5}, "eq 1 is below gte 5"),
            ({"eq": 5, "gt": 5}, "eq 5 is not above gt 5"),
            ({"eq": 9, "lte": 5}, "eq 9 is above lte 5"),
            ({"eq": 5, "lt": 5}, "eq 5 is not below lt 5"),
        ],
    )
    def test_contradiction_is_reported_with_its_reason(
        self, engine, operators, fragment
    ):
        conflicts = engine.analyze_policies(
            {"p": _cap({"context": {"amount": operators}})}
        )

        found = _of_kind(conflicts, "contradictory_constraints")

        assert len(found) == 1
        assert found[0].severity == "high"
        assert "context.amount" in found[0].description
        assert fragment in found[0].description
        assert found[0].rules_involved == ("p.context.amount",)
        assert found[0].evidence[0]["constraint"] == operators

    def test_inverted_time_window_is_reported(self, engine):
        conflicts = engine.analyze_policies(
            {
                "p": _cap(
                    {"time": {"not_before": 200.0, "not_after": 100.0}}
                )
            }
        )

        found = _of_kind(conflicts, "contradictory_constraints")

        assert len(found) == 1
        assert "not_before 200.0 is after not_after 100.0" in (
            found[0].description
        )

    def test_a_valid_time_window_is_not_reported(self, engine):
        conflicts = engine.analyze_policies(
            {"p": _cap({"time": {"not_before": 1.0, "not_after": 2.0}})}
        )

        assert not _of_kind(conflicts, "contradictory_constraints")

    def test_a_satisfiable_range_is_not_reported(self, engine):
        conflicts = engine.analyze_policies(
            {"p": _cap({"context": {"amount": {"gte": 1, "lte": 100}}})}
        )

        assert not _of_kind(conflicts, "contradictory_constraints")

    def test_every_field_namespace_is_walked(self, engine):
        # A checker that only looked at one namespace would leave the
        # others unexamined while reporting a clean result.
        for namespace in (
            "context",
            "identity",
            "task",
            "lineage",
            "provenance",
            "environment",
        ):
            conflicts = engine.analyze_policies(
                {"p": _cap({namespace: {"f": {"in": []}}})}
            )

            found = _of_kind(conflicts, "contradictory_constraints")

            assert len(found) == 1, namespace
            assert f"{namespace}.f" in found[0].description


# ======================================================================
# Unconditional constraints: a limit that limits nothing
# ======================================================================


class TestUnconditionalConstraints:
    def test_empty_namespace_grants_it_unconditionally(self, engine):
        conflicts = engine.analyze_policies({"p": _cap({"task": {}})})

        found = _of_kind(conflicts, "unconditional_constraint")

        assert len(found) == 1
        assert found[0].severity == "high"
        assert "constrains no field" in found[0].description
        assert found[0].rules_involved == ("p.task",)

    def test_field_with_an_empty_operator_dict(self, engine):
        # ``{"amount": {}}`` passes validate_constraints -- there is no
        # unknown operator in it -- and applies no test to the field. It
        # reads as a limit on ``amount`` and is not one.
        conflicts = engine.analyze_policies(
            {"p": _cap({"context": {"amount": {}}})}
        )

        found = _of_kind(conflicts, "unconditional_constraint")

        assert len(found) == 1
        assert "no constraining operator" in found[0].description
        assert "context.amount" in found[0].description

    def test_an_unknown_operator_never_reaches_the_analyzer(self):
        # validate_constraints refuses it at issue time, so no analysis
        # of a live capability has to account for the shape.
        with pytest.raises(Capability2Error):
            _cap({"context": {"amount": {"note": "todo"}}})

    def test_a_real_constraint_is_not_called_unconditional(self, engine):
        conflicts = engine.analyze_policies(
            {"p": _cap({"context": {"amount": {"lte": 10}}})}
        )

        assert not _of_kind(conflicts, "unconditional_constraint")

    def test_a_bare_scalar_entry_constrains(self, engine):
        # ``{"agent_id": "a"}`` is an equality test, not an empty
        # operator dict, and must not be reported as unconditional.
        conflicts = engine.analyze_policies(
            {"p": _cap({"identity": {"agent_id": "agent-a"}})}
        )

        assert not _of_kind(conflicts, "unconditional_constraint")
        assert not _of_kind(conflicts, "contradictory_constraints")

    def test_a_capability_with_no_constraints_reports_nothing_here(
        self, engine
    ):
        # An unconstrained capability is wide open, but it is wide open
        # visibly. There is no namespace masquerading as a limit, which
        # is what this check is for.
        conflicts = engine.analyze_policies(
            {"p": Capability2(capability="files.read")}
        )

        assert not _of_kind(conflicts, "unconditional_constraint")


# ======================================================================
# The limits of a structural check, stated as tests
# ======================================================================


class TestSatisfiabilityIsNotAProof:
    def test_string_operators_are_not_reasoned_about(self):
        # prefix "a" with eq "b" is unsatisfiable: no string both starts
        # with "a" and equals "b". Nothing here models string prefixes,
        # so the verdict is "satisfiable" -- meaning "no recognized
        # contradiction", which is not the same claim.
        assert _operator_verdict({"prefix": "a", "eq": "b"}) == (
            "satisfiable",
            "",
        )

    def test_glob_is_not_reasoned_about(self):
        assert _operator_verdict({"glob": "x*", "eq": "y"}) == (
            "satisfiable",
            "",
        )

    def test_non_numeric_bounds_are_left_alone(self):
        # Comparing strings with gte/lte is legal at issue time; ordering
        # them here would be inventing a semantics the evaluator does not
        # necessarily share.
        assert _operator_verdict({"gte": "z", "lte": "a"}) == (
            "satisfiable",
            "",
        )

    def test_booleans_are_not_numbers(self):
        # bool is a subclass of int. Treating True as 1 would make
        # ``{"eq": True, "lte": 0}`` a contradiction on a field whose
        # values are not numeric at all.
        assert _operator_verdict({"eq": True, "lte": 0}) == (
            "satisfiable",
            "",
        )

    def test_eq_none_is_a_constraint_not_an_absent_operator(self):
        # A field required to equal None is constrained. The sentinel
        # exists so ``get("eq")`` returning None is not read as "no eq".
        assert _operator_verdict({"eq": None}) == ("satisfiable", "")

    def test_unrecognized_keys_do_not_mask_a_real_operator(self):
        # Unit level: validate_constraints rejects this shape, so it
        # cannot arrive from a live capability. The filter is here so a
        # hand-built dict cannot suppress a finding either.
        verdict, _ = _operator_verdict({"note": "x", "in": []})

        assert verdict == "unsatisfiable"


# ======================================================================
# A policy that could not be read is named
# ======================================================================


class TestUnanalyzablePolicies:
    def test_unparseable_policy_is_reported(self, engine):
        conflicts = engine.analyze_policies({"broken": {"nonsense": 1}})

        found = _of_kind(conflicts, "unanalyzable_policy")

        assert len(found) == 1
        assert "broken" in found[0].description
        assert found[0].policies_involved == ("broken",)
        assert found[0].evidence[0]["error"]

    def test_response_policy_is_exempt(self, engine):
        # A dict carrying "rules" is a response policy, analyzed by
        # _analyze_response_conflicts. It is not a failed Capability2.
        conflicts = engine.analyze_policies(
            {"resp": {"rules": [{"stage": "quarantine"}]}}
        )

        assert not _of_kind(conflicts, "unanalyzable_policy")

    def test_each_unreadable_policy_names_itself(self, engine):
        conflicts = engine.analyze_policies(
            {"a": {"x": 1}, "b": {"y": 2}, "good": _cap({})}
        )

        found = _of_kind(conflicts, "unanalyzable_policy")

        assert sorted(c.policies_involved[0] for c in found) == ["a", "b"]

    def test_a_readable_estate_reports_no_unanalyzable_policy(self, engine):
        conflicts = engine.analyze_policies(
            {
                "cap": _cap({"context": {"amount": {"lte": 10}}}),
                "rules": RuleSet(max_delegation_depth=3),
            }
        )

        assert not _of_kind(conflicts, "unanalyzable_policy")

    def test_a_dict_capability2_is_parsed_not_reported(self, engine):
        payload = _cap({"context": {"amount": {"in": []}}}).to_dict()

        conflicts = engine.analyze_policies({"p": payload})

        assert not _of_kind(conflicts, "unanalyzable_policy")
        # Parsed, and then actually analyzed.
        assert _of_kind(conflicts, "contradictory_constraints")


# ======================================================================
# rules_involved must survive being read twice
# ======================================================================


class TestConflictSerialization:
    def _conflicting_response_policy(self) -> dict:
        return {
            "resp": {
                "rules": [
                    {"stage": "quarantine", "auto_approve": True},
                    {"stage": "quarantine", "auto_approve": False},
                ]
            }
        }

    def test_rules_involved_survives_two_serializations(self, engine):
        conflicts = engine.analyze_policies(
            self._conflicting_response_policy()
        )
        found = _of_kind(conflicts, "response_policy_conflict")

        assert len(found) == 1

        first = found[0].to_dict()
        second = found[0].to_dict()

        # A generator would have emptied itself into the first reader.
        assert first["rules_involved"] == [
            "resp.rules[0]",
            "resp.rules[1]",
        ]
        assert second["rules_involved"] == first["rules_involved"]

    def test_rules_involved_is_a_tuple(self, engine):
        conflicts = engine.analyze_policies(
            self._conflicting_response_policy()
        )

        assert isinstance(
            _of_kind(conflicts, "response_policy_conflict")[0].rules_involved,
            tuple,
        )

    def test_consistent_response_policy_is_not_a_conflict(self, engine):
        conflicts = engine.analyze_policies(
            {
                "resp": {
                    "rules": [
                        {"stage": "quarantine", "auto_approve": False},
                        {"stage": "quarantine", "auto_approve": False},
                    ]
                }
            }
        )

        assert not _of_kind(conflicts, "response_policy_conflict")


# ======================================================================
# Counterfactual analysis: an unreplayable case is not evidence
# ======================================================================


def _recorded_case(sdk: FirewallSDK, *, hops: int = 2):
    """Record one real decision so the replay has a baseline to match.

    Two hops by default: ``max_delegation_depth`` must be positive, so a
    ceiling can only deny a chain that is at least two deep.
    """

    recorder = CaseRecorder()
    private_key = sdk.active_key().private_key

    capability = sdk.issue(
        agent="agent-a",
        capability="pay.send",
        private_key=private_key,
        issuer="trusted-issuer",
    )

    for index in range(hops):
        capability = sdk.delegate(
            capability,
            private_key,
            delegatee=f"agent-{index + 1}",
        ).child

    decision = sdk.authorize(capability, "pay.send", {})
    recorder.record(sdk, capability, "pay.send", {}, decision)

    return next(iter(recorder.cases()))


class TestCounterfactualHonesty:
    def test_a_real_narrowing_is_reported_as_improved(self, engine, sdk):
        case = _recorded_case(sdk)
        before = RuleSet(
            max_delegation_depth=5, trusted_issuers={"trusted-issuer"}
        )
        after = before.replace(max_delegation_depth=1)

        result = engine.counterfactual_analysis(
            before, after, CaseSet((case,))
        )

        assert result.counted_cases == 1
        assert result.excluded_cases == 0
        assert result.newly_denied == 1
        assert result.newly_allowed == 0
        assert result.security_delta == "improved"
        assert result.complete is True

    def test_no_change_is_unchanged_not_unknown(self, engine, sdk):
        case = _recorded_case(sdk)
        rules = RuleSet(
            max_delegation_depth=5, trusted_issuers={"trusted-issuer"}
        )

        result = engine.counterfactual_analysis(
            rules, rules, CaseSet((case,))
        )

        assert result.security_delta == "unchanged"
        assert result.unchanged_allowed == 1
        assert result.unchanged_denied == 0
        assert result.complete is True

    def test_an_unfaithful_case_is_never_counted_as_a_denial(
        self, engine, sdk
    ):
        # The replay lands on a different reason than the live pipeline
        # gave, so the simulator did not reproduce this case. Counting it
        # would claim a hardening from a case it could not verify.
        case = dataclasses.replace(
            _recorded_case(sdk), baseline_reason="something_else"
        )
        before = RuleSet(
            max_delegation_depth=5, trusted_issuers={"trusted-issuer"}
        )
        after = before.replace(max_delegation_depth=1)

        result = engine.counterfactual_analysis(
            before, after, CaseSet((case,))
        )

        assert result.newly_denied == 0
        assert result.counted_cases == 0
        assert result.excluded_cases == 1
        assert result.security_delta == "unknown"
        assert result.complete is False

    def test_nothing_replayable_is_unknown_not_unchanged(self, engine, sdk):
        case = dataclasses.replace(_recorded_case(sdk), expired=True)
        rules = RuleSet(
            max_delegation_depth=5, trusted_issuers={"trusted-issuer"}
        )

        result = engine.counterfactual_analysis(
            rules, rules, CaseSet((case,))
        )

        assert result.counted_cases == 0
        assert result.security_delta == "unknown"
        assert result.unchanged_denied == 0
        assert result.complete is False

    def test_an_unreplayable_case_does_not_inflate_unchanged_denied(
        self, engine, sdk
    ):
        # The old count read ``after_reason != "authorized"``, and an
        # excluded case has ``after_reason is None``.
        good = _recorded_case(sdk)
        bad = dataclasses.replace(
            _recorded_case(sdk), case_id="expired", expired=True
        )
        rules = RuleSet(
            max_delegation_depth=5, trusted_issuers={"trusted-issuer"}
        )

        result = engine.counterfactual_analysis(
            rules, rules, CaseSet((good, bad))
        )

        assert result.total_cases == 2
        assert result.counted_cases == 1
        assert result.excluded_cases == 1
        assert result.unchanged_allowed == 1
        assert result.unchanged_denied == 0
        assert result.security_delta == "unchanged"
        # The claim is honest about its own coverage.
        assert result.complete is False
        assert any("excluded" in gap for gap in result.gaps)

    def test_excluded_cases_appear_in_details_marked_uncounted(
        self, engine, sdk
    ):
        case = dataclasses.replace(_recorded_case(sdk), expired=True)
        rules = RuleSet(
            max_delegation_depth=5, trusted_issuers={"trusted-issuer"}
        )

        result = engine.counterfactual_analysis(
            rules, rules, CaseSet((case,))
        )

        excluded = [d for d in result.details if d["counted"] is False]

        assert len(excluded) == 1
        assert excluded[0]["excluded_because"]

    def test_an_empty_case_set_cannot_claim_anything(self, engine):
        rules = RuleSet(max_delegation_depth=1)

        result = engine.counterfactual_analysis(rules, rules, CaseSet())

        assert result.total_cases == 0
        assert result.security_delta == "unknown"
        # No cases were excluded; there were none to exclude.
        assert result.excluded_cases == 0
        assert result.complete is True

    def test_result_dict_carries_coverage(self, engine, sdk):
        case = dataclasses.replace(_recorded_case(sdk), expired=True)
        rules = RuleSet(
            max_delegation_depth=5, trusted_issuers={"trusted-issuer"}
        )

        payload = engine.counterfactual_analysis(
            rules, rules, CaseSet((case,))
        ).to_dict()

        assert payload["counted_cases"] == 0
        assert payload["excluded_cases"] == 1
        assert payload["complete"] is False
        assert payload["gaps"]
        assert payload["security_delta"] == "unknown"


class TestCounterfactualResultShape:
    def test_complete_requires_no_exclusions_and_no_gaps(self):
        assert CounterfactualResult(
            current_policy_version="a",
            proposed_policy_version="b",
            total_cases=1,
            newly_allowed=0,
            newly_denied=0,
            unchanged_allowed=1,
            unchanged_denied=0,
            security_delta="unchanged",
            counted_cases=1,
        ).complete is True

    def test_a_gap_alone_makes_it_incomplete(self):
        assert CounterfactualResult(
            current_policy_version="a",
            proposed_policy_version="b",
            total_cases=1,
            newly_allowed=0,
            newly_denied=0,
            unchanged_allowed=1,
            unchanged_denied=0,
            security_delta="unchanged",
            counted_cases=1,
            gaps=("something was not read",),
        ).complete is False


# ======================================================================
# Nothing here decides anything
# ======================================================================


class TestAnalysisIsNotAuthority:
    def test_the_engine_cannot_authorize(self, engine):
        assert not hasattr(engine, "authorize")
        assert not hasattr(engine, "allow")

    def test_a_conflict_carries_no_verdict(self, engine):
        conflict = _of_kind(
            engine.analyze_policies(
                {"p": _cap({"context": {"amount": {"in": []}}})}
            ),
            "contradictory_constraints",
        )[0]

        assert not hasattr(conflict, "allowed")
        assert not hasattr(conflict, "decision")
        assert conflict.recommendation

    def test_safety_probe_is_advisory_and_does_not_authorize(self, engine):
        # An unconstrained capability evaluates every request as
        # satisfying its constraints, which the probe flags. That is a
        # finding about the capability, not a decision about a request.
        findings = engine.verify_policy_safety(
            Capability2(capability="files.read")
        )

        assert _kinds(findings) == ["unsafe_policy"] * len(findings)
        assert findings
        assert all(f.severity == "high" for f in findings)

    def test_safety_probe_accepts_the_estates_own_cases(self, engine):
        findings = engine.verify_policy_safety(
            Capability2(capability="files.read"),
            test_cases=[{"action": "read", "resource": "public"}],
        )

        # Nothing in the supplied set names a sensitive resource.
        assert findings == ()
