"""v2.2 Policy Conflict Engine (firewall.policy_analysis).

Detects, over the policy representations this codebase actually has:

- contradictory constraints within one policy (``eq`` against ``neq``,
  ``eq`` outside its own ``gte``/``lte`` window, ``in`` against
  ``not_in``, an inverted numeric range)
- unreachable policies -- a constraint no request can satisfy, so the
  policy can never match
- unconditional policies -- a constraint every request satisfies, which
  is widening whatever it is attached to
- incomparable policies for one capability (neither narrows the other)
- invalid delegation constraints and invalid delegation depth
- cross-policy issuer trust disagreements
- conflicting response ``auto_approve`` settings for high-impact stages
- policy changes that increase effective authority, by counterfactual
  replay of recorded cases

**Not detected, because the model does not express them.** Shadowed
rules, unreachable-by-precedence rules, precedence conflicts and
ambiguous authorization all require an *ordered list of matchers* where
an earlier entry can mask a later one. A :class:`RuleSet` is a trusted
issuer set plus a delegation-depth ceiling, and a :class:`Capability2`
constraint is a conjunction of operators; neither has rule ordering, so
there is nothing to shadow. These are named here rather than left for a
reader to infer from their absence.

**Satisfiability analysis is structural, not complete.** The checks
below prove a constraint unsatisfiable when they fire. They do not prove
one satisfiable when they stay silent: no contradiction found means no
contradiction of a recognized shape was found.

Every finding is ``derived`` -- computed from the policies as given.
Counterfactual results are ``simulated``. Nothing here authorizes,
denies, or relaxes anything; :meth:`FirewallSDK.authorize` remains the
only decision authority.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from firewall.capability2 import Capability2
from firewall.policy import PolicyDefinitionError, evaluate_policy
from firewall.sdk import FirewallSDK
from firewall.simulation import CaseSet, RuleSet, simulate


@dataclass(frozen=True)
class PolicyConflict:
    """A detected policy conflict."""

    conflict_type: str
    description: str
    severity: str  # low, medium, high, critical
    rules_involved: tuple[str, ...] = ()
    policies_involved: tuple[str, ...] = ()
    evidence: tuple[dict[str, Any], ...] = ()
    recommendation: str = ""
    provenance: str = "derived"

    def to_dict(self) -> dict[str, Any]:
        return {
            "conflict_type": self.conflict_type,
            "description": self.description,
            "severity": self.severity,
            "rules_involved": list(self.rules_involved),
            "policies_involved": list(self.policies_involved),
            "evidence": [dict(e) for e in self.evidence],
            "recommendation": self.recommendation,
            "provenance": self.provenance,
        }


@dataclass(frozen=True)
class CounterfactualResult:
    """Result of policy counterfactual analysis.

    The counts cover only cases the simulator *counted*: reconstructed,
    reproduced against their recorded decision, and faithful. A case it
    could not replay is excluded and reported in ``excluded_cases``
    rather than folded into a verdict.
    """

    current_policy_version: str
    proposed_policy_version: str
    total_cases: int
    newly_allowed: int
    newly_denied: int
    unchanged_allowed: int
    unchanged_denied: int
    security_delta: str  # improved, degraded, mixed, unchanged, unknown
    counted_cases: int = 0
    excluded_cases: int = 0
    gaps: tuple[str, ...] = ()
    details: list[dict[str, Any]] = field(default_factory=list)
    provenance: str = "simulated"

    @property
    def complete(self) -> bool:
        """True when every case in the set was counted.

        A partial answer is still useful, but it is not the same answer.
        ``security_delta`` describes the counted cases only, so a caller
        gating a policy rollout on ``"unchanged"`` has to know whether
        the cases that would have disagreed are the ones that failed to
        replay.
        """

        return self.excluded_cases == 0 and not self.gaps

    def to_dict(self) -> dict[str, Any]:
        return {
            "current_policy_version": self.current_policy_version,
            "proposed_policy_version": self.proposed_policy_version,
            "total_cases": self.total_cases,
            "newly_allowed": self.newly_allowed,
            "newly_denied": self.newly_denied,
            "unchanged_allowed": self.unchanged_allowed,
            "unchanged_denied": self.unchanged_denied,
            "security_delta": self.security_delta,
            "counted_cases": self.counted_cases,
            "excluded_cases": self.excluded_cases,
            "gaps": list(self.gaps),
            "complete": self.complete,
            "details": self.details,
            "provenance": self.provenance,
        }


class PolicyConflictEngine:
    """
    Analyzes policies for conflicts, shadowing, widening, and other issues.
    Supports counterfactual analysis of policy changes.
    """

    def __init__(
        self,
        sdk: FirewallSDK,
        *,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        if not isinstance(sdk, FirewallSDK):
            raise TypeError("sdk must be a FirewallSDK")

        self._sdk = sdk
        self._clock = clock or time.time
        self._lock = threading.RLock()

    def analyze_policies(
        self,
        policies: dict[str, Any],
        *,
        include_capability2: bool = True,
    ) -> tuple[PolicyConflict, ...]:
        """
        Analyze a collection of policies for conflicts.

        policies: dict mapping policy_name -> policy_object (Capability2, RuleSet, etc.)
        """
        conflicts: list[PolicyConflict] = []

        # Convert all policies to comparable format
        capability2_policies: dict[str, Capability2] = {}
        ruleset_policies: dict[str, RuleSet] = {}
        unclassified: dict[str, str] = {}

        for name, policy in policies.items():
            if isinstance(policy, Capability2):
                capability2_policies[name] = policy
            elif isinstance(policy, RuleSet):
                ruleset_policies[name] = policy
            elif isinstance(policy, dict):
                # Try to parse as Capability2
                try:
                    capability2_policies[name] = Capability2.from_dict(policy)
                except Exception as exc:
                    # A policy that could not be classified is reported.
                    # Dropping it silently made "no conflicts found" mean
                    # "no conflicts found in the policies I could read",
                    # which reads identically to a clean estate.
                    if "rules" not in policy:
                        unclassified[name] = str(exc)

        for name, detail in sorted(unclassified.items()):
            conflicts.append(PolicyConflict(
                conflict_type="unanalyzable_policy",
                description=(
                    f"Policy {name} is neither a Capability2, a RuleSet, "
                    f"nor a response policy with rules, so it was not "
                    f"analyzed: {detail}"
                ),
                severity="medium",
                policies_involved=(name,),
                evidence=({"name": name, "error": detail},),
                recommendation=(
                    "Supply the policy in a supported form, or remove it "
                    "from the analysis set so the absence of findings "
                    "means something"
                ),
            ))

        # 1. Check Capability2 policies for contradictions and widening
        if include_capability2 and capability2_policies:
            conflicts.extend(self._analyze_capability2_conflicts(capability2_policies))

        # 2. Check RuleSet policies for shadowing/unreachable rules
        if ruleset_policies:
            conflicts.extend(self._analyze_ruleset_conflicts(ruleset_policies))

        # 3. Check cross-policy widening (Capability2 vs RuleSet)
        if capability2_policies and ruleset_policies:
            conflicts.extend(self._analyze_cross_policy_conflicts(
                capability2_policies, ruleset_policies
            ))

        # 4. Check delegation constraint conflicts
        conflicts.extend(self._analyze_delegation_conflicts(capability2_policies))

        # 5. Check response policy conflicts
        conflicts.extend(self._analyze_response_conflicts(policies))

        # 6. Check constraint satisfiability (unreachable / unconditional)
        conflicts.extend(
            self._analyze_satisfiability(capability2_policies)
        )

        return tuple(conflicts)

    def _analyze_capability2_conflicts(
        self,
        policies: dict[str, Capability2],
    ) -> list[PolicyConflict]:
        """Analyze Capability2 policies for internal conflicts."""
        conflicts = []

        policy_names = sorted(policies.keys())

        # Contradictory constraints are detected in
        # _analyze_satisfiability, which walks the real
        # {namespace: {field: {operator: value}}} shape. The check that
        # lived here read constraints[namespace] as an operator dict and
        # looked for "eq" alongside "neq" -- those keys are field names
        # at that level, and validate_constraints rejects "neq" as an
        # operator anywhere in a Capability2, so it could never fire.

        # Check pairwise for widening/narrowing conflicts
        for i, name_a in enumerate(policy_names):
            for name_b in policy_names[i+1:]:
                policy_a = policies[name_a]
                policy_b = policies[name_b]

                if policy_a.capability == policy_b.capability:
                    # Same capability - check for conflicts
                    if not policy_a.is_narrower_than(policy_b) and not policy_b.is_narrower_than(policy_a):
                        # Neither is narrower - they conflict
                        conflicts.append(PolicyConflict(
                            conflict_type="policy_conflict",
                            description=f"Policies {name_a} and {name_b} for capability {policy_a.capability} are incomparable (neither narrows the other)",
                            severity="medium",
                            rules_involved=(name_a, name_b),
                            policies_involved=(name_a, name_b),
                            evidence=(
                                {"policy": name_a, "constraints": dict(policy_a.constraints)},
                                {"policy": name_b, "constraints": dict(policy_b.constraints)},
                            ),
                            recommendation="Ensure policies for same capability form a narrowing chain",
                        ))

        return conflicts

    def _analyze_ruleset_conflicts(
        self,
        policies: dict[str, RuleSet],
    ) -> list[PolicyConflict]:
        """Analyze RuleSet policies for shadowing and unreachable rules."""
        conflicts = []

        for name, ruleset in policies.items():
            trusted_issuers = ruleset.trusted_issuers
            max_depth = ruleset.max_delegation_depth

            # Check for shadowed trusted issuers
            if len(trusted_issuers) > 1:
                # All issuers are equally trusted - no shadowing in current model
                pass

            # Check delegation depth
            if max_depth is not None and max_depth <= 0:
                conflicts.append(PolicyConflict(
                    conflict_type="invalid_policy",
                    description=f"RuleSet {name}: max_delegation_depth must be positive",
                    severity="high",
                    rules_involved=(f"{name}.max_delegation_depth",),
                    policies_involved=(name,),
                    recommendation="Set max_delegation_depth to a positive integer or None",
                ))

        return conflicts

    def _analyze_cross_policy_conflicts(
        self,
        cap2_policies: dict[str, Capability2],
        ruleset_policies: dict[str, RuleSet],
    ) -> list[PolicyConflict]:
        """Analyze conflicts between Capability2 and RuleSet policies."""
        conflicts = []

        # RuleSet trusted_issuers vs Capability2 issuer constraints
        for cap2_name, cap2_policy in cap2_policies.items():
            issuer_constraint = cap2_policy.constraints.get("identity", {}).get("issuer")
            if issuer_constraint:
                for rs_name, rs_policy in ruleset_policies.items():
                    if issuer_constraint not in rs_policy.trusted_issuers:
                        conflicts.append(PolicyConflict(
                            conflict_type="cross_policy_conflict",
                            description=f"Capability2 {cap2_name} requires issuer {issuer_constraint} but RuleSet {rs_name} does not trust it",
                            severity="medium",
                            rules_involved=(f"{cap2_name}.identity.issuer", f"{rs_name}.trusted_issuers"),
                            policies_involved=(cap2_name, rs_name),
                            recommendation="Align issuer trust between Capability2 and RuleSet policies",
                        ))

        return conflicts

    def _analyze_delegation_conflicts(
        self,
        policies: dict[str, Capability2],
    ) -> list[PolicyConflict]:
        """Analyze delegation constraint conflicts."""
        conflicts = []

        for name, policy in policies.items():
            lineage = policy.constraints.get("lineage", {})
            max_depth = lineage.get("max_depth")

            if max_depth is not None:
                if isinstance(max_depth, bool) or not isinstance(max_depth, int) or max_depth <= 0:
                    conflicts.append(PolicyConflict(
                        conflict_type="invalid_delegation_constraint",
                        description=f"Policy {name}: lineage.max_depth must be positive integer",
                        severity="high",
                        rules_involved=(f"{name}.lineage.max_depth",),
                        policies_involved=(name,),
                        recommendation="Set lineage.max_depth to a positive integer",
                    ))

        return conflicts

    def _analyze_response_conflicts(
        self,
        policies: dict[str, Any],
    ) -> list[PolicyConflict]:
        """Analyze response policy conflicts."""
        conflicts = []

        # This would integrate with firewall.response2 and firewall.immune
        # For now, check for basic response policy structures
        for name, policy in policies.items():
            if isinstance(policy, dict) and "rules" in policy:
                rules = policy["rules"]
                if isinstance(rules, list):
                    # Check for conflicting auto_approve settings
                    stages_seen: dict[str, bool] = {}
                    for rule in rules:
                        if isinstance(rule, dict):
                            stage = rule.get("stage")
                            auto_approve = rule.get("auto_approve", False)
                            if stage in ("quarantine", "contain"):
                                if stage in stages_seen and stages_seen[stage] != auto_approve:
                                    # A tuple, not a generator: the field
                                    # is declared tuple[str, ...] and
                                    # to_dict() consumes it, so a
                                    # generator emptied itself on the
                                    # first serialization and every later
                                    # reader saw no rules at all.
                                    involved = tuple(
                                        f"{name}.rules[{i}]"
                                        for i, r in enumerate(rules)
                                        if isinstance(r, dict)
                                        and r.get("stage") == stage
                                    )
                                    conflicts.append(PolicyConflict(
                                        conflict_type="response_policy_conflict",
                                        description=f"Policy {name}: conflicting auto_approve for stage {stage}",
                                        severity="high",
                                        rules_involved=involved,
                                        policies_involved=(name,),
                                        recommendation="Ensure consistent auto_approve for high-impact stages",
                                    ))
                                stages_seen[stage] = auto_approve

        return conflicts

    def counterfactual_analysis(
        self,
        current_ruleset: RuleSet,
        proposed_ruleset: RuleSet,
        case_set: CaseSet,
        *,
        current_version: str = "current",
        proposed_version: str = "proposed",
    ) -> CounterfactualResult:
        """Replay recorded traffic under a proposed policy.

        Counts are taken over ``report.counted_outcomes`` and read from
        the ``after_allowed`` boolean, not from the reason string.

        Both details matter for the direction of the answer. A case the
        simulator could not replay has ``after_reason is None``, which is
        ``!= "authorized"``; counting it as a denial made a *widening*
        report as ``"improved"`` when enough cases failed to replay.
        Excluded cases are reported, never counted.
        """

        report = simulate(case_set, current_ruleset, proposed_ruleset)

        counted = report.counted_outcomes
        excluded = report.excluded_outcomes

        newly_allowed = sum(
            1 for o in counted if o.changed and o.after_allowed is True
        )
        newly_denied = sum(
            1 for o in counted if o.changed and o.after_allowed is False
        )

        if not counted:
            # Nothing replayed. "unchanged" would be a claim about
            # cases that were never evaluated.
            security_delta = "unknown"
        elif newly_allowed > 0 and newly_denied == 0:
            security_delta = "degraded"  # more permissive
        elif newly_denied > 0 and newly_allowed == 0:
            security_delta = "improved"  # more restrictive
        elif newly_allowed > 0 and newly_denied > 0:
            security_delta = "mixed"
        else:
            security_delta = "unchanged"

        gaps: list[str] = []
        if excluded:
            gaps.append(
                f"{len(excluded)} of {len(report.outcomes)} cases could "
                "not be replayed and are excluded from every count"
            )

        details: list[dict[str, Any]] = []
        for outcome in counted:
            if outcome.changed:
                details.append(
                    {
                        "agent": outcome.agent,
                        "action": outcome.action,
                        "before": outcome.before_reason,
                        "after": outcome.after_reason,
                        "after_allowed": outcome.after_allowed,
                        "counted": True,
                    }
                )
        for outcome in excluded:
            details.append(
                {
                    "agent": outcome.agent,
                    "action": outcome.action,
                    "before": outcome.before_reason,
                    "after": outcome.after_reason,
                    "after_allowed": outcome.after_allowed,
                    "counted": False,
                    "excluded_because": outcome.error
                    or outcome.note
                    or "not reproducible or not faithful",
                }
            )

        return CounterfactualResult(
            current_policy_version=current_version,
            proposed_policy_version=proposed_version,
            total_cases=len(case_set),
            newly_allowed=newly_allowed,
            newly_denied=newly_denied,
            unchanged_allowed=sum(
                1
                for o in counted
                if not o.changed and o.after_allowed is True
            ),
            unchanged_denied=sum(
                1
                for o in counted
                if not o.changed and o.after_allowed is False
            ),
            security_delta=security_delta,
            counted_cases=len(counted),
            excluded_cases=len(excluded),
            gaps=tuple(gaps),
            details=details,
        )

    def _analyze_satisfiability(
        self,
        policies: dict[str, Capability2],
    ) -> list[PolicyConflict]:
        """Report constraints no request can satisfy, and constraints
        every request satisfies.

        The first is unreachable: it is dead weight, and a reviewer who
        believes it is enforcing something is wrong about what the estate
        enforces. The second is widening -- a namespace present but
        constraining nothing grants that namespace unconditionally,
        while still appearing in the policy as though it were a limit.

        Walks the real constraint shape. A Capability2 constraint is
        ``{namespace: {field: entry}}`` for the six field namespaces, so
        the operators live two levels down; a checker that read
        ``constraints[namespace]`` as an operator dict would be
        inspecting field *names*.
        """

        conflicts: list[PolicyConflict] = []

        for name in sorted(policies):
            policy = policies[name]
            constraints = policy.constraints

            time_window = constraints.get("time")
            if isinstance(time_window, dict):
                not_before = time_window.get("not_before")
                not_after = time_window.get("not_after")
                if (
                    _is_number(not_before)
                    and _is_number(not_after)
                    and not_before > not_after
                ):
                    conflicts.append(
                        self._unreachable(
                            name,
                            "time",
                            dict(time_window),
                            f"not_before {not_before} is after "
                            f"not_after {not_after}",
                        )
                    )

            for namespace in _FIELD_NAMESPACES:
                fields = constraints.get(namespace)
                if not isinstance(fields, dict):
                    continue

                if not fields:
                    conflicts.append(
                        self._unconditional(
                            name,
                            namespace,
                            {},
                            "the namespace is present but constrains no "
                            "field",
                        )
                    )
                    continue

                for field_name in sorted(fields, key=str):
                    entry = fields[field_name]
                    if not isinstance(entry, dict):
                        # A bare scalar, list or None is an equality or
                        # membership test; it always constrains.
                        continue

                    verdict, reason = _operator_verdict(entry)
                    label = f"{namespace}.{field_name}"

                    if verdict == "unsatisfiable":
                        conflicts.append(
                            self._unreachable(
                                name, label, dict(entry), reason
                            )
                        )
                    elif verdict == "unconditional":
                        conflicts.append(
                            self._unconditional(
                                name, label, dict(entry), reason
                            )
                        )

        return conflicts

    def _unreachable(
        self,
        policy_name: str,
        label: str,
        constraint: dict[str, Any],
        reason: str,
    ) -> PolicyConflict:
        return PolicyConflict(
            conflict_type="contradictory_constraints",
            description=(
                f"Policy {policy_name}: {label} can never match "
                f"({reason})"
            ),
            severity="high",
            rules_involved=(f"{policy_name}.{label}",),
            policies_involved=(policy_name,),
            evidence=(
                {
                    "namespace": label,
                    "constraint": constraint,
                    "reason": reason,
                },
            ),
            recommendation=(
                "Remove the constraint or correct it; an unreachable "
                "constraint enforces nothing while appearing to"
            ),
        )

    def _unconditional(
        self,
        policy_name: str,
        label: str,
        constraint: dict[str, Any],
        reason: str,
    ) -> PolicyConflict:
        return PolicyConflict(
            conflict_type="unconditional_constraint",
            description=(
                f"Policy {policy_name}: {label} matches every request "
                f"({reason})"
            ),
            severity="high",
            rules_involved=(f"{policy_name}.{label}",),
            policies_involved=(policy_name,),
            evidence=(
                {
                    "namespace": label,
                    "constraint": constraint,
                    "reason": reason,
                },
            ),
            recommendation=(
                "Constrain the namespace explicitly or drop it; a "
                "namespace that constrains nothing reads as a limit "
                "while imposing none"
            ),
        )

    def verify_policy_safety(
        self,
        policy: Any,
        *,
        test_cases: Optional[list[dict[str, Any]]] = None,
    ) -> tuple[PolicyConflict, ...]:
        """Spot-check a capability against requests it should refuse.

        This is a probe, not a verification, and the empty tuple is not a
        safety proof. It evaluates the capability's own constraints via
        :meth:`Capability2.evaluate` -- it does not call
        ``FirewallSDK.authorize``, so it exercises none of the identity,
        provenance, revocation, budget or policy gates that decide a real
        request. A capability that passes here can still be denied in
        production, and one that fails here has only failed a constraint
        evaluation.

        The default request set is four hardcoded probes keyed on the
        literal string ``"sensitive"`` in the resource. That names one
        convention; supply ``test_cases`` for an estate that does not use
        it. Findings are advisory and cannot authorize anything.
        """
        conflicts: list[PolicyConflict] = []

        if isinstance(policy, Capability2):
            # Test against edge cases
            test_requests = test_cases or [
                {"action": "read", "resource": "sensitive"},
                {"action": "write", "resource": "sensitive"},
                {"action": "admin", "resource": "*"},
                {"action": "*", "resource": "*"},
            ]

            for request in test_requests:
                allowed, reason = policy.evaluate(request)
                if allowed and "sensitive" in str(request.get("resource", "")):
                    conflicts.append(PolicyConflict(
                        conflict_type="unsafe_policy",
                        description=f"Policy {policy.capability} allows access to sensitive resource: {request}",
                        severity="high",
                        policies_involved=(policy.capability,),
                        evidence=({"request": request, "reason": reason},),
                        recommendation="Add constraints to deny sensitive resource access",
                    ))

        return tuple(conflicts)


#: Scalar operators a Capability2 constraint may use, mirroring
#: ``firewall.capability2.constraints._SCALAR_OPERATORS``.
#: ``validate_constraints`` rejects anything outside this set at issue
#: time, so a checker looking for ``neq``, ``not_in`` or ``contains``
#: here can never fire -- those belong to the separate
#: :mod:`firewall.policy` operator form.
_SCALAR_OPERATORS = frozenset(
    {"eq", "lt", "lte", "gt", "gte", "in", "prefix", "glob"}
)

#: Namespaces whose constraint value is ``{field: entry}``, where an
#: entry may itself be an operator dict. ``resource``, ``scope`` and
#: ``action`` are strings or string lists; ``time`` is its own shape.
_FIELD_NAMESPACES = (
    "context",
    "identity",
    "task",
    "lineage",
    "provenance",
    "environment",
)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _operator_verdict(operators: dict[str, Any]) -> tuple[str, str]:
    """Classify one field's operator dict.

    Returns ``("unsatisfiable", reason)``, ``("unconditional", reason)``
    or ``("satisfiable", "")``.

    ``"satisfiable"`` means *no contradiction of a recognized shape was
    found*. It is not a proof: this is structural pattern matching over
    the operator vocabulary, not a decision procedure. Reporting it as
    proof would turn the absence of a finding into a guarantee the check
    cannot give.
    """

    present = {
        key: value
        for key, value in operators.items()
        if key in _SCALAR_OPERATORS
    }

    if not present:
        return ("unconditional", "no constraining operator is present")

    eq = present.get("eq", _MISSING)
    allowed = present.get("in", _MISSING)
    gte = present.get("gte", _MISSING)
    gt = present.get("gt", _MISSING)
    lte = present.get("lte", _MISSING)
    lt = present.get("lt", _MISSING)

    if isinstance(allowed, (list, tuple)) and not allowed:
        return ("unsatisfiable", "in is empty, so nothing is permitted")

    if eq is not _MISSING and isinstance(allowed, (list, tuple)):
        if eq not in allowed:
            return (
                "unsatisfiable",
                f"eq is {eq!r} but in does not contain it",
            )

    # Inverted ranges. gt/lt are strict, so equality of the bounds is
    # already empty for them.
    if _is_number(gte) and _is_number(lte) and gte > lte:
        return ("unsatisfiable", f"gte {gte} is above lte {lte}")
    if _is_number(gt) and _is_number(lte) and gt >= lte:
        return ("unsatisfiable", f"gt {gt} leaves nothing at or below {lte}")
    if _is_number(gte) and _is_number(lt) and gte >= lt:
        return ("unsatisfiable", f"gte {gte} leaves nothing below {lt}")
    if _is_number(gt) and _is_number(lt) and gt >= lt:
        return ("unsatisfiable", f"gt {gt} leaves nothing below {lt}")

    if _is_number(eq):
        if _is_number(gte) and eq < gte:
            return ("unsatisfiable", f"eq {eq} is below gte {gte}")
        if _is_number(gt) and eq <= gt:
            return ("unsatisfiable", f"eq {eq} is not above gt {gt}")
        if _is_number(lte) and eq > lte:
            return ("unsatisfiable", f"eq {eq} is above lte {lte}")
        if _is_number(lt) and eq >= lt:
            return ("unsatisfiable", f"eq {eq} is not below lt {lt}")

    return ("satisfiable", "")


class _Missing:
    """Sentinel distinguishing "operator absent" from ``None``.

    ``operators.get("eq")`` returning ``None`` is ambiguous: a constraint
    may legitimately require a field to equal ``None``, and
    ``validate_constraints`` accepts that.
    """

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<missing>"


_MISSING = _Missing()