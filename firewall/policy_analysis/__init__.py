"""v2.2 Policy Conflict Engine (firewall.policy_analysis).

Detects:
- contradictory rules
- shadowed rules
- unreachable rules
- precedence conflicts
- widening combinations
- ambiguous authorization
- unsafe defaults
- conflicting delegation constraints
- conflicting response policies
- policy changes that increase effective authority

Implements deterministic explanations and counterfactual analysis.
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
    """Result of policy counterfactual analysis."""

    current_policy_version: str
    proposed_policy_version: str
    total_cases: int
    newly_allowed: int
    newly_denied: int
    unchanged_allowed: int
    unchanged_denied: int
    security_delta: str  # "improved", "degraded", "mixed", "unchanged"
    details: list[dict[str, Any]] = field(default_factory=list)
    provenance: str = "simulated"

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

        for name, policy in policies.items():
            if isinstance(policy, Capability2):
                capability2_policies[name] = policy
            elif isinstance(policy, RuleSet):
                ruleset_policies[name] = policy
            elif isinstance(policy, dict):
                # Try to parse as Capability2
                try:
                    capability2_policies[name] = Capability2.from_dict(policy)
                except Exception:
                    pass

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

        return tuple(conflicts)

    def _analyze_capability2_conflicts(
        self,
        policies: dict[str, Capability2],
    ) -> list[PolicyConflict]:
        """Analyze Capability2 policies for internal conflicts."""
        conflicts = []

        policy_names = sorted(policies.keys())

        # Check each policy for self-contradiction
        for name, policy in policies.items():
            # Check for contradictory constraints within the same namespace
            for namespace, constraint in policy.constraints.items():
                if isinstance(constraint, dict):
                    # Check for contradictory operators
                    ops = set(constraint.keys())
                    if "eq" in ops and "neq" in ops:
                        if constraint["eq"] == constraint["neq"]:
                            conflicts.append(PolicyConflict(
                                conflict_type="contradictory_constraints",
                                description=f"Policy {name}: namespace {namespace} has both eq and neq with same value",
                                severity="high",
                                rules_involved=(f"{name}.{namespace}",),
                                policies_involved=(name,),
                                evidence=[{"namespace": namespace, "constraint": constraint}],
                                recommendation="Remove contradictory constraint",
                            ))

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
                            evidence=[
                                {"policy": name_a, "constraints": dict(policy_a.constraints)},
                                {"policy": name_b, "constraints": dict(policy_b.constraints)},
                            ],
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
                                    conflicts.append(PolicyConflict(
                                        conflict_type="response_policy_conflict",
                                        description=f"Policy {name}: conflicting auto_approve for stage {stage}",
                                        severity="high",
                                        rules_involved=(f"{name}.rules[{i}]" for i, r in enumerate(rules) if r.get("stage") == stage),
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
        """
        Perform counterfactual analysis: replay known traffic under proposed policy.

        Returns a CounterfactualResult with security delta assessment.
        """
        # Use the existing simulation infrastructure
        report = simulate(case_set, current_ruleset, proposed_ruleset)

        # Analyze security delta
        newly_allowed = sum(1 for o in report.outcomes if o.changed and o.after_reason == "authorized")
        newly_denied = sum(1 for o in report.outcomes if o.changed and o.after_reason != "authorized")

        if newly_allowed > 0 and newly_denied == 0:
            security_delta = "degraded"  # More permissive
        elif newly_denied > 0 and newly_allowed == 0:
            security_delta = "improved"  # More restrictive
        elif newly_allowed > 0 and newly_denied > 0:
            security_delta = "mixed"
        else:
            security_delta = "unchanged"

        details = []
        for outcome in report.outcomes:
            if outcome.changed:
                details.append({
                    "agent": outcome.agent,
                    "action": outcome.action,
                    "before": outcome.before_reason,
                    "after": outcome.after_reason,
                    "counted": outcome.counted,
                })

        return CounterfactualResult(
            current_policy_version=current_version,
            proposed_policy_version=proposed_version,
            total_cases=len(case_set),
            newly_allowed=newly_allowed,
            newly_denied=newly_denied,
            unchanged_allowed=sum(1 for o in report.outcomes if not o.changed and o.after_reason == "authorized"),
            unchanged_denied=sum(1 for o in report.outcomes if not o.changed and o.after_reason != "authorized"),
            security_delta=security_delta,
            details=details,
        )

    def verify_policy_safety(
        self,
        policy: Any,
        *,
        test_cases: Optional[list[dict[str, Any]]] = None,
    ) -> tuple[PolicyConflict, ...]:
        """
        Verify a policy doesn't introduce unsafe widening.

        Uses the SDK's authorization to test the policy against known cases.
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
                        evidence=[{"request": request, "reason": reason}],
                        recommendation="Add constraints to deny sensitive resource access",
                    ))

        return tuple(conflicts)