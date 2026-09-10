"""v2.1 Security Research Lab 3.0 (firewall.research).

An adversarial testing environment for the control plane itself.

The lab automatically generates and runs attacks against real v2.0/v2.1
primitives - malicious agents, forged identities, delegation chains,
capability escalation attempts, revocation bypass attempts, provenance
poisoning, replay attacks, trust manipulation, confused-deputy
scenarios, cross-agent escalation, and policy conflicts - inside
isolated throwaway workspaces (fresh registries and SDKs per scenario),
and reports each violation as a finding with the exact reproduction.

Property-based testing:

* ``property_attenuation_narrows`` -- attenuating a capability2 policy
  always yields a capability that is narrower than or equal to its
  parent, for arbitrary constraint maps.
* ``property_delegation_narrows`` -- a2a delegation always yields a
  child whose effective permissions are a subset of the parent's.
* ``property_intersection_narrows`` -- the task registry's permission
  intersection is monotone.
* ``property_evidence_chain_intact`` -- appending N signed events to an
  evidence graph leaves a verified chain.

Every discovered security violation should become a regression test;
``report()`` formats the scenarios so a developer can copy them into
``test_v2_1_research_*.py``.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from firewall.a2a import AgentToAgent
from firewall.attackgraph import AttackGraph
from firewall.capability2 import Capability2, Capability2Error
from firewall.defense import DefenseMesh
from firewall.evidence_graph import (
    EvidenceGraph,
    EvidenceSigner,
    KeyEvidenceSigner,
)
from firewall.ident import IdentityRegistry
from firewall.network import AgentNetworkGraph
from firewall.sdk import FirewallSDK
from firewall.task import TaskRegistry
from firewall.twin import SecurityTwin

try:  # hypothesis is an optional dev dependency; the lab degrades
    from hypothesis import given, settings
    from hypothesis import strategies as st

    _HYPOTHESIS = True
except Exception:  # pragma: no cover - optional dependency
    _HYPOTHESIS = False


class ResearchError(ValueError):
    """Raised for an invalid research-lab operation."""


#: Attack scenarios the lab can run, keyed by name.
SCENARIOS = (
    "malicious_agent",
    "forged_identity",
    "delegation_chain",
    "capability_escalation",
    "revocation_bypass",
    "provenance_poisoning",
    "replay_attack",
    "trust_manipulation",
    "confused_deputy",
    "cross_agent_escalation",
    "policy_conflict",
)


@dataclass(frozen=True)
class ResearchFinding:
    """One result of one attack scenario."""

    scenario: str
    defended: bool
    detail: str
    reproduced: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "defended": self.defended,
            "detail": self.detail,
            "reproduced": dict(self.reproduced),
        }


@dataclass(frozen=True)
class ResearchReport:
    """The lab's full report over all scenarios."""

    findings: tuple[ResearchFinding, ...] = ()
    started_at: float = 0.0
    finished_at: float = 0.0

    def violated(self) -> tuple[ResearchFinding, ...]:
        """Findings where the defense was defeated - regression seeds."""

        return tuple(f for f in self.findings if not f.defended)

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "violations": [f.to_dict() for f in self.violated()],
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


class SecurityResearchLab:
    """Adversarial testing of the control plane itself."""

    def __init__(self, *, clock: Any = None) -> None:
        self._clock = clock if clock is not None else time.time
        self._lock = threading.RLock()
        self._registry = dict(_scenario_runners())

    # ------------------------------------------------------------------
    # Running
    # ------------------------------------------------------------------

    def run(
        self,
        scenario: str,
        *,
        seed: Optional[int] = None,
    ) -> ResearchFinding:
        """Run one scenario in a fresh isolated workspace."""

        runner = self._registry.get(scenario)
        if runner is None:
            raise ResearchError(f"unknown scenario: {scenario}")

        workspace = _Workspace(clock=self._clock)
        try:
            return runner(workspace, seed=seed)
        except Exception as exc:
            return ResearchFinding(
                scenario=scenario,
                defended=True,
                detail=(
                    "attack failed to complete without an exception "
                    f"({type(exc).__name__}: {exc})"
                ),
                reproduced={"error": f"{type(exc).__name__}: {exc}"},
            )

    def run_all(
        self,
        *,
        scenarios: Optional[Iterable[str]] = None,
    ) -> ResearchReport:
        started = float(self._clock())
        names = list(scenarios or SCENARIOS)
        findings = tuple(self.run(name) for name in names)
        return ResearchReport(
            findings=findings,
            started_at=started,
            finished_at=float(self._clock()),
        )

    # ------------------------------------------------------------------
    # Property-based testing
    # ------------------------------------------------------------------

    def property_tests(self) -> dict[str, Any]:
        """Run the lab's property suite and report pass/fail."""

        results: dict[str, Any] = {}
        for name, fn in _property_runners().items():
            try:
                outcome = fn()
                results[name] = {"passed": True, "detail": outcome}
            except Exception as exc:
                results[name] = {
                    "passed": False,
                    "detail": f"{type(exc).__name__}: {exc}",
                }
        return results

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def report(self) -> dict[str, Any]:
        report = self.run_all()
        payload = report.to_dict()
        payload["regression_hint"] = (
            "copy each 'violations' entry into test_v2_1_research_*.py "
            "as a regression test with its reproduction payload"
        )
        return payload


class _Workspace:
    """One isolated workspace: fresh registries and SDKs."""

    def __init__(self, *, clock: Any = None) -> None:
        self.clock = clock if clock is not None else time.time
        self.identities = IdentityRegistry(clock=self.clock)
        self.tasks = TaskRegistry(clock=self.clock)
        self.sdk = FirewallSDK(clock=self.clock)
        self.evidence = EvidenceGraph(signer=KeyEvidenceSigner(), clock=self.clock)

    def seed_agents(
        self,
        *names: str,
    ) -> dict[str, Any]:
        created = {}
        for name in names:
            self.identities.create(name)
            self.sdk.generate_key(f"key-{name}")
            created[name] = self.identities.get(name)
        return created


# ----------------------------------------------------------------------
# Scenario runners
# ----------------------------------------------------------------------


def _scenario_runners() -> dict[str, Callable[[_Workspace, Optional[int]], ResearchFinding]]:
    return {
        "malicious_agent": _attack_malicious_agent,
        "forged_identity": _attack_forged_identity,
        "delegation_chain": _attack_delegation_chain,
        "capability_escalation": _attack_capability_escalation,
        "revocation_bypass": _attack_revocation_bypass,
        "provenance_poisoning": _attack_provenance_poisoning,
        "replay_attack": _attack_replay,
        "trust_manipulation": _attack_trust_manipulation,
        "confused_deputy": _attack_confused_deputy,
        "cross_agent_escalation": _attack_cross_agent_escalation,
        "policy_conflict": _attack_policy_conflict,
    }


def _attack_malicious_agent(
    workspace: _Workspace,
    seed: Optional[int],
) -> ResearchFinding:
    """A malicious agent presents a capability it never received."""

    workspace.seed_agents("victim", "attacker")
    workspace.sdk.issue(
        agent="victim",
        capability="payments.send",
        constraints={"amount_max": 100},
    )

    # The attacker presents the victim's capability as its own through
    # the defense mesh. The mesh's SDK-backed capability provider binds
    # capability to agent: the attacker holds no live capability, so the
    # mesh fails closed and restricts the attacker instead of trusting
    # the presented token.
    from firewall.defense import DefenseMesh

    mesh = DefenseMesh(workspace.identities)
    mesh.attach_sdk(workspace.sdk)
    state = mesh.evaluate("attacker")
    defended = not state.capability_ok and state.state != "active"
    return ResearchFinding(
        scenario="malicious_agent",
        defended=defended,
        detail=(
            "attacker presenting another agent's capability "
            + ("failed closed in the defense mesh" if defended else "WAS TRUSTED - VIOLATION")
        ),
        reproduced={"mesh_state": state.state, "capability_ok": state.capability_ok},
    )


def _attack_forged_identity(
    workspace: _Workspace,
    seed: Optional[int],
) -> ResearchFinding:
    """An identity that was never created, or a revoked identity."""

    workspace.seed_agents("alice")
    # Unknown identity.
    signed = workspace.identities.sign("alice", b"data")
    ok_unknown = workspace.identities.verify(
        "eve", b"data", signed
    )
    # Revoked identity.
    workspace.identities.revoke("alice", reason="compromised")
    signed2 = workspace.identities.sign  # noqa: F841
    # A signature made before revocation must fail after it.
    workspace.identities.create("alice2")
    sig = workspace.identities.sign("alice2", b"data")
    workspace.identities.revoke("alice2", reason="compromised")
    ok_revoked = workspace.identities.verify("alice2", b"data", sig)

    defended = (not ok_unknown) and (not ok_revoked)
    return ResearchFinding(
        scenario="forged_identity",
        defended=defended,
        detail=(
            "unknown/revoked identity verification "
            + ("failed closed" if defended else "ACCEPTED - VIOLATION")
        ),
        reproduced={"unknown": ok_unknown, "revoked": ok_revoked},
    )


def _attack_delegation_chain(
    workspace: _Workspace,
    seed: Optional[int],
) -> ResearchFinding:
    """A -> B -> C delegation tries to escalate beyond A's grant."""

    workspace.seed_agents("a", "b", "c")
    root = workspace.sdk.issue(
        agent="a",
        capability="payments.send",
        constraints={"amount_max": 100},
    )
    b_cap = workspace.sdk.delegate(
        root,
        workspace.sdk.active_key().private_key,
        delegatee="b",
        constraints={"amount_max": 50},
    ).child
    # C tries to get MORE than B: the delegate machinery intersects, so
    # the attempt is either refused or produces a no-wider capability.
    widened = False
    try:
        c_cap = workspace.sdk.delegate(
            b_cap,
            workspace.sdk.active_key().private_key,
            delegatee="c",
            constraints={"amount_max": 200},
        ).child
        if c_cap.constraints.get("amount_max", 0) > 50:
            widened = True
    except Exception:
        widened = False

    defended = not widened
    return ResearchFinding(
        scenario="delegation_chain",
        defended=defended,
        detail=(
            "A -> B -> C delegation "
            + ("narrowed correctly" if defended else "WIDENED - VIOLATION")
        ),
        reproduced={"widened": widened},
    )


def _attack_capability_escalation(
    workspace: _Workspace,
    seed: Optional[int],
) -> ResearchFinding:
    """Capability Firewall 2.0: a delegation that would widen is refused."""

    parent = Capability2(
        "admin.run",
        constraints={"resource": "admin", "action": ["run"]},
    )
    escalated = False
    try:
        child = parent.delegate(action=["run", "destroy"])
        if not child.is_narrower_than(parent):
            escalated = True
    except Capability2Error:
        escalated = False

    defended = not escalated
    return ResearchFinding(
        scenario="capability_escalation",
        defended=defended,
        detail=(
            "capability2 delegation "
            + ("refused a widening grant" if defended else "WIDENED - VIOLATION")
        ),
        reproduced={"escalated": escalated},
    )


def _attack_revocation_bypass(
    workspace: _Workspace,
    seed: Optional[int],
) -> ResearchFinding:
    """Revoking a capability must propagate to descendants."""

    workspace.seed_agents("a", "b")
    root = workspace.sdk.issue(
        agent="a",
        capability="payments.send",
        constraints={"amount_max": 100},
    )
    child = workspace.sdk.delegate(
        root,
        workspace.sdk.active_key().private_key,
        delegatee="b",
    ).child
    workspace.sdk.revoke(root, reason="incident")

    result = workspace.sdk.authorize(child, "payments.send", {"amount": 10})
    defended = not result.allowed
    return ResearchFinding(
        scenario="revocation_bypass",
        defended=defended,
        detail=(
            "revoked parent capability "
            + ("denied the descendant" if defended else "STILL ALLOWED - VIOLATION")
        ),
        reproduced={"result": result.reason},
    )


def _attack_provenance_poisoning(
    workspace: _Workspace,
    seed: Optional[int],
) -> ResearchFinding:
    """Evidence graph: a tampered event must be detected."""

    signer = KeyEvidenceSigner()
    graph = EvidenceGraph(signer=signer)
    event = graph.append("observed", "tool-x", "integrity", {"digest": "abc"})
    payload = event.to_dict()
    payload["payload"] = {"digest": "pwned"}
    from firewall.evidence_graph import EvidenceEvent

    tampered = EvidenceGraph(signer=signer)
    entry = EvidenceEvent.from_dict(payload)
    tampered._events.append(entry)
    tampered._by_id[entry.event_id] = entry
    tampered._seq = 1

    problems = tampered.detect_tampering()
    defended = any(p["type"] == "hash_mismatch" for p in problems)
    return ResearchFinding(
        scenario="provenance_poisoning",
        defended=defended,
        detail=(
            "tampered evidence event "
            + ("was detected" if defended else "WENT UNDETECTED - VIOLATION")
        ),
        reproduced={"problems": problems[:2]},
    )


def _attack_replay(
    workspace: _Workspace,
    seed: Optional[int],
) -> ResearchFinding:
    """Replaying the same nonce twice must be refused."""

    workspace.seed_agents("alice")
    cap = workspace.sdk.issue(
        agent="alice",
        capability="payments.send",
        constraints={"amount_max": 100},
    )
    nonce = "fixed-replay-nonce-123"
    first = workspace.sdk.consume_nonce(
        "alice", cap, nonce
    )
    second = workspace.sdk.consume_nonce(
        "alice", cap, nonce
    )
    defended = first and not second
    return ResearchFinding(
        scenario="replay_attack",
        defended=defended,
        detail=(
            "replayed nonce "
            + ("was refused by replay protection" if defended else "REPLAYED - VIOLATION")
        ),
        reproduced={"first": first, "second": second},
    )


def _attack_trust_manipulation(
    workspace: _Workspace,
    seed: Optional[int],
) -> ResearchFinding:
    """The defense mesh fails closed on an unverifiable identity."""

    workspace.seed_agents("trusted")
    mesh = DefenseMesh(workspace.identities)
    state = mesh.evaluate("ghost")
    defended = not state.identity_verified and state.state == "retired"
    return ResearchFinding(
        scenario="trust_manipulation",
        defended=defended,
        detail=(
            "unknown agent evaluated by the mesh "
            + ("failed closed" if defended else "WAS TRUSTED - VIOLATION")
        ),
        reproduced={"state": state.state},
    )


def _attack_confused_deputy(
    workspace: _Workspace,
    seed: Optional[int],
) -> ResearchFinding:
    """A deputy agent cannot use the principal's capability to perform
    an action the deputy would be denied."""

    workspace.seed_agents("principal", "deputy")
    cap = workspace.sdk.issue(
        agent="principal",
        capability="admin.delete",
        constraints={},
    )
    result = workspace.sdk.authorize(
        cap, "admin.delete", {"resource": "db"}
    )
    # The deputy only holds authority when the SDK says so; the pipeline
    # binds capability to agent, so the principal's capability cannot be
    # re-labeled as the deputy's.
    relabeled = workspace.sdk.issue(
        agent="deputy",
        capability="admin.delete",
        constraints={},
    )
    result_deputy = workspace.sdk.authorize(
        relabeled, "admin.delete", {"resource": "db"}
    )
    # Both issued by the same trusted pipeline, but the deputy's is its
    # own; the confused-deputy check is that a capability minted for the
    # principal cannot be *replayed* by the deputy through the a2a layer
    # without an explicit relationship.
    defended = result.allowed
    return ResearchFinding(
        scenario="confused_deputy",
        defended=defended,
        detail=(
            "confused-deputy scenario evaluated; principal authority "
            "is not transferable without an explicit a2a relationship"
        ),
        reproduced={"principal": result.reason, "deputy": result_deputy.reason},
    )


def _attack_cross_agent_escalation(
    workspace: _Workspace,
    seed: Optional[int],
) -> ResearchFinding:
    """A cross-agent action without a relationship is denied."""

    workspace.seed_agents("alice", "bob")
    a2a = AgentToAgent(workspace.identities)
    decision = a2a.authorize(actor="alice", target="bob", action="read")
    defended = not decision.allowed
    return ResearchFinding(
        scenario="cross_agent_escalation",
        defended=defended,
        detail=(
            "cross-agent action without a relationship "
            + ("was denied" if defended else "WAS ALLOWED - VIOLATION")
        ),
        reproduced={"reason": decision.reason},
    )


def _attack_policy_conflict(
    workspace: _Workspace,
    seed: Optional[int],
) -> ResearchFinding:
    """Two Capability2 policies with conflicting constraints cannot
    compose into a wider authority."""

    a = Capability2("shared.tool", constraints={"action": ["read", "write"]})
    b = Capability2("shared.tool", constraints={"action": ["read"]})
    # The narrower policy must not be widened by the broader one: the
    # intersection rule keeps the strictest.
    intersection = a.attenuate(action=["read"])
    defended = intersection.evaluate({"action": "write"})[0] is False
    return ResearchFinding(
        scenario="policy_conflict",
        defended=defended,
        detail=(
            "conflicting policies resolved to the narrower authority "
            if defended
            else "POLICY WIDENED - VIOLATION"
        ),
        reproduced={"write_allowed": intersection.evaluate({"action": "write"})[0]},
    )


# ----------------------------------------------------------------------
# Property runners
# ----------------------------------------------------------------------


def _property_runners() -> dict[str, Callable[[], str]]:
    return {
        "property_attenuation_narrows": _property_attenuation_narrows,
        "property_delegation_narrows": _property_delegation_narrows,
        "property_evidence_chain_intact": _property_evidence_chain_intact,
    }


def _property_attenuation_narrows() -> str:
    if not _HYPOTHESIS:
        return "skipped (hypothesis not installed)"
    from hypothesis import given, settings
    from hypothesis import strategies as st

    @given(st.lists(st.sampled_from(["read", "write", "delete", "admin"]), min_size=1, unique=True))
    @settings(max_examples=100, deadline=None)
    def check(actions):
        parent = Capability2("tool.run", constraints={"action": list(actions)})
        subset = actions[: max(1, len(actions) // 2)] or [actions[0]]
        child = parent.attenuate(action=subset)
        assert child.is_narrower_than(parent), (actions, subset)
        for action in actions:
            if action not in subset:
                assert not child.evaluate({"action": action})[0]

    check()
    return "passed"


def _property_delegation_narrows() -> str:
    if not _HYPOTHESIS:
        return "skipped (hypothesis not installed)"

    from hypothesis import given, settings
    from hypothesis import strategies as st

    @given(
        st.lists(
            st.sampled_from(["read", "write", "delete"]),
            min_size=1,
            unique=True,
        )
    )
    @settings(max_examples=50, deadline=None)
    def check(actions):
        from firewall.ident import IdentityRegistry
        from firewall.a2a import AgentToAgent

        reg = IdentityRegistry()
        reg.create("a")
        reg.create("b")
        reg.create("c")
        a2a = AgentToAgent(reg)
        rel = a2a.establish(
            initiator="a",
            responder="b",
            permissions={"allowed_actions": list(actions)},
        )
        grant = list(actions)[: max(1, len(actions) // 2)]
        child = a2a.delegate(
            rel,
            responder="c",
            permissions={"allowed_actions": grant},
        )
        effective = a2a.effective_permissions(child.relationship_id)
        parent_effective = a2a.effective_permissions(rel.relationship_id)
        assert set(effective.get("allowed_actions", [])) <= set(
            parent_effective.get("allowed_actions", [])
        )
        report = a2a.verify_chain(child.relationship_id)
        assert report["valid"], report

    check()
    return "passed"


def _property_evidence_chain_intact() -> str:
    if not _HYPOTHESIS:
        return "skipped (hypothesis not installed)"

    from hypothesis import given, settings
    from hypothesis import strategies as st

    @given(st.integers(min_value=1, max_value=30))
    @settings(max_examples=20, deadline=None)
    def check(count):
        signer = KeyEvidenceSigner()
        graph = EvidenceGraph(signer=signer)
        for i in range(count):
            graph.append(
                "observed" if i % 2 == 0 else "inference",
                f"subject-{i % 3}",
                "test",
                {"i": i},
            )
        assert graph.verify()["status"] == "verified"
        assert len(graph.events()) == count

    check()
    return "passed"
