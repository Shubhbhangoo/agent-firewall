"""Regression tests for the v2.1 hostile security audit.

Every test in this file corresponds to a reproduced exploit. They assert
the security invariant that was broken, not the implementation that
happened to fix it:

* quarantine recovery restores only the authority *that quarantine
  suspended* - never a revocation that predates it;
* a recursively-revoked delegation is never relaundered as a root
  capability;
* a denied re-entry never leaves authority live;
* an unrecognised persisted mesh state never defaults to ``active``;
* containment is always possible, including after a recovery cycle.
"""

from __future__ import annotations

import json
import time

import pytest

from firewall.attackgraph import AttackGraph
from firewall.capability2 import Capability2, Capability2Error
from firewall.containment import (
    ContainmentAction,
    ContainmentController,
    ContainmentState,
)
from firewall.defense import DefenseError, DefenseMesh
from firewall.evidence_graph import (
    EvidenceError,
    EvidenceGraph,
    KeyEvidenceSigner,
)
from firewall.ident import IdentityRegistry
from firewall.posture import PostureEngine, PostureSignal
from firewall.sdk import FirewallSDK
from firewall.twin import SecurityTwin


class Clock:
    """Advanceable clock anchored to wall time.

    Anchored rather than arbitrary: ``FirewallSDK.issue()`` stamps
    ``issued_at`` from the wall clock, so a clock at an unrelated epoch
    would make every freshly issued capability look ``not_yet_valid``.
    """

    def __init__(self) -> None:
        self.t = time.time()

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float = 1.0) -> None:
        self.t += seconds


def build(*agents: str):
    """A mesh wired to a live SDK and containment controller."""

    registry = IdentityRegistry()
    for agent in agents or ("agent-a",):
        registry.create(agent)
    clock = Clock()
    sdk = FirewallSDK(clock=clock)
    sdk.generate_key("audit-key")
    containment = ContainmentController(
        sdk, authorizer=lambda: True, clock=clock
    )
    mesh = DefenseMesh(
        registry,
        posture=PostureEngine(),
        containment=containment,
        clock=clock,
    )
    mesh.attach_sdk(sdk)
    return registry, sdk, containment, mesh, clock


def live(sdk, agent: str) -> list:
    return [
        capability
        for capability in sdk._capability_registry.values()
        if capability.agent_id == agent
        and not sdk.is_effectively_revoked(capability)
    ]


# ======================================================================
# Recovery must not resurrect authority quarantine never took
# ======================================================================


class TestRecoveryDoesNotResurrectAuthority:
    def test_revocation_predating_quarantine_is_not_restored(self):
        """A standing operator revocation survives an unrelated
        quarantine/recovery cycle.

        The exploit: revoke a dangerous capability permanently, then
        quarantine and recover the agent for an unrelated incident.
        Recovery used to re-issue *every* revoked capability the agent
        had ever held, handing back the revoked authority under a fresh
        fingerprint the revocation registry no longer matched.
        """

        _, sdk, _, mesh, clock = build()

        sdk.issue(agent="agent-a", capability="logs.read")
        dangerous = sdk.issue(
            agent="agent-a",
            capability="payments.send",
            constraints={"amount_max": 1_000_000},
        )
        sdk.revoke(dangerous, reason="operator: no payments, ever")
        assert not sdk.authorize(
            dangerous, "payments.send", {"amount": 1}
        ).allowed

        clock.advance(10)
        mesh.quarantine("agent-a", reason="unrelated incident")
        clock.advance(10)
        mesh.recover("agent-a", reason="incident cleared")
        clock.advance(10)
        mesh.reenter("agent-a", reason="cleared to resume")

        assert mesh.state("agent-a")["state"] == "active"
        # The benign capability comes back; the revoked one does not.
        capabilities = live(sdk, "agent-a")
        assert [c.capability for c in capabilities] == ["logs.read"]
        for capability in capabilities:
            assert capability.capability != "payments.send"

    def test_recursively_revoked_child_is_not_relaundered(self):
        """Parent revocation keeps binding a restored child.

        The exploit: a delegated child is revoked through its parent, so
        it is only *effectively* revoked. Recovery re-issued it as a
        fresh root capability with an empty lineage, permanently
        defeating the parent's revocation and resetting delegation depth
        to zero.
        """

        _, sdk, _, mesh, clock = build("agent-a", "agent-b")

        parent = sdk.issue(
            agent="agent-a",
            capability="payments.send",
            constraints={"amount_max": 500},
        )
        key = sdk.active_key().private_key
        child = sdk.delegate(
            parent, key, delegatee="agent-b", constraints={"amount_max": 100}
        ).child
        # ``issue``/``delegate`` stamp ``issued_at`` from the wall clock,
        # which has moved on since this clock was anchored.
        clock.advance(1)
        assert sdk.authorize(child, "payments.send", {"amount": 50}).allowed

        sdk.revoke(parent, reason="parent compromised")
        assert sdk.is_effectively_revoked(child)

        clock.advance(10)
        mesh.quarantine("agent-b", reason="incident")
        clock.advance(10)
        mesh.recover("agent-b", reason="cleared")
        clock.advance(10)
        with pytest.raises(DefenseError):
            # Nothing may be restored, so the agent holds no live
            # authority and re-entry fails closed.
            mesh.reenter("agent-b", reason="try to resume")

        assert live(sdk, "agent-b") == []

    def test_recovering_state_does_not_restore_authority(self):
        """``recovering`` is an investigation state, not a cleared one."""

        _, sdk, _, mesh, clock = build()

        sdk.issue(
            agent="agent-a",
            capability="payments.send",
            constraints={"amount_max": 100},
        )
        clock.advance(10)
        mesh.quarantine("agent-a", reason="compromise suspected")
        clock.advance(10)
        mesh.recover("agent-a", reason="investigating")

        assert mesh.state("agent-a")["state"] == "recovering"
        assert live(sdk, "agent-a") == []

    def test_denied_reentry_leaves_no_live_authority(self):
        """A re-entry denied on posture must not leave authority live.

        The exploit: authority was restored on entry to ``recovering``,
        before re-entry verified anything. Re-entry then correctly
        refused a compromised agent - which kept its restored authority
        anyway.
        """

        _, sdk, containment, mesh, clock = build()
        posture = mesh._posture

        sdk.issue(
            agent="agent-a",
            capability="payments.send",
            constraints={"amount_max": 100},
        )
        clock.advance(10)
        mesh.quarantine("agent-a", reason="compromise suspected")
        clock.advance(10)
        mesh.recover("agent-a", reason="investigating")

        posture.ingest(
            "agent-a",
            PostureSignal(
                name="compromise", severity=9, description="beaconing"
            ),
        )
        clock.advance(10)
        with pytest.raises(DefenseError, match="posture"):
            mesh.reenter("agent-a", reason="attempt re-entry")

        assert mesh.state("agent-a")["state"] == "recovering"
        assert live(sdk, "agent-a") == []

    def test_reentry_denied_by_capability_provider_undoes_restore(self):
        """A provider that denies at the last gate rolls the restore back.

        Restoration has to happen before the capability check - the
        default provider reports "can act" only while the agent holds
        live authority - so the denial path is what keeps the invariant
        true. It must also leave the containment posture in place.
        """

        _, sdk, containment, mesh, clock = build()

        sdk.issue(
            agent="agent-a",
            capability="payments.send",
            constraints={"amount_max": 100},
        )
        clock.advance(10)
        mesh.quarantine("agent-a", reason="incident")
        clock.advance(10)
        mesh.recover("agent-a", reason="investigating")

        # ``attach_sdk`` installs the SDK-backed provider, so the only
        # way to model "the provider still says no" is to replace it.
        mesh._capability_provider = lambda agent: (
            False,
            "still under investigation",
        )
        clock.advance(10)
        with pytest.raises(DefenseError, match="still under investigation"):
            mesh.reenter("agent-a", reason="attempt re-entry")

        assert mesh.state("agent-a")["state"] == "recovering"
        assert live(sdk, "agent-a") == []
        assert (
            containment.state("agent-a") is ContainmentState.QUARANTINED
        )

    def test_verified_reentry_does_restore_authority(self):
        """Positive control: the legitimate lifecycle still works.

        Without this, every test above could pass by never restoring
        anything at all.
        """

        _, sdk, _, mesh, clock = build()

        sdk.issue(
            agent="agent-a",
            capability="payments.send",
            constraints={"amount_max": 100},
        )
        clock.advance(10)
        mesh.quarantine("agent-a", reason="incident")
        assert live(sdk, "agent-a") == []

        clock.advance(10)
        mesh.recover("agent-a", reason="investigated")
        clock.advance(10)
        mesh.reenter("agent-a", reason="cleared")

        assert mesh.state("agent-a")["state"] == "active"
        restored = live(sdk, "agent-a")
        assert len(restored) == 1
        result = sdk.authorize(
            restored[0], "payments.send", {"amount": 50}
        )
        assert result.allowed, result.reason
        # Attenuation is preserved: the restored grant is not widened.
        assert restored[0].constraints["amount_max"] == 100
        assert not sdk.authorize(
            restored[0], "payments.send", {"amount": 5_000}
        ).allowed


# ======================================================================
# Containment must always be possible
# ======================================================================


class TestContainmentIsAlwaysPossible:
    def test_recovered_agent_can_be_quarantined_again(self):
        """A second incident must be containable.

        The exploit: ``recovered`` was absent from every containment
        transition's allowed-from set, so an agent that had been through
        one recovery cycle was permanently immune to containment.
        """

        clock = Clock()
        sdk = FirewallSDK(clock=clock)
        sdk.generate_key("k")
        containment = ContainmentController(
            sdk, authorizer=lambda: True, clock=clock
        )

        sdk.issue(agent="agent-a", capability="payments.send")
        containment.apply(
            ContainmentAction.QUARANTINE_AGENT,
            "agent-a",
            actor="op",
            reason="incident 1",
        )
        clock.advance(10)
        containment.apply(
            ContainmentAction.RECOVER,
            "agent-a",
            actor="op",
            reason="cleared",
        )
        assert containment.state("agent-a") is ContainmentState.RECOVERED

        # New authority granted after the recovery, then a second
        # incident: quarantine must revoke it.
        clock.advance(10)
        sdk.issue(
            agent="agent-a",
            capability="payments.send",
            constraints={"amount_max": 999},
        )
        assert live(sdk, "agent-a")

        containment.apply(
            ContainmentAction.QUARANTINE_AGENT,
            "agent-a",
            actor="op",
            reason="incident 2: confirmed compromise",
        )
        assert containment.state("agent-a") is ContainmentState.QUARANTINED
        assert live(sdk, "agent-a") == []

    def test_recovery_still_requires_prior_containment(self):
        """Loosening stays strict: an uncontained agent cannot recover."""

        clock = Clock()
        sdk = FirewallSDK(clock=clock)
        sdk.generate_key("k")
        containment = ContainmentController(
            sdk, authorizer=lambda: True, clock=clock
        )
        with pytest.raises(Exception):
            containment.apply(
                ContainmentAction.RECOVER,
                "agent-a",
                actor="op",
                reason="never contained",
            )

    def test_mesh_quarantine_contains_after_a_recovery_cycle(self):
        """The mesh must not report a quarantine it did not perform.

        The exploit: the mesh swallowed the controller's
        ``ContainmentError``, recorded the agent as ``quarantined``, and
        left every capability live - claiming a "capability provider
        backstop" that does not gate ``authorize()``.
        """

        _, sdk, containment, mesh, clock = build()

        sdk.issue(agent="agent-a", capability="payments.send")
        clock.advance(5)
        mesh.quarantine("agent-a", reason="incident 1")
        clock.advance(5)
        mesh.recover("agent-a", reason="cleared")
        clock.advance(5)
        mesh.reenter("agent-a", reason="back to work")
        assert mesh.state("agent-a")["state"] == "active"

        clock.advance(5)
        sdk.issue(
            agent="agent-a",
            capability="payments.send",
            constraints={"amount_max": 1_000_000},
        )
        assert live(sdk, "agent-a")

        mesh.quarantine("agent-a", reason="incident 2: confirmed compromise")
        assert mesh.state("agent-a")["state"] == "quarantined"
        assert live(sdk, "agent-a") == []

    def test_stale_containment_records_are_not_replayed(self):
        """Each recovery restores only its own quarantine's records.

        Restoration records used to accumulate: a capability restored by
        cycle one stayed on the list, so if an operator revoked it in
        between, cycle two's recovery resurrected it.
        """

        clock = Clock()
        sdk = FirewallSDK(clock=clock)
        sdk.generate_key("k")
        containment = ContainmentController(
            sdk, authorizer=lambda: True, clock=clock
        )

        sdk.issue(agent="agent-a", capability="payments.send")
        containment.apply(
            ContainmentAction.QUARANTINE_AGENT,
            "agent-a",
            actor="op",
            reason="incident 1",
        )
        clock.advance(10)
        containment.apply(
            ContainmentAction.RECOVER,
            "agent-a",
            actor="op",
            reason="cleared",
        )
        assert containment._revoked.get("agent-a", []) == []

        # Whatever came back, the operator now revokes for good.
        for capability in live(sdk, "agent-a"):
            sdk.revoke(capability, reason="operator: permanent")

        clock.advance(10)
        containment.apply(
            ContainmentAction.QUARANTINE_AGENT,
            "agent-a",
            actor="op",
            reason="incident 2",
        )
        clock.advance(10)
        containment.apply(
            ContainmentAction.RECOVER,
            "agent-a",
            actor="op",
            reason="cleared again",
        )
        assert live(sdk, "agent-a") == []


# ======================================================================
# Persisted state must fail closed
# ======================================================================


class TestPersistedStateFailsClosed:
    def test_unknown_persisted_state_refuses_to_load(self, tmp_path):
        """An unrecognised state must never fall through to ``active``.

        The exploit: ``_load`` dropped any state not in ``MESH_STATES``
        and ``self._states.get(agent, "active")`` supplied the default,
        so editing one byte of ``mesh.json`` turned a quarantined agent
        active on restart.
        """

        path = tmp_path / "mesh.json"
        path.write_text(
            json.dumps(
                {
                    "states": {"agent-a": "quarantined!"},
                    "recovery_started": {},
                    "transitions": [],
                }
            ),
            encoding="utf-8",
        )
        registry = IdentityRegistry()
        registry.create("agent-a")

        with pytest.raises(DefenseError, match="unknown state"):
            DefenseMesh(registry, state_path=path)

    def test_quarantined_state_survives_restart(self, tmp_path):
        """Positive control: a valid quarantine still reloads."""

        path = tmp_path / "mesh.json"
        registry = IdentityRegistry()
        registry.create("agent-a")
        mesh = DefenseMesh(registry, state_path=path)
        mesh.quarantine("agent-a", actor="op", reason="incident")
        mesh.close()

        registry2 = IdentityRegistry()
        registry2.create("agent-a")
        reloaded = DefenseMesh(registry2, state_path=path)
        assert reloaded.state("agent-a")["state"] == "quarantined"


# ======================================================================
# capability2: a string constraint is not a prefix pattern
# ======================================================================


class TestCapability2PrefixMatchingIsBounded:
    """The exploit: ``_evaluate_value`` treated *every* string constraint
    as a prefix, on every namespace. A capability limited to
    ``action=read`` therefore authorised ``action=read_all_secrets``, and
    a scope of ``/tmp/safe`` authorised ``/tmp/safe-but-actually-evil``.
    Prefix matching is only sound for a hierarchical scope, and only at a
    segment boundary.
    """

    def test_action_is_not_a_prefix_pattern(self):
        cap = Capability2("reports", constraints={"action": "read"})
        allowed, reason = cap.evaluate({"action": "read_all_secrets"})
        assert allowed is False, reason
        assert cap.evaluate({"action": "read"})[0] is True

    def test_resource_is_not_a_prefix_pattern(self):
        cap = Capability2("reports", constraints={"resource": "reports"})
        allowed, reason = cap.evaluate(
            {"resource": "reports_admin_override"}
        )
        assert allowed is False, reason
        assert cap.evaluate({"resource": "reports"})[0] is True

    def test_opaque_namespace_keys_are_not_prefixes(self):
        cap = Capability2(
            "db.read", constraints={"environment": {"region": "eu"}}
        )
        assert cap.evaluate({"region": "eu-secret-prod"})[0] is False
        assert cap.evaluate({"region": "eu"})[0] is True

    @pytest.mark.parametrize(
        "path",
        [
            "/tmp/safe-but-actually-evil/creds",
            "/tmp/safe2",
            "/tmp/safeish",
            "/tmp/safe.bak",
        ],
    )
    def test_scope_prefix_requires_a_segment_boundary(self, path):
        cap = Capability2("files", constraints={"scope": "/tmp/safe"})
        allowed, reason = cap.evaluate({"path": path})
        assert allowed is False, reason

    @pytest.mark.parametrize(
        "path", ["/tmp/safe", "/tmp/safe/report.txt", "/tmp/safe/a/b/c"]
    )
    def test_scope_still_contains_its_own_subtree(self, path):
        cap = Capability2("files", constraints={"scope": "/tmp/safe"})
        allowed, reason = cap.evaluate({"path": path})
        assert allowed is True, reason

    def test_trailing_separator_scope_matches_its_subtree(self):
        cap = Capability2("files", constraints={"scope": "/tmp/safe/"})
        assert cap.evaluate({"path": "/tmp/safe/x"})[0] is True
        assert cap.evaluate({"path": "/tmp/safe-evil/x"})[0] is False


class TestCapability2NarrowingCannotWiden:
    """Delegation may narrow authority but must never widen it."""

    def test_extending_a_string_is_not_narrowing(self):
        parent = Capability2(
            "reports",
            constraints={"action": "read", "resource": "reports"},
        )
        # A hand-written "child" that extends both strings. The parent
        # denies this request, so the child must not be accepted as an
        # attenuation of it.
        child = Capability2(
            "reports",
            constraints={
                "action": "read_all_secrets",
                "resource": "reports_admin_override",
            },
        )
        assert parent.evaluate(
            {"action": "read_all_secrets",
             "resource": "reports_admin_override"}
        )[0] is False
        assert child.is_narrower_than(parent) is False

    def test_scope_widening_past_a_segment_boundary_is_refused(self):
        parent = Capability2("files", constraints={"scope": "/tmp/safe"})
        evil = Capability2(
            "files", constraints={"scope": "/tmp/safe-but-actually-evil"}
        )
        good = Capability2(
            "files", constraints={"scope": "/tmp/safe/reports"}
        )
        assert evil.is_narrower_than(parent) is False
        assert good.is_narrower_than(parent) is True

    def test_dropping_a_constrained_namespace_is_not_narrowing(self):
        """``evaluate`` skips namespaces it holds no constraint for, so a
        child that simply omits one the parent constrains is *unlimited*
        there - a widening dressed as a subset."""

        parent = Capability2(
            "files",
            constraints={"action": "read", "scope": "/tmp/safe"},
        )
        dropped = Capability2("files", constraints={"action": "read"})
        request = {"action": "read", "path": "/etc/shadow"}
        assert parent.evaluate(request)[0] is False
        # The child would allow what the parent denies...
        assert dropped.evaluate(request)[0] is True
        # ...so it must not pass the narrowing check.
        assert dropped.is_narrower_than(parent) is False

    def test_attenuate_never_returns_a_wider_capability(self):
        """``attenuate`` is the documented safe-narrowing API: it must
        refuse, not silently widen.

        The exploit: ``_narrow_scalar`` returned the child whenever it
        merely *extended* the parent string, so
        ``attenuate(environment={"region": "eu-secret-prod"})`` on a
        capability bound to ``region == "eu"`` produced a child that
        permitted exactly what the parent denied.
        """

        parent = Capability2(
            "db.read",
            constraints={"environment": {"region": "eu",
                                         "tier": "staging"}},
        )
        request = {"region": "eu-secret-prod", "tier": "staging"}
        assert parent.evaluate(request)[0] is False

        with pytest.raises(Capability2Error):
            parent.attenuate(environment={"region": "eu-secret-prod"})

    def test_attenuate_still_narrows(self):
        """Positive control: real narrowing keeps working and the result
        is accepted by ``is_narrower_than``."""

        parent = Capability2(
            "db.read",
            constraints={"context": {"amount": 100, "team": "eu"},
                         "action": ["read", "write"]},
        )
        child = parent.attenuate(context={"amount": 10}, action=["read"])
        assert child.is_narrower_than(parent) is True
        assert child.evaluate(
            {"amount": 5, "team": "eu", "action": "read"}
        )[0] is True
        # Narrower than the parent on both axes.
        assert child.evaluate(
            {"amount": 50, "team": "eu", "action": "read"}
        )[0] is False
        assert child.evaluate(
            {"amount": 5, "team": "eu", "action": "write"}
        )[0] is False

    def test_dotted_scope_keeps_its_own_delimiter(self):
        """A scope uses one delimiter, not all of them.

        ``payments`` is a flat root, so ``.`` may open its first child
        segment; once the scope is a path, only ``/`` does - otherwise
        ``/tmp/safe.bak``, a sibling file, reads as a child of
        ``/tmp/safe``.
        """

        flat = Capability2("x", constraints={"scope": "payments"})
        assert flat.evaluate({"path": "payments.send"})[0] is True
        assert flat.evaluate({"path": "payments_admin"})[0] is False

        dotted = Capability2("x", constraints={"scope": "org.team"})
        assert dotted.evaluate({"path": "org.team.project"})[0] is True
        assert dotted.evaluate({"path": "org.teamx"})[0] is False

        path = Capability2("x", constraints={"scope": "/srv/app.v1"})
        assert path.evaluate({"path": "/srv/app.v1/logs"})[0] is True
        assert path.evaluate({"path": "/srv/app.v1.bak"})[0] is False


# ======================================================================
# Evidence must not be deletable without a tamper signal
# ======================================================================


class TestEvidenceDeletionIsDetected:
    """The exploit: ``_load`` swallowed ``EvidenceError`` per entry, so
    corrupting one field of the last event *deleted* it. The surviving
    chain stayed internally consistent - no broken link, no sequence gap
    - and ``verify()`` reported ``verified`` over a truncated graph.
    Plain tail truncation had the same effect.
    """

    def _graph(self, path):
        signer = KeyEvidenceSigner()
        graph = EvidenceGraph(signer, state_path=path)
        for event_type in (
            "authorization_denied",
            "quarantined",
            "exfiltration_attempt",
        ):
            graph.append("observed", "agent-a", event_type, {"n": 1})
        graph.close()
        return signer, path.read_text(encoding="utf-8")

    def test_corrupting_the_last_event_is_not_a_silent_delete(self, tmp_path):
        path = tmp_path / "evidence.json"
        signer, original = self._graph(path)

        data = json.loads(original)
        data["events"][-1]["seq"] = "not-an-integer"
        path.write_text(json.dumps(data), encoding="utf-8")

        with pytest.raises(EvidenceError):
            EvidenceGraph(signer, state_path=path)

    def test_tail_truncation_is_detected(self, tmp_path):
        path = tmp_path / "evidence.json"
        signer, original = self._graph(path)

        data = json.loads(original)
        path.write_text(
            json.dumps({"events": data["events"][:1], "head": data["head"]}),
            encoding="utf-8",
        )
        with pytest.raises(EvidenceError, match="head mismatch"):
            EvidenceGraph(signer, state_path=path)

    def test_dropped_count_is_detected(self, tmp_path):
        """Even with a head the attacker also rewrote, the recorded
        length has to line up."""

        path = tmp_path / "evidence.json"
        signer, original = self._graph(path)

        data = json.loads(original)
        kept = [data["events"][0], data["events"][2]]
        path.write_text(
            json.dumps(
                {"events": kept, "head": kept[-1]["event_id"], "count": 3}
            ),
            encoding="utf-8",
        )
        with pytest.raises(EvidenceError, match="missing events"):
            EvidenceGraph(signer, state_path=path)

    def test_middle_deletion_still_breaks_the_chain(self, tmp_path):
        path = tmp_path / "evidence.json"
        signer, original = self._graph(path)

        data = json.loads(original)
        kept = [data["events"][0], data["events"][2]]
        path.write_text(
            json.dumps(
                {"events": kept, "head": kept[-1]["event_id"],
                 "count": len(kept)}
            ),
            encoding="utf-8",
        )
        graph = EvidenceGraph(signer, state_path=path)
        report = graph.verify()
        assert report["status"] == "failed"
        assert "broken_link" in {p["type"] for p in report["problems"]}

    def test_untouched_state_reloads_verified(self, tmp_path):
        """Positive control: the fix must not break honest reload."""

        path = tmp_path / "evidence.json"
        signer, original = self._graph(path)
        path.write_text(original, encoding="utf-8")

        graph = EvidenceGraph(signer, state_path=path)
        report = graph.verify()
        assert report["status"] == "verified", report["problems"]
        assert report["events"] == 3


# ======================================================================
# The twin must not share mutable state with production
# ======================================================================


class TestTwinIsolation:
    def test_counterfactuals_never_mutate_the_live_graph(self):
        live = self._live()
        before = json.dumps(live.to_dict(), sort_keys=True)
        twin = SecurityTwin.from_graph(live)

        twin.compromise("a")
        twin.revoke_capability("a", "payments.send")
        twin.delegate("a", "b", permissions={"allowed": ["x"]})
        twin.expose_credential("a", credential="root-key")

        assert json.dumps(live.to_dict(), sort_keys=True) == before

    def test_twin_shares_no_nested_mutable_state(self):
        """The exploit: ``_clone`` copied only the outermost
        ``attributes`` dict, so a nested dict or list stayed the *same
        object* the live graph held. Writing to the twin's baseline wrote
        straight through to production authority records.
        """

        live = self._live()
        before = json.dumps(live.to_dict(), sort_keys=True)
        base = SecurityTwin.from_graph(live).baseline()

        capability = base.node("capability:payments.send")
        assert (
            capability.attributes["limits"]
            is not live.node("capability:payments.send").attributes["limits"]
        )
        capability.attributes["limits"]["amount_max"] = 10**9
        base.node("agent:a").attributes["tags"].append("owned")
        edge = [e for e in base._edges if e.type == "holds"][0]
        edge.attributes["grant"]["amount_max"] = 10**9

        assert json.dumps(live.to_dict(), sort_keys=True) == before
        assert live.node("capability:payments.send").attributes[
            "limits"
        ] == {"amount_max": 100}

    @staticmethod
    def _live() -> AttackGraph:
        graph = AttackGraph()
        graph.add_node(
            "agent:a", "agent", "a", basis="observed",
            attributes={"tags": ["prod"], "meta": {"trusted": True}},
        )
        graph.add_node("agent:b", "agent", "b", basis="observed")
        graph.add_node(
            "capability:payments.send", "capability", "payments.send",
            basis="observed", attributes={"limits": {"amount_max": 100}},
        )
        graph.add_node(
            "resource:secrets", "resource", "secrets", basis="observed"
        )
        graph.add_edge(
            "capability:payments.send", "agent:a", "holds",
            basis="observed", attributes={"grant": {"amount_max": 100}},
        )
        graph.add_edge(
            "agent:a", "resource:secrets", "accesses", basis="observed"
        )
        return graph
